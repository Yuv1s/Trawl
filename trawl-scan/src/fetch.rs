//! One guarded fetch.
//!
//! Every request the scanner makes goes through here, and here is where the
//! guard stops being a set of rules and starts being enforced. The sequence is
//! deliberate: resolve the host, run every address it answered with past the
//! guard, and only then connect — to the vetted address itself, not to the name.
//!
//! Connecting to the address is what closes the rebinding gap. A hostile host
//! can answer a public address to the resolver and a private one at connect
//! time; a client that re-resolves walks straight into it. This pins the client
//! to the IP the guard approved, so the connection lands where it was checked.
//!
//! Redirects are followed by hand rather than by the HTTP client, because each
//! hop is a fresh URL that has to face the guard again. A client that follows
//! redirects itself would happily be redirected from a public page to
//! `http://169.254.169.254`, and the guard would never see it.

use crate::guard;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Longest a single request may take.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Longest to wait on a single address before trying the next one it resolved
/// to. Short, so a dead first address (the ::1 a v4-only service leaves stale)
/// falls through quickly instead of holding the whole request.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Longest to wait on name resolution. Resolution is off the async threads and
/// has no timeout of its own, so a name server that never answers would hang the
/// request forever without this.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Longest the whole of one fetch may take across all its redirect hops. Each
/// hop has its own [`TIMEOUT`], but a chain of slow hops would otherwise add up
/// to minutes; this bounds the lot.
const FETCH_DEADLINE: Duration = Duration::from_secs(25);

/// Most redirects to follow before giving up. A chain longer than this is either
/// broken or trying to wear the guard down.
const MAX_REDIRECTS: usize = 5;

/// Most of a body to read by default. Enough for any page or script worth
/// scanning, and a cap so a hostile server cannot stream gigabytes at the
/// scanner. A caller that needs more, such as the file proxy, sets its own.
pub const MAX_BODY: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Fetched {
    /// Where the request ended up, after any redirects.
    pub final_url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// True when the body hit [`MAX_BODY`] and the rest was left unread.
    pub truncated: bool,
}

/// How to make one request. A plain GET by default; the active probes reach for
/// the other methods, a body, headers a crawl would never send, and a shorter
/// timeout, since an endpoint that stalls on a probe should fail fast rather than
/// hold the whole pass for ten seconds.
#[derive(Debug, Clone, Default)]
pub struct Request {
    pub method: reqwest::Method,
    pub body: Option<Vec<u8>>,
    pub headers: Vec<(String, String)>,
    pub timeout: Option<Duration>,
    /// How much of the body to read, when the default [`MAX_BODY`] is not what
    /// this caller wants. The file proxy reads a larger slice than the crawl.
    pub max_body: Option<usize>,
    /// Stop at a redirect that leaves the request's origin rather than follow it.
    /// The active probes set this: a crafted request carries a method, a body and
    /// credentials, none of which may cross to another origin, so when a probe is
    /// redirected off its origin it returns the redirect itself and sends nothing.
    pub stop_at_cross_origin: bool,
}

#[derive(Debug)]
pub enum FetchError {
    /// The guard refused an address, with the rule that caught it.
    Blocked(String),
    BadUrl(String),
    TooManyRedirects,
    Network(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Blocked(why) => write!(f, "refused: {why}"),
            FetchError::BadUrl(why) => write!(f, "bad URL: {why}"),
            FetchError::TooManyRedirects => write!(f, "too many redirects"),
            FetchError::Network(why) => write!(f, "network error: {why}"),
        }
    }
}

/// Whether two addresses are the same service: one origin, or loopback names on one port,
/// since `localhost` and `127.0.0.1` are one machine and a redirect between them leaves
/// nothing.
pub fn same_service(a: &reqwest::Url, b: &reqwest::Url) -> bool {
    let loopback = |url: &reqwest::Url| {
        matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
    };
    a.origin() == b.origin()
        || (a.scheme() == b.scheme()
            && a.port_or_known_default() == b.port_or_known_default()
            && loopback(a)
            && loopback(b))
}

fn require_web_scheme(url: &reqwest::Url) -> Result<(), FetchError> {
    match url.scheme() {
        "http" | "https" => Ok(()),
        other => Err(FetchError::BadUrl(format!(
            "scheme {other:?} is not http(s)"
        ))),
    }
}

/// What to do with a redirect, from the two origins and the kind of request.
#[derive(Debug, PartialEq, Eq)]
enum RedirectAction {
    /// Do not follow. The caller returns the redirect response untouched, so a
    /// crafted request is never replayed to another origin.
    Stop,
    /// Follow to the target. `drop_credentials` strips `Authorization`, `Cookie`
    /// and the body when the hop crosses origin; `to_get` turns a non-GET into a
    /// GET and drops the body, per 301/302/303.
    Follow {
        drop_credentials: bool,
        to_get: bool,
    },
}

/// Decides a redirect without touching the network, so the rule is testable on
/// its own: never carry credentials or a body across origins, never let a probe
/// follow off its origin at all, and apply 301/302/303 method semantics.
fn redirect_action(
    status: u16,
    same_origin: bool,
    method_is_get_or_head: bool,
    stop_at_cross_origin: bool,
) -> RedirectAction {
    if !same_origin && stop_at_cross_origin {
        return RedirectAction::Stop;
    }
    let to_get = !method_is_get_or_head && matches!(status, 301..=303);
    RedirectAction::Follow {
        drop_credentials: !same_origin,
        to_get,
    }
}

fn strip_credentials(headers: &mut Vec<(String, String)>) {
    headers.retain(|(name, _)| {
        !name.eq_ignore_ascii_case("authorization") && !name.eq_ignore_ascii_case("cookie")
    });
}

pub async fn fetch(url: &str, allow_local: bool) -> Result<Fetched, FetchError> {
    fetch_with(url, allow_local, &Request::default()).await
}

pub async fn fetch_with(
    url: &str,
    allow_local: bool,
    request: &Request,
) -> Result<Fetched, FetchError> {
    let mut current = reqwest::Url::parse(url).map_err(|e| FetchError::BadUrl(e.to_string()))?;
    require_web_scheme(&current)?;
    // Local access is for the service that was asked for. A local page redirecting anywhere
    // else is held to the strict guard, or it could send the scanner to any other service
    // on the person's machine or network.
    let asked_for = allow_local.then(|| current.clone());

    // The request as it stands this hop. A redirect may rewrite these: a
    // cross-origin hop strips the credentials and body, and 301/302/303 turn a
    // non-GET into a GET. The original `request` is never mutated, so the caller
    // keeps what it passed.
    let mut method = request.method.clone();
    let mut headers = request.headers.clone();
    let mut body = request.body.clone();

    // One wall-clock budget for the whole fetch, so a chain of slow hops cannot
    // add up past it however many redirects it takes.
    let started = Instant::now();
    let max_body = request.max_body.unwrap_or(MAX_BODY);

    for _ in 0..=MAX_REDIRECTS {
        let remaining = FETCH_DEADLINE.checked_sub(started.elapsed());
        let Some(remaining) = remaining.filter(|left| !left.is_zero()) else {
            return Err(FetchError::Network("fetch deadline exceeded".into()));
        };

        let host = current
            .host_str()
            .ok_or_else(|| FetchError::BadUrl("no host in URL".into()))?
            .to_string();
        let port = current.port_or_known_default().unwrap_or(80);

        // Resolution blocks, so it runs off the async threads, under a timeout of
        // its own since it has none otherwise. Every address the name answered
        // with is vetted, and one bad answer condemns the name.
        let resolving = host.clone();
        let local_here = asked_for.as_ref().is_some_and(|asked| same_service(asked, &current));
        let resolve = tokio::task::spawn_blocking(move || {
            guard::resolve_and_check(&resolving, port, local_here)
        });
        let resolved = tokio::time::timeout(DNS_TIMEOUT.min(remaining), resolve)
            .await
            .map_err(|_| FetchError::Network("DNS resolution timed out".into()))?
            .map_err(|e| FetchError::Network(e.to_string()))?
            .map_err(|e| FetchError::Network(e.to_string()))?;

        if let Some(reason) = resolved.blocked() {
            return Err(FetchError::Blocked(if asked_for.is_some() && !local_here {
                format!(
                    "{reason}, and this redirect left the address you named, which is as far as local mode goes"
                )
            } else {
                reason.to_string()
            }));
        }
        let mut addresses = resolved.safe_addresses();
        if addresses.is_empty() {
            return Err(FetchError::Network("host did not resolve".into()));
        }

        // Every vetted address is tried in turn until one answers. A name that
        // resolves to several addresses is the ordinary case, and `localhost` is
        // the one that bites: it usually lists ::1 first, and a service bound
        // only to 127.0.0.1 is not there, so the ::1 attempt has to fail before
        // the working address is reached. On many machines that failure is a
        // two-second stall rather than a refusal, so IPv4 is tried first and a
        // short connect timeout keeps a dead address from holding the request.
        addresses.sort_by_key(|addr| addr.is_ipv6());

        // The hop's timeout never outlasts what is left of the whole-fetch budget.
        let hop_timeout = request.timeout.unwrap_or(TIMEOUT).min(remaining);

        let mut resp = None;
        let mut last_error = None;
        for addr in addresses {
            // Pinned to the vetted IP and told not to follow redirects itself,
            // nor to consult any proxy: a proxy would resolve the name again and
            // send the request there, undoing the IP pin the guard depends on.
            // The hostname still drives TLS, so certificate checking is unaffected.
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .timeout(hop_timeout)
                .connect_timeout(CONNECT_TIMEOUT.min(remaining))
                .resolve(&host, SocketAddr::new(addr, port))
                .build()
                .map_err(|e| FetchError::Network(e.to_string()))?;

            let mut builder = client.request(method.clone(), current.clone());
            for (name, value) in &headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            if let Some(body) = &body {
                builder = builder.body(body.clone());
            }

            match builder.send().await {
                Ok(got) => {
                    resp = Some(got);
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }

        let mut resp = resp.ok_or_else(|| {
            FetchError::Network(
                last_error
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "could not connect".into()),
            )
        })?;

        let status = resp.status();

        if status.is_redirection()
            && let Some(location) = resp.headers().get(reqwest::header::LOCATION)
        {
            let location = location
                .to_str()
                .map_err(|_| FetchError::BadUrl("unreadable redirect target".into()))?;
            let target = current
                .join(location)
                .map_err(|e| FetchError::BadUrl(e.to_string()))?;
            require_web_scheme(&target)?;

            let same_origin = target.origin() == current.origin();
            let method_is_get_or_head =
                matches!(method, reqwest::Method::GET | reqwest::Method::HEAD);
            match redirect_action(
                status.as_u16(),
                same_origin,
                method_is_get_or_head,
                request.stop_at_cross_origin,
            ) {
                RedirectAction::Follow {
                    drop_credentials,
                    to_get,
                } => {
                    if drop_credentials {
                        // Never let a session cookie or a forged Authorization,
                        // nor a request body, cross to another origin.
                        strip_credentials(&mut headers);
                        body = None;
                    }
                    if to_get {
                        method = reqwest::Method::GET;
                        body = None;
                    }
                    current = target;
                    continue;
                }
                // A probe redirected off its origin: stop and return the redirect
                // itself, having sent nothing to the other origin.
                RedirectAction::Stop => {}
            }
        }

        let headers = resp
            .headers()
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
            .collect();
        let final_url = current.to_string();

        let mut collected = Vec::new();
        let mut truncated = false;
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| FetchError::Network(e.to_string()))?
        {
            if collected.len() + chunk.len() > max_body {
                collected.extend_from_slice(&chunk[..max_body - collected.len()]);
                truncated = true;
                break;
            }
            collected.extend_from_slice(&chunk);
        }

        return Ok(Fetched {
            final_url,
            status: status.as_u16(),
            headers,
            body: collected,
            truncated,
        });
    }

    Err(FetchError::TooManyRedirects)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Answers one connection with a redirect to `location`.
    fn redirect_once(listener: TcpListener, location: String) {
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await;
            let answer = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = socket.write_all(answer.as_bytes()).await;
        });
    }

    #[tokio::test]
    async fn a_local_page_cannot_send_a_fetch_to_another_local_service() {
        let other = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let other_at = other.local_addr().unwrap();
        let entry = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let entry_at = entry.local_addr().unwrap();
        redirect_once(entry, format!("http://{other_at}/admin"));

        let outcome = fetch(&format!("http://{entry_at}/"), true).await;

        assert!(matches!(outcome, Err(FetchError::Blocked(_))), "{outcome:?}");
        let reached = tokio::time::timeout(Duration::from_millis(100), other.accept()).await;
        assert!(reached.is_err(), "nothing was sent to the other service");
    }

    #[tokio::test]
    async fn a_redirect_between_loopback_names_stays_local() {
        let entry = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = entry.local_addr().unwrap().port();
        tokio::spawn(async move {
            let redirect = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/home\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let page = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nhere";
            for answer in [redirect.as_str(), page] {
                let (mut socket, _) = entry.accept().await.unwrap();
                let mut request = [0u8; 1024];
                let _ = socket.read(&mut request).await;
                let _ = socket.write_all(answer.as_bytes()).await;
            }
        });

        let page = fetch(&format!("http://localhost:{port}/loc"), true).await.unwrap();

        assert_eq!(page.body, b"here");
    }

    #[test]
    fn a_service_is_an_origin_or_a_loopback_name_on_one_port() {
        let url = |text: &str| reqwest::Url::parse(text).unwrap();
        let same = |a: &str, b: &str| same_service(&url(a), &url(b));

        assert!(same("http://target.example/a", "http://target.example/b"));
        assert!(same("http://localhost:5000/", "http://127.0.0.1:5000/home"));
        assert!(same("http://[::1]:5000/", "http://localhost:5000/"));

        assert!(!same("http://localhost:5000/", "http://127.0.0.1:5001/"));
        assert!(!same("http://localhost:5000/", "https://127.0.0.1:5000/"));
        assert!(!same("http://localhost:5000/", "http://192.168.1.1:5000/"));
        assert!(!same("http://target.example/", "http://other.example/"));
    }

    #[tokio::test]
    async fn a_local_page_can_redirect_within_itself() {
        let entry = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let entry_at = entry.local_addr().unwrap();
        tokio::spawn(async move {
            for answer in [
                "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nhere",
            ] {
                let (mut socket, _) = entry.accept().await.unwrap();
                let mut request = [0u8; 1024];
                let _ = socket.read(&mut request).await;
                let _ = socket.write_all(answer.as_bytes()).await;
            }
        });

        let page = fetch(&format!("http://{entry_at}/"), true).await.unwrap();

        assert_eq!(page.body, b"here");
        assert!(page.final_url.ends_with("/next"));
    }

    #[test]
    fn a_cross_origin_redirect_drops_credentials_and_body() {
        // The core of the write-request leak: a redirect to another origin must
        // never carry the method, body or credentials of the crafted request.
        let action = redirect_action(307, false, false, false);
        assert_eq!(
            action,
            RedirectAction::Follow {
                drop_credentials: true,
                to_get: false
            }
        );
    }

    #[test]
    fn a_probe_never_follows_off_its_origin() {
        // With stop_at_cross_origin set, a probe stops dead rather than replay
        // anything to the new origin.
        assert_eq!(
            redirect_action(301, false, true, true),
            RedirectAction::Stop
        );
        assert_eq!(
            redirect_action(307, false, false, true),
            RedirectAction::Stop
        );
    }

    #[test]
    fn same_origin_301_302_303_downgrade_a_non_get_to_get() {
        for status in [301, 302, 303] {
            assert_eq!(
                redirect_action(status, true, false, false),
                RedirectAction::Follow {
                    drop_credentials: false,
                    to_get: true
                }
            );
        }
        // 307 and 308 keep the method and body on a same-origin hop.
        for status in [307, 308] {
            assert_eq!(
                redirect_action(status, true, false, false),
                RedirectAction::Follow {
                    drop_credentials: false,
                    to_get: false
                }
            );
        }
        // A GET stays a GET; there is nothing to downgrade.
        assert_eq!(
            redirect_action(302, true, true, false),
            RedirectAction::Follow {
                drop_credentials: false,
                to_get: false
            }
        );
    }

    #[test]
    fn strip_credentials_removes_only_authorization_and_cookie() {
        let mut headers = vec![
            ("Authorization".to_string(), "Bearer x".to_string()),
            ("cookie".to_string(), "session=1".to_string()),
            ("Accept".to_string(), "text/html".to_string()),
        ];
        strip_credentials(&mut headers);
        assert_eq!(
            headers,
            vec![("Accept".to_string(), "text/html".to_string())]
        );
    }
}
