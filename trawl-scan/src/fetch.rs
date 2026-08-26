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
use std::time::Duration;

/// Longest a single request may take.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Longest to wait on a single address before trying the next one it resolved
/// to. Short, so a dead first address (the ::1 a v4-only service leaves stale)
/// falls through quickly instead of holding the whole request.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Most redirects to follow before giving up. A chain longer than this is either
/// broken or trying to wear the guard down.
const MAX_REDIRECTS: usize = 5;

/// Most of a body to read. Enough for any page or script worth scanning, and a
/// cap so a hostile server cannot stream gigabytes at the scanner.
const MAX_BODY: usize = 2 * 1024 * 1024;

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

fn require_web_scheme(url: &reqwest::Url) -> Result<(), FetchError> {
    match url.scheme() {
        "http" | "https" => Ok(()),
        other => Err(FetchError::BadUrl(format!(
            "scheme {other:?} is not http(s)"
        ))),
    }
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

    for _ in 0..=MAX_REDIRECTS {
        let host = current
            .host_str()
            .ok_or_else(|| FetchError::BadUrl("no host in URL".into()))?
            .to_string();
        let port = current.port_or_known_default().unwrap_or(80);

        // Resolution blocks, so it runs off the async threads. Every address the
        // name answered with is vetted, and one bad answer condemns the name.
        let resolving = host.clone();
        let resolved = tokio::task::spawn_blocking(move || {
            guard::resolve_and_check(&resolving, port, allow_local)
        })
        .await
        .map_err(|e| FetchError::Network(e.to_string()))?
        .map_err(|e| FetchError::Network(e.to_string()))?;

        if let Some(reason) = resolved.blocked() {
            return Err(FetchError::Blocked(reason.to_string()));
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

        let mut resp = None;
        let mut last_error = None;
        for addr in addresses {
            // Pinned to the vetted IP and told not to follow redirects itself.
            // The hostname still drives TLS, so certificate checking is unaffected.
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(request.timeout.unwrap_or(TIMEOUT))
                .connect_timeout(CONNECT_TIMEOUT)
                .resolve(&host, SocketAddr::new(addr, port))
                .build()
                .map_err(|e| FetchError::Network(e.to_string()))?;

            let mut builder = client.request(request.method.clone(), current.clone());
            for (name, value) in &request.headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            if let Some(body) = &request.body {
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
            current = current
                .join(location)
                .map_err(|e| FetchError::BadUrl(e.to_string()))?;
            require_web_scheme(&current)?;
            continue;
        }

        let headers = resp
            .headers()
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
            .collect();
        let final_url = current.to_string();

        let mut body = Vec::new();
        let mut truncated = false;
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| FetchError::Network(e.to_string()))?
        {
            if body.len() + chunk.len() > MAX_BODY {
                body.extend_from_slice(&chunk[..MAX_BODY - body.len()]);
                truncated = true;
                break;
            }
            body.extend_from_slice(&chunk);
        }

        return Ok(Fetched {
            final_url,
            status: status.as_u16(),
            headers,
            body,
            truncated,
        });
    }

    Err(FetchError::TooManyRedirects)
}
