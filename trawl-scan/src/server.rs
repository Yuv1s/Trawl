//! The HTTP surface the frontend talks to.
//!
//! Three routes. `GET /health` is what the "waiting for the scanner" panel polls;
//! the moment it answers, the panel knows the scanner is up and switches to the
//! URL input. `POST /scan` fetches the target through the guard, pulls it apart
//! into the pages, images, scripts and comments it references, folds in what
//! `robots.txt` gives away, and runs the body past the same flag detection the
//! offline tool uses. Following those links, and handing images to Cuttlefish,
//! come next.
//!
//! Every route is paired to one frontend origin and one token chosen when the
//! scanner starts. This keeps unrelated pages from turning the loopback service
//! into a proxy, especially when local targets are enabled.

use crate::guard;
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tower_http::cors::CorsLayer;

/// The header the file proxy sets when a body was cut at its cap, so the page can
/// tell a whole file from a truncated one. Named here because both the proxy and
/// the CORS layer that exposes it refer to it.
const TRUNCATED_HEADER: HeaderName = HeaderName::from_static("x-trawl-truncated");

/// The file proxy reads a larger slice than the crawl: an image the offline tools
/// are handed may be bigger than a page worth scanning, but still not unbounded.
const FETCH_MAX_BODY: usize = 32 * 1024 * 1024;

/// One scan-wide ceiling on the passive crawl. About 140 sequential fetches, each
/// able to take several hops, could otherwise run for a very long time; when this
/// is reached the scan returns what it has with a notice rather than failing.
const PASSIVE_DEADLINE: Duration = Duration::from_secs(180);

/// Longest to spend classifying the entry host before a scan or proxy fetch. The
/// fetch itself bounds its own resolution; this bounds the one that happens first.
const ENTRY_DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// Ceilings on what one scan reports back, so a hostile page cannot blow the
/// result up to megabytes of JSON. Past these the rest are dropped and a notice
/// gives the count.
const MAX_FLAGS: usize = 500;
const MAX_COMMENTS: usize = 500;
const MAX_BUCKET: usize = 500;

/// The port the scanner binds, so the default and the `Host` check agree with
/// where it actually listens.
pub const DEFAULT_PORT: u16 = 8099;

/// What the scanner was started with. Carried into every handler so a request
/// cannot decide for itself whether local targets are allowed: only the person
/// who started the process can, by starting it that way.
#[derive(Clone)]
pub struct Config {
    pub allow_local: bool,
    token: String,
    allowed_origin: HeaderValue,
    port: u16,
    /// Hosts and ports a scan found to be local, which is the only thing that lets a
    /// proxied fetch reach a local address.
    local_origins: Arc<Mutex<HashSet<(String, u16)>>>,
}

impl Config {
    pub fn new(allow_local: bool, token: String, origin: String) -> Result<Self, String> {
        validate_token(&token)?;
        let allowed_origin = validate_origin(&origin)?;

        Ok(Self {
            allow_local,
            token,
            allowed_origin,
            port: DEFAULT_PORT,
            local_origins: Arc::default(),
        })
    }

    fn remember_local(&self, url: &str) {
        if let Some(origin) = host_and_port(url) {
            self.local_origins
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(origin);
        }
    }

    fn scanned_as_local(&self, url: &str) -> bool {
        host_and_port(url).is_some_and(|origin| {
            self.local_origins
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&origin)
        })
    }

    /// Sets the port the service listens on, for the `Host` header check. Kept
    /// off `new` so its callers, the tests among them, are left as they were.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
}

/// Whether the scanner should reach local and private targets, from the flag and
/// the environment. Only `--allow-local` and `TRAWL_ALLOW_LOCAL=1` turn it on;
/// the page sends exactly `1`, and a stray `0` must not, the way merely setting
/// the variable once did.
pub fn local_requested(flag_present: bool, env_value: Option<&str>) -> bool {
    flag_present || env_value == Some("1")
}

pub fn app(config: Config) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(config.allowed_origin.clone())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        // So the page can read whether a proxied file was truncated.
        .expose_headers([TRUNCATED_HEADER]);

    Router::new()
        .route("/health", get(health))
        .route("/scan", post(scan))
        .route("/fetch", get(raw))
        .layer(cors)
        // Outermost, so a request with a foreign Host is turned away before any
        // handler runs. The token still gates everything; this closes the DNS
        // rebinding path, where a public name resolves to loopback and a page
        // reaches the service as though it were its own origin.
        .layer(middleware::from_fn_with_state(
            config.clone(),
            require_local_host,
        ))
        .with_state(config)
}

type ApiError = (StatusCode, String);

/// Turns away any request whose `Host` is not the loopback address the scanner
/// listens on. A browser reaching the real service always sends one of these;
/// a rebinding attack, which reaches loopback while believing it is on another
/// name, sends that name instead and is refused here.
async fn require_local_host(
    State(config): State<Config>,
    request: Request,
    next: Next,
) -> Response {
    if only_host(request.headers()).is_some_and(|host| host_is_allowed(host, config.port)) {
        next.run(request).await
    } else {
        (
            StatusCode::FORBIDDEN,
            "the scanner is reachable on loopback only",
        )
            .into_response()
    }
}

/// The request's `Host`, if it has exactly one. With two, what this reads and what
/// something later reads can differ.
fn only_host(headers: &HeaderMap) -> Option<&str> {
    let mut hosts = headers.get_all(header::HOST).iter();
    match (hosts.next(), hosts.next()) {
        (Some(value), None) => value.to_str().ok(),
        _ => None,
    }
}

/// Whether a `Host` header names this loopback service: one of `127.0.0.1`,
/// `localhost` or `[::1]`, and, if it carries a port, the one the scanner binds.
fn host_is_allowed(host_header: &str, port: u16) -> bool {
    let Some((host, host_port)) = split_host_port(host_header) else {
        return false;
    };
    let host_ok = matches!(host, "127.0.0.1" | "localhost" | "::1");
    let port_ok = host_port.is_none_or(|given| given == port);
    host_ok && port_ok
}

/// Splits a `Host` header into its host and optional port, understanding the
/// bracketed `[::1]:port` form an IPv6 literal takes. Nothing at all for a port that
/// is there but is not a number, which no browser sends.
fn split_host_port(host_header: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = host_header.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        return match after.strip_prefix(':') {
            Some(port) => Some((inside, Some(port.parse().ok()?))),
            None => after.is_empty().then_some((inside, None)),
        };
    }
    match host_header.rsplit_once(':') {
        Some((host, port)) => Some((host, Some(port.parse().ok()?))),
        None => Some((host_header, None)),
    }
}

fn validate_token(token: &str) -> Result<(), String> {
    if token.len() < 32 {
        return Err("TRAWL_TOKEN must contain at least 32 characters".to_string());
    }
    if token.len() > 256 {
        return Err("TRAWL_TOKEN must contain no more than 256 characters".to_string());
    }
    if !token.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
    }) {
        return Err("TRAWL_TOKEN must use bearer-token characters only".to_string());
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<HeaderValue, String> {
    let parsed = reqwest::Url::parse(origin)
        .map_err(|_| "TRAWL_ORIGIN must be an absolute http or https origin".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err("TRAWL_ORIGIN must be an absolute http or https origin".to_string());
    }

    let exact = parsed.origin().ascii_serialization();
    if origin != exact {
        return Err(
            "TRAWL_ORIGIN must contain only the exact origin, with no path, query, fragment, or trailing slash"
                .to_string(),
        );
    }

    HeaderValue::from_str(&exact).map_err(|_| "TRAWL_ORIGIN is not a valid HTTP origin".to_string())
}

fn tokens_equal(provided: &str, expected: &str) -> bool {
    let provided = provided.as_bytes();
    let expected = expected.as_bytes();
    let mut difference = provided.len() ^ expected.len();
    let compared_len = provided.len().max(expected.len());

    for index in 0..compared_len {
        difference |= usize::from(
            provided.get(index).copied().unwrap_or_default()
                ^ expected.get(index).copied().unwrap_or_default(),
        );
    }

    difference == 0
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer")
        && !token.is_empty()
        && !token.contains(char::is_whitespace))
    .then_some(token)
}

fn unauthorized() -> ApiError {
    (
        StatusCode::UNAUTHORIZED,
        "scanner authentication required".to_string(),
    )
}

fn authorize_bearer(headers: &HeaderMap, config: &Config) -> Result<(), ApiError> {
    if bearer_token(headers).is_some_and(|token| tokens_equal(token, &config.token)) {
        Ok(())
    } else {
        Err(unauthorized())
    }
}

#[derive(Serialize)]
struct Health {
    service: &'static str,
    version: &'static str,
    /// Whether this scanner will reach local and private targets. The page shows
    /// it so a person knows which mode they started.
    allow_local: bool,
}

async fn health(
    State(config): State<Config>,
    headers: HeaderMap,
) -> Result<Json<Health>, ApiError> {
    authorize_bearer(&headers, &config)?;

    Ok(Json(Health {
        service: "trawl-scan",
        version: env!("CARGO_PKG_VERSION"),
        allow_local: config.allow_local,
    }))
}

#[derive(Deserialize)]
struct ScanRequest {
    url: String,
    /// Run the active battery, which sends crafted requests rather than only
    /// reading. Off unless the page's authorization affirmation set it, because
    /// this is the half that touches the target.
    #[serde(default)]
    active: bool,
    /// The person's own leads, each a name to try as a parameter, a field and a
    /// header on top of the built-in list. Ignored unless `active` is set.
    #[serde(default)]
    hints: Vec<String>,
}

/// A finding and the page it was found on, so the preview can say where.
#[derive(Serialize)]
struct Located {
    value: String,
    source: String,
    /// How it was read, empty when it sat in the page as plain text. A decoded
    /// or header-borne flag says so here: "base64 in the source", "in the X-Flag
    /// response header".
    note: String,
}

fn located(value: String, source: &str, note: &str) -> Located {
    Located {
        value,
        source: source.to_string(),
        note: note.to_string(),
    }
}

/// One page the crawl actually visited.
#[derive(Serialize)]
struct PageResult {
    url: String,
    status: u16,
}

/// A file that answered to its name, that no page linked to and no sitemap
/// listed. The most interesting kind of find on a scan: someone left it there
/// and meant for nobody to see it.
#[derive(Serialize)]
struct Found {
    url: String,
    status: u16,
    /// How many bytes came back, so an empty stub reads differently from a real
    /// file at a glance.
    size: usize,
    /// True for the source-control, dotfile and backup paths, which are a
    /// heavier finding than a guessable loot file.
    sensitive: bool,
}

/// What a crawl turned up, grouped the way a person looks for it.
#[derive(Serialize, Default)]
struct ScanResult {
    /// Where the entry request ended up, after redirects.
    target: String,
    /// What the person should know did not happen: active checks skipped, the
    /// time limit reached, findings capped, long responses cut. Always present,
    /// empty when the scan ran in full.
    notices: Vec<String>,
    /// Every page the crawl visited, the entry first.
    pages: Vec<PageResult>,
    /// Same-host images, each a candidate for Cuttlefish once fetched.
    images: Vec<String>,
    /// Same-host scripts, where client-side logic and stray endpoints hide.
    scripts: Vec<String>,
    /// Same-host stylesheets, fonts, documents and the like.
    assets: Vec<String>,
    /// Links that leave the target. Reported, never followed.
    external: Vec<String>,
    /// Files that answered to their name without a link pointing at them.
    found: Vec<Found>,
    /// Flag shapes found anywhere, each with the page it sat on.
    flags: Vec<Located>,
    /// HTML comments found anywhere, each with the page it sat on.
    comments: Vec<Located>,
}

/// Most pages one scan will fetch. A one-level crawl of an ordinary site is a
/// dozen or two; this stops a sprawling one from turning into a long wait, until
/// the results stream rather than arrive all at once.
const MAX_PAGES: usize = 25;

fn sorted(mut urls: Vec<String>) -> Vec<String> {
    urls.sort();
    urls.dedup();
    urls
}

/// Flag shapes in a run of bytes, held to a recognised tag.
///
/// The offline tool does not need the tag: a decoded blob rarely holds a stray
/// brace, so any `word{...}` there is worth showing. A web page is nothing but
/// braces, every CSS rule a `body{...}`, so without the tag the flag list would
/// be a wall of stylesheet. Only `flag{`, `ctf{` and the tags people use survive.
fn flags_in(body: &[u8]) -> Vec<String> {
    trawl_core::bytes::flag_candidates(body)
        .into_iter()
        .filter(|found| trawl_core::bytes::tag_is_known(&found.text))
        .map(|found| found.text)
        .collect()
}

/// What one fetched page contributes: its flags, its comments, and every
/// reference on it.
///
/// Flags come from four places now: plain in the body, in a linked filename,
/// out of a decoding the source suggests, and in a response header. The header
/// scan is why `X-Flag` and a base64 cookie get read; the decode scan is why an
/// encoded variable does. All of it runs through the same flag-shape filter, so
/// a page hiding nothing contributes nothing.
fn glean(
    page_url: &str,
    body: &[u8],
    headers: &[(String, String)],
) -> (Vec<Located>, Vec<Located>, Vec<crate::crawl::Reference>) {
    let page = reqwest::Url::parse(page_url).ok();

    let mut flags: Vec<Located> = flags_in(body)
        .into_iter()
        .map(|value| located(value, page_url, ""))
        .collect();

    let references = page
        .as_ref()
        .map(|base| crate::crawl::references(base, body))
        .unwrap_or_default();

    // A flag can hide in a filename rather than the text, where the URL encodes
    // its braces out of the detector's sight. Decoding each reference puts it
    // back where the detector can see it.
    for reference in &references {
        for value in flags_in(crate::crawl::decode_url(&reference.url).as_bytes()) {
            flags.push(located(value, page_url, "in a linked filename"));
        }
    }

    // Encoded flags: a base64 variable, a rotated comment, a colour written as
    // CSS escapes, an array XORed against a byte.
    for found in crate::decode::harvest(body) {
        flags.push(located(
            found.value,
            page_url,
            &format!("{} in the source", found.how),
        ));
    }

    // The response headers carry their own: a plain flag in X-Flag, a base64
    // payload in a cookie, an ETag written backwards.
    for (name, value) in headers {
        let name = name.to_ascii_lowercase();
        for flag in flags_in(value.as_bytes()) {
            flags.push(located(
                flag,
                page_url,
                &format!("in the {name} response header"),
            ));
        }
        for found in crate::decode::harvest(value.as_bytes()) {
            flags.push(located(
                found.value,
                page_url,
                &format!("{} in the {name} response header", found.how),
            ));
        }
    }

    let comments = crate::crawl::comments(body)
        .into_iter()
        .map(|value| located(value, page_url, ""))
        .collect();

    (flags, comments, references)
}

/// Whether a URL is on the same origin as the scan's entry: scheme, host and
/// port all equal. Origin rather than host, so a link to another port or scheme
/// on the same name is treated as off-target, the way the guard intends.
fn same_origin(url: &str, entry: &reqwest::Url) -> bool {
    reqwest::Url::parse(url)
        .map(|parsed| parsed.origin() == entry.origin())
        .unwrap_or(false)
}

/// The host and port of a URL, for the entry classification that decides whether
/// local access applies.
fn host_and_port(url: &str) -> Option<(String, u16)> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(80);
    Some((host, port))
}

/// Whether this request may reach local or private addresses: only when the
/// scanner is in local mode and the host it names itself resolves there. Done off
/// the async threads, since it resolves. A public entry comes back false and is
/// held to the strict guard for every hop.
async fn entry_allows_local(url: &str, config: &Config) -> bool {
    let Some((host, port)) = host_and_port(url) else {
        return false;
    };
    let scanner_local = config.allow_local;
    // Resolution blocks and has no timeout of its own, so it runs off the async
    // threads under a bound. A slow or hostile resolver falls back to the strict
    // guard rather than hanging the request before it has begun.
    let resolve =
        tokio::task::spawn_blocking(move || guard::host_allows_local(&host, port, scanner_local));
    tokio::time::timeout(ENTRY_DNS_TIMEOUT, resolve)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false)
}

/// Whether a proxied fetch may reach local or private addresses: only for an origin a
/// scan already found local, and still local now. Without the first half, a public site
/// could point its own name at a private address once the crawl was done, and the image
/// it listed would be fetched from there.
async fn fetch_allows_local(url: &str, config: &Config) -> bool {
    config.scanned_as_local(url) && entry_allows_local(url, config).await
}

/// Where an entry's redirects left it, against the address the person named.
struct Landed {
    /// Still what was named, which is as far as local access and active checks go.
    same_service: bool,
    /// Still that site, if perhaps moved to https, which is as far as guessing names goes.
    same_site: bool,
}

fn landed(requested: &str, entry: &reqwest::Url) -> Landed {
    let requested = reqwest::Url::parse(requested).ok();
    let same_service = requested
        .as_ref()
        .is_some_and(|url| crate::fetch::same_service(url, entry));
    let same_site = requested
        .as_ref()
        .is_some_and(|url| url.host_str() == entry.host_str() && url.port() == entry.port());

    Landed {
        same_service,
        same_site: same_service || same_site,
    }
}

/// Sorts a page's references into the buckets they belong in, and hands back the
/// same-host pages it linked. What the caller does with those links is what sets
/// the crawl depth: the entry follows them, a page one level down does not.
///
/// Assets are gathered from every page regardless, so images that live on a
/// gallery are found even though the entry never linked them.
struct Buckets<'a> {
    images: &'a mut Vec<String>,
    scripts: &'a mut Vec<String>,
    assets: &'a mut Vec<String>,
    external: &'a mut Vec<String>,
}

fn categorize(
    references: Vec<crate::crawl::Reference>,
    entry: &reqwest::Url,
    into: &mut Buckets,
) -> Vec<String> {
    use crate::crawl::Kind;
    let mut page_links = Vec::new();

    for reference in references {
        if !same_origin(&reference.url, entry) {
            into.external.push(reference.url);
            continue;
        }
        match reference.kind {
            Kind::Image => into.images.push(reference.url),
            Kind::Script => into.scripts.push(reference.url),
            Kind::Style | Kind::Asset => into.assets.push(reference.url),
            Kind::Page => page_links.push(reference.url),
        }
    }

    page_links
}

/// Queues the same-host pages a sitemap lists, so one reachable only through the
/// sitemap is still crawled.
fn enqueue_sitemap(
    body: &[u8],
    page_url: &str,
    entry: &reqwest::Url,
    visited: &mut HashSet<String>,
    queue: &mut Vec<String>,
) {
    let Ok(base) = reqwest::Url::parse(page_url) else {
        return;
    };
    for loc in crate::crawl::sitemap_locs(&base, body) {
        if same_origin(&loc, entry) && visited.insert(loc.clone()) {
            queue.push(loc);
        }
    }
}

/// Files a site never links to but sometimes leaves reachable: a source backup,
/// a committed dotfile, an exported store. Tried by name, one request each.
const SENSITIVE_PATHS: &[&str] = &[
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/.env.bak",
    "/backup/app.py.bak",
    "/app.py.bak",
    "/main.py.bak",
    "/index.php.bak",
    "/config.php.bak",
    "/settings.py.bak",
    "/.htaccess",
    "/.DS_Store",
    "/.svn/entries",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sqlite3",
    "/config.json.bak",
];

/// Whether a URL points at something worth reading as text: a script, a
/// stylesheet, a data file. A flag can hide in a CSS escape or a JS constant,
/// and neither is fetched by the page crawl, which only follows pages.
fn is_texty(url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    matches!(
        path.rsplit('.').next(),
        Some("css" | "js" | "mjs" | "json" | "txt" | "xml" | "map" | "csv")
    )
}

/// [`glean`] run off the async worker. The parsing, decoding and flag search can
/// take seconds on a large or hostile body, which would stall the executor if it
/// ran inline; moving it to a blocking thread keeps the server responsive.
async fn glean_off_thread(
    page_url: String,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
) -> (Vec<Located>, Vec<Located>, Vec<crate::crawl::Reference>) {
    tokio::task::spawn_blocking(move || glean(&page_url, &body, &headers))
        .await
        .unwrap_or_default()
}

/// Fetches each text resource once and reads flags out of it, plain and decoded.
/// This is what catches a flag written into a stylesheet or a script the crawl
/// linked but never opened.
///
/// Says how many of those it read were cut at the body limit, how many it left unread
/// at its own limit, and how many could not be fetched.
async fn harvest_resources(
    allow_local: bool,
    deadline: Instant,
    resources: &[String],
    visited: &mut HashSet<String>,
    result: &mut ScanResult,
) -> Harvested {
    let mut fetched = 0;
    let mut harvested = Harvested::default();

    for (index, url) in resources.iter().enumerate() {
        if fetched >= MAX_RESOURCES {
            // A file every page links is listed once for each of them.
            let rest = resources[index..].iter().filter(|url| !visited.contains(*url));
            harvested.left = rest.collect::<HashSet<_>>().len();
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        if !is_texty(url) || !visited.insert(url.clone()) {
            continue;
        }
        fetched += 1;

        let answer = crate::fetch::fetch(url, allow_local).await;
        harvested.failed += usize::from(answer.is_err());
        if let Ok(res) = answer
            && res.status == 200
        {
            harvested.cut += usize::from(res.truncated);

            // The decode battery is pure CPU over the body, so it runs off the
            // async worker the same way the page gleaning does.
            let body = res.body;
            let url_owned = url.clone();
            let found = tokio::task::spawn_blocking(move || {
                let mut out: Vec<Located> = flags_in(&body)
                    .into_iter()
                    .map(|value| located(value, &url_owned, ""))
                    .collect();
                for found in crate::decode::harvest(&body) {
                    out.push(located(
                        found.value,
                        &url_owned,
                        &format!("{} in the source", found.how),
                    ));
                }
                out
            })
            .await
            .unwrap_or_default();
            result.flags.extend(found);
        }
    }

    harvested
}

/// Most scripts and stylesheets one scan will open.
const MAX_RESOURCES: usize = 30;

/// What reading a page's scripts and stylesheets came to.
#[derive(Default)]
struct Harvested {
    cut: usize,
    left: usize,
    failed: usize,
}

/// Most files one sweep will report. A soft-404 server that slips calibration
/// could otherwise answer every name; this stops the list from filling with its
/// catch-all.
const MAX_FOUND: usize = 40;

/// Learns the server's not-found answer, then sweeps for files by name.
///
/// The sensitive paths and the loot list are one pass: both are names a file
/// gets when it should not be reachable, and both are judged against the same
/// baseline so a soft-404 server does not turn every guess into a find. A hit
/// is recorded as a found file, its body read for flags, and anything it in
/// turn references bucketed like any other page's.
///
/// Returns how many of those hits were cut at the body limit, and whether the sweep
/// stopped at its limit on finds with names still to try.
#[allow(clippy::too_many_arguments)]
async fn probe_by_name(
    allow_local: bool,
    deadline: Instant,
    entry: &reqwest::Url,
    visited: &mut HashSet<String>,
    result: &mut ScanResult,
    images: &mut Vec<String>,
    scripts: &mut Vec<String>,
    assets: &mut Vec<String>,
    external: &mut Vec<String>,
) -> (usize, bool) {
    let base = entry.clone();
    let mut cut = 0;
    let mut capped = false;

    // Ask for two paths that cannot be there and remember the answer, so a
    // server that says 200 to everything does not make every name look found.
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut samples = Vec::new();
    for path in crate::discovery::calibration_paths(seed) {
        if let Ok(url) = base.join(&path)
            && let Ok(res) = crate::fetch::fetch(url.as_str(), allow_local).await
        {
            samples.push((res.status, res.body.len()));
        }
    }
    let baseline = crate::discovery::Baseline::from_samples(&samples);

    let sensitive = SENSITIVE_PATHS.iter().map(|p| (*p, true));
    let loot = crate::discovery::DISCOVERY_PATHS
        .iter()
        .map(|p| (*p, false));

    for (path, sensitive) in sensitive.chain(loot) {
        if result.found.len() >= MAX_FOUND {
            capped = true;
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        let Ok(url) = base.join(path) else {
            continue;
        };
        let probe = url.to_string();
        if !visited.insert(probe.clone()) {
            continue;
        }

        let Ok(page) = crate::fetch::fetch(&probe, allow_local).await else {
            continue;
        };
        if !baseline.is_hit(page.status, page.body.len()) {
            continue;
        }
        cut += usize::from(page.truncated);

        result.found.push(Found {
            url: probe.clone(),
            status: page.status,
            size: page.body.len(),
            sensitive,
        });

        if !page.body.is_empty() {
            let (flags, comments, references) =
                glean_off_thread(probe.clone(), page.body, page.headers).await;
            result.flags.extend(flags);
            result.comments.extend(comments);

            let mut buckets = Buckets {
                images: &mut *images,
                scripts: &mut *scripts,
                assets: &mut *assets,
                external: &mut *external,
            };
            categorize(references, entry, &mut buckets);
        }
    }

    (cut, capped)
}

/// What a scan left undone, apart from running out of time, which has a notice of its own.
#[derive(Default)]
struct Undone {
    pages_left: usize,
    resources_left: usize,
    failed: usize,
    sweep_capped: bool,
    active_stopped: bool,
}

/// One line for each thing a scan stopped short of, so that what it did not reach does not
/// read as somewhere it looked and found nothing.
fn undone_notices(undone: &Undone) -> Vec<String> {
    let mut notices = Vec::new();
    if undone.pages_left > 0 {
        notices.push(format!(
            "The crawl stopped at {MAX_PAGES} pages, with {} more left unread.",
            undone.pages_left
        ));
    }
    if undone.resources_left > 0 {
        notices.push(format!(
            "Trawl read {MAX_RESOURCES} scripts and stylesheets, with {} more left unread.",
            undone.resources_left
        ));
    }
    if undone.failed > 0 {
        notices.push(format!(
            "Pages and files the scan found but could not fetch, and so did not search: {}.",
            undone.failed
        ));
    }
    if undone.sweep_capped {
        notices.push(format!(
            "The file name sweep stopped after {MAX_FOUND} finds, so the names after that were not tried."
        ));
    }
    if undone.active_stopped {
        notices.push(format!(
            "The active checks stopped at their limit of {} requests or {} seconds, so not every check ran.",
            crate::active::REQUEST_BUDGET,
            crate::active::ACTIVE_DEADLINE.as_secs()
        ));
    }
    notices
}

async fn scan(
    State(config): State<Config>,
    headers: HeaderMap,
    Json(request): Json<ScanRequest>,
) -> Result<Json<ScanResult>, ApiError> {
    authorize_bearer(&headers, &config)?;

    // Local access is decided once, from the host the person named, before the
    // first fetch. A public entry comes back false and stays under the strict
    // guard for every hop, so it cannot redirect or resolve its way inward.
    let allow_local = entry_allows_local(&request.url, &config).await;

    let entry = crate::fetch::fetch(&request.url, allow_local)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let entry_url = entry.final_url.clone();

    let mut result = ScanResult {
        target: entry_url.clone(),
        ..Default::default()
    };

    // The entry origin, which every scope decision is measured against. It comes
    // from a URL a fetch already accepted, so it parses.
    let Ok(entry_parsed) = reqwest::Url::parse(&entry_url) else {
        return Err((StatusCode::BAD_REQUEST, "entry URL did not parse".into()));
    };

    // A redirect is read like any page, and the person is told. What goes further than
    // reading is for the site they named, which is the only one they vouched for.
    let arrived = landed(&request.url, &entry_parsed);

    // A local page sending the crawl to a public site does not make that site local, or its
    // name could turn to a private address part way through what follows.
    let allow_local = allow_local && arrived.same_service;
    if allow_local {
        config.remember_local(&entry_url);
    }

    if !arrived.same_service {
        result.notices.push(format!(
            "The target redirected from {} to {}, so this is what that address holds.{}",
            request.url,
            entry_url,
            if arrived.same_site {
                ""
            } else {
                " File names were not tried on it, since it is not the site you named."
            }
        ));
    }

    // The whole passive crawl shares one deadline, checked between fetches, so a
    // site that answers slowly cannot hold the request open indefinitely.
    let deadline = Instant::now() + PASSIVE_DEADLINE;
    let mut time_limit_hit = false;

    // Every response searched that stopped at the body limit, the entry first.
    let mut cut = usize::from(entry.truncated);
    let mut undone = Undone::default();

    let (mut images, mut scripts, mut assets, mut external) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());

    // Pages queued to visit, and the set already seen so none is fetched twice.
    let mut queue: Vec<String> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(entry_url.clone());

    // Page bodies kept for the active pass, which reads endpoint names out of the
    // source that a crawl's `href`/`src` scan never saw.
    let mut bodies: Vec<Vec<u8>> = Vec::new();

    // The entry, whose links seed the queue.
    {
        let (flags, comments, references) =
            glean_off_thread(entry_url.clone(), entry.body.clone(), entry.headers.clone()).await;
        result.pages.push(PageResult {
            url: entry_url.clone(),
            status: entry.status,
        });
        result.flags.extend(flags);
        result.comments.extend(comments);
        enqueue_sitemap(
            &entry.body,
            &entry_url,
            &entry_parsed,
            &mut visited,
            &mut queue,
        );
        bodies.push(entry.body);

        let mut buckets = Buckets {
            images: &mut images,
            scripts: &mut scripts,
            assets: &mut assets,
            external: &mut external,
        };
        for link in categorize(references, &entry_parsed, &mut buckets) {
            if visited.insert(link.clone()) {
                queue.push(link);
            }
        }
    }

    // robots.txt names paths a crawler is asked to avoid, which is a map to what
    // is worth a look. Its paths join the queue like any other, but only those on
    // the entry's own origin: an absolute Disallow pointing at another host is not
    // the target and is not fetched.
    if let Ok(robots_url) = entry_parsed.join("/robots.txt")
        && let Ok(robots) = crate::fetch::fetch(robots_url.as_str(), allow_local).await
    {
        cut += usize::from(robots.truncated);
        for path in crate::crawl::robots_paths(&entry_parsed, &robots.body) {
            if same_origin(&path, &entry_parsed) && visited.insert(path.clone()) {
                queue.push(path);
            }
        }
    }

    // One level down: fetch each queued page, gather everything it references,
    // but do not follow its own links further.
    let mut cursor = 0;
    while cursor < queue.len() && result.pages.len() < MAX_PAGES {
        if Instant::now() >= deadline {
            time_limit_hit = true;
            break;
        }
        let url = queue[cursor].clone();
        cursor += 1;

        let answer = crate::fetch::fetch(&url, allow_local).await;
        undone.failed += usize::from(answer.is_err());
        if let Ok(page) = answer {
            cut += usize::from(page.truncated);
            let (flags, comments, references) =
                glean_off_thread(url.clone(), page.body.clone(), page.headers.clone()).await;
            result.pages.push(PageResult {
                url: url.clone(),
                status: page.status,
            });
            result.flags.extend(flags);
            result.comments.extend(comments);
            enqueue_sitemap(&page.body, &url, &entry_parsed, &mut visited, &mut queue);
            bodies.push(page.body);

            let mut buckets = Buckets {
                images: &mut images,
                scripts: &mut scripts,
                assets: &mut assets,
                external: &mut external,
            };
            categorize(references, &entry_parsed, &mut buckets);
        }
    }

    // Reaching the limit is one thing and running out of time is another, with its own notice.
    if !time_limit_hit && result.pages.len() >= MAX_PAGES {
        undone.pages_left = queue.len() - cursor;
    }

    // Files a crawl never links to, tried by name: a source backup left in
    // place, a dotfile served by mistake, a flag dropped at the root. The
    // server's own not-found answer is learned first so a soft-404 site does
    // not turn every guess into a find. Each hit still runs the guard.
    if arrived.same_site {
        if Instant::now() < deadline {
            let (sweep_cut, sweep_capped) = probe_by_name(
                allow_local,
                deadline,
                &entry_parsed,
                &mut visited,
                &mut result,
                &mut images,
                &mut scripts,
                &mut assets,
                &mut external,
            )
            .await;
            cut += sweep_cut;
            undone.sweep_capped = sweep_capped;
        } else {
            time_limit_hit = true;
        }
    }

    // Scripts and stylesheets the crawl linked but did not open, read for the
    // flags that hide in a CSS escape or a JS constant.
    let resources: Vec<String> = scripts
        .iter()
        .chain(assets.iter())
        .filter(|url| is_texty(url))
        .cloned()
        .collect();
    let harvested =
        harvest_resources(allow_local, deadline, &resources, &mut visited, &mut result).await;
    cut += harvested.cut;
    undone.resources_left = harvested.left;
    undone.failed += harvested.failed;
    if Instant::now() >= deadline {
        time_limit_hit = true;
    }

    // The active battery, only when the page's authorization affirmation asked
    // for it. This is the half that sends crafted requests, so it never runs when
    // the entry redirected to another origin: the person authorised the target
    // they named, not wherever it pointed.
    if request.active {
        if arrived.same_service {
            let active =
                crate::active::run(&entry_url, allow_local, &bodies, &request.hints).await;
            cut += active.cut;
            undone.active_stopped = active.stopped;
            for hit in active.hits {
                result
                    .flags
                    .push(located(hit.value, &hit.source, &hit.note));
            }
        } else {
            result.notices.push(format!(
                "Active checks were skipped because the target redirected from {} to {}.",
                request.url, entry_url
            ));
        }
    }

    result.images = sorted(images);
    result.scripts = sorted(scripts);
    result.assets = sorted(assets);
    result.external = sorted(external);

    // One line per finding, keeping the first page it was seen on.
    result.flags = dedup_located(result.flags);
    result.comments = dedup_located(result.comments);

    if time_limit_hit {
        result
            .notices
            .push("The scan reached its time limit; these are the results found by then.".into());
    }
    if let Some(notice) = cut_notice(cut) {
        result.notices.push(notice);
    }
    result.notices.extend(undone_notices(&undone));

    // Hold the result to sensible sizes, so one hostile page cannot return
    // megabytes of findings. Each cap that bites leaves a notice with the count.
    cap_with_notice(&mut result.flags, MAX_FLAGS, "flags", &mut result.notices);
    cap_with_notice(
        &mut result.comments,
        MAX_COMMENTS,
        "comments",
        &mut result.notices,
    );
    cap_with_notice(
        &mut result.images,
        MAX_BUCKET,
        "images",
        &mut result.notices,
    );
    cap_with_notice(
        &mut result.scripts,
        MAX_BUCKET,
        "scripts",
        &mut result.notices,
    );
    cap_with_notice(
        &mut result.assets,
        MAX_BUCKET,
        "assets",
        &mut result.notices,
    );
    cap_with_notice(
        &mut result.external,
        MAX_BUCKET,
        "external links",
        &mut result.notices,
    );

    Ok(Json(result))
}

/// The one line that covers every response cut at the body limit, so a scan that
/// stopped short of a flag does not read as one that looked and found nothing.
fn cut_notice(cut: usize) -> Option<String> {
    let limit = crate::fetch::MAX_BODY / (1024 * 1024);
    let responses = if cut == 1 { "response" } else { "responses" };
    (cut > 0).then(|| {
        format!(
            "{cut} {responses} ran past the {limit} MiB Trawl reads of each. The rest went unread, so a flag there would not show here."
        )
    })
}

/// Truncates a list to a cap and, when that drops anything, records how many were
/// left out so the person is not shown a silently shortened result.
fn cap_with_notice<T>(items: &mut Vec<T>, cap: usize, label: &str, notices: &mut Vec<String>) {
    if items.len() > cap {
        let omitted = items.len() - cap;
        items.truncate(cap);
        notices.push(format!("{label}: showing {cap}, {omitted} more left out."));
    }
}

fn dedup_located(items: Vec<Located>) -> Vec<Located> {
    let mut seen = HashSet::new();
    items
        .into_iter()
        .filter(|item| seen.insert(item.value.clone()))
        .collect()
}

#[derive(Deserialize)]
struct FetchQuery {
    url: String,
}

/// The media types the proxy serves with the target's own `Content-Type`: raster
/// images the page shows as a thumbnail and hands to the offline tools. Anything
/// else is served as an opaque download, so a proxied HTML page or script is
/// never rendered as itself in the person's browser.
const RASTER_IMAGE_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/bmp",
    "image/webp",
    "image/x-icon",
    "image/vnd.microsoft.icon",
];

/// Whether a `Content-Type` names a raster image, matched on the media type with
/// parameters ignored and case folded, so `image/PNG; charset=binary` still counts.
fn is_raster_image(content_type: &str) -> bool {
    let media = content_type.split(';').next().unwrap_or("").trim();
    RASTER_IMAGE_TYPES
        .iter()
        .any(|allowed| media.eq_ignore_ascii_case(allowed))
}

/// Hands the raw bytes of a guarded URL back to the page.
///
/// This is what lets the browser show a thumbnail of an image on the target, and
/// hand that same image to the offline tools, without the page itself ever
/// reaching across origins: the scanner fetches it, under the same guard as a
/// scan, and returns the bytes.
///
/// A raster image keeps its type so the page can render it; everything else is
/// forced to an opaque attachment, and every response is marked no-sniff and
/// sandboxed, so nothing proxied can run as a document in the person's origin.
async fn raw(
    State(config): State<Config>,
    headers: HeaderMap,
    Query(query): Query<FetchQuery>,
) -> Result<impl IntoResponse, ApiError> {
    authorize_bearer(&headers, &config)?;

    let allow_local = fetch_allows_local(&query.url, &config).await;

    let request = crate::fetch::Request {
        max_body: Some(FETCH_MAX_BODY),
        ..Default::default()
    };
    let fetched = crate::fetch::fetch_with(&query.url, allow_local, &request)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let raw_type = fetched
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.clone());

    // A raster image passes its type through; anything else becomes an opaque
    // download, so the browser never treats proxied bytes as a page to render.
    let mut content_type = HeaderValue::from_static("application/octet-stream");
    let mut attachment = true;
    if let Some(raw_type) = raw_type.as_deref()
        && is_raster_image(raw_type)
        && let Ok(value) = HeaderValue::from_str(raw_type)
    {
        content_type = value;
        attachment = false;
    }

    let mut out = HeaderMap::new();
    out.insert(header::CONTENT_TYPE, content_type);
    out.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    out.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox"),
    );
    if attachment {
        out.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment"),
        );
    }
    if fetched.truncated {
        out.insert(TRUNCATED_HEADER, HeaderValue::from_static("1"));
    }

    Ok((out, fetched.body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn config() -> Config {
        Config::new(
            false,
            TOKEN.to_string(),
            "https://trawl.example".to_string(),
        )
        .unwrap()
    }

    fn authorization(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        headers
    }

    /// Answers every connection for as long as the test runs: the body a path names,
    /// whatever its query, or else a 404 carrying `not_found`.
    async fn site(routes: Vec<(&'static str, Vec<u8>)>, not_found: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        let answers = Arc::new((routes, not_found));
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let answers = answers.clone();
                tokio::spawn(async move {
                    let mut request = [0u8; 2048];
                    let read = socket.read(&mut request).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&request[..read]);
                    let path = request.split([' ', '?']).nth(1).unwrap_or("/");

                    let (routes, not_found) = &*answers;
                    let (status, body) = match routes.iter().find(|(route, _)| *route == path) {
                        Some((_, body)) => ("200 OK", body),
                        None => ("404 Not Found", not_found),
                    };
                    let head = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = socket.write_all(head.as_bytes()).await;
                    let _ = socket.write_all(body).await;
                    // Left unread, a request's tail would reset the connection under the
                    // reply on its way back.
                    let _ = socket.shutdown().await;
                    while matches!(socket.read(&mut [0u8; 2048]).await, Ok(1..)) {}
                });
            }
        });
        at
    }

    /// `head`, filler up to all a fetch reads, then `tail`, which it never gets to.
    fn past_the_limit(head: &str, tail: &str) -> Vec<u8> {
        let mut body = head.as_bytes().to_vec();
        body.resize(crate::fetch::MAX_BODY, b' ');
        body.extend_from_slice(tail.as_bytes());
        body
    }

    async fn scanned(at: SocketAddr, active: bool) -> ScanResult {
        let config =
            Config::new(true, TOKEN.to_string(), "https://trawl.example".to_string()).unwrap();
        let request = ScanRequest {
            url: format!("http://{at}/"),
            active,
            hints: Vec::new(),
        };
        let headers = authorization(&format!("Bearer {TOKEN}"));
        let Ok(Json(result)) = scan(State(config), headers, Json(request)).await else {
            panic!("the scan was refused");
        };
        result
    }

    fn flags_of(result: &ScanResult) -> Vec<&str> {
        result.flags.iter().map(|flag| flag.value.as_str()).collect()
    }

    #[test]
    fn a_cut_notice_gives_the_count_and_the_limit() {
        assert_eq!(cut_notice(0), None);

        let one = cut_notice(1).unwrap();
        assert!(one.starts_with("1 response ran past the 2 MiB "), "{one}");

        let five = cut_notice(5).unwrap();
        assert!(five.starts_with("5 responses ran past the 2 MiB "), "{five}");
    }

    #[tokio::test]
    async fn everything_a_scan_searched_that_was_cut_is_counted_in_one_notice() {
        let page = r#"<a href="/next">on</a><script src="/app.js"></script> flag{before_the_cut}"#;
        let tail = "flag{after_the_cut}";
        let routes = vec![
            ("/", past_the_limit(page, tail)),
            ("/next", past_the_limit("", tail)),
            ("/robots.txt", past_the_limit("", tail)),
            ("/.env", past_the_limit("", tail)),
            ("/app.js", past_the_limit("", tail)),
        ];
        let at = site(routes, Vec::new()).await;

        let result = scanned(at, false).await;

        assert_eq!(result.notices, [cut_notice(5).unwrap()]);
        let flags = flags_of(&result);
        assert!(flags.contains(&"flag{before_the_cut}"), "{flags:?}");
        assert!(!flags.contains(&tail), "{flags:?}");
    }

    /// A route for a path that has to outlive the site it is served from.
    fn leaked(path: String) -> &'static str {
        Box::leak(path.into_boxed_str())
    }

    #[tokio::test]
    async fn a_crawl_that_stops_at_its_limit_on_pages_says_so() {
        let extra = 5;
        let links: String = (0..MAX_PAGES + extra)
            .map(|i| format!(r#"<a href="/p{i}">page</a>"#))
            .collect();
        let at = site(vec![("/", links.into_bytes())], Vec::new()).await;

        let result = scanned(at, false).await;

        let expected = undone_notices(&Undone {
            pages_left: 1 + extra,
            ..Undone::default()
        });
        assert!(result.notices.contains(&expected[0]), "{:?}", result.notices);
    }

    #[tokio::test]
    async fn a_scan_that_stops_at_its_limit_on_scripts_says_so() {
        // Two pages linking every one of them, which must not count each of them twice.
        let scripts: String = (0..MAX_RESOURCES + 4)
            .map(|i| format!(r#"<script src="/s{i}.js"></script>"#))
            .collect();
        let entry = format!(r#"<a href="/next">next</a>{scripts}"#);
        let routes = vec![("/", entry.into_bytes()), ("/next", scripts.into_bytes())];
        let at = site(routes, Vec::new()).await;

        let result = scanned(at, false).await;

        let expected = undone_notices(&Undone {
            resources_left: 4,
            ..Undone::default()
        });
        assert!(result.notices.contains(&expected[0]), "{:?}", result.notices);
    }

    #[tokio::test]
    async fn a_sweep_that_stops_at_its_limit_on_finds_says_so() {
        // Every name tried answers differently from the calibration paths, so each is a find.
        let names = SENSITIVE_PATHS.iter().chain(crate::discovery::DISCOVERY_PATHS.iter());
        let mut routes: Vec<(&'static str, Vec<u8>)> =
            names.map(|path| (*path, b"something is here".to_vec())).collect();
        routes.push((leaked("/".to_string()), b"home".to_vec()));
        let at = site(routes, Vec::new()).await;

        let result = scanned(at, false).await;

        let expected = undone_notices(&Undone {
            sweep_capped: true,
            ..Undone::default()
        });
        assert!(result.notices.contains(&expected[0]), "{:?}", result.notices);
    }

    #[tokio::test]
    async fn an_active_pass_that_runs_out_of_requests_says_so() {
        // More names in the page's source than the pass has requests to spend on them.
        let paths: Vec<String> = (0..crate::active::REQUEST_BUDGET + 50)
            .map(|i| format!("/api/e{i}"))
            .collect();
        let source: String = paths.iter().map(|p| format!(r#"fetch("{p}");"#)).collect();
        let mut routes: Vec<(&'static str, Vec<u8>)> = paths
            .into_iter()
            .map(|path| (leaked(path), b"answered".to_vec()))
            .collect();
        routes.push(("/", format!("<script>{source}</script>").into_bytes()));
        let at = site(routes, Vec::new()).await;

        let outcome =
            crate::active::run(&format!("http://{at}/"), true, &[source.into_bytes()], &[]).await;

        assert!(outcome.stopped);
    }

    #[tokio::test]
    async fn an_active_pass_that_finishes_does_not_say_it_stopped() {
        let at = site(vec![("/", b"nothing to see".to_vec())], Vec::new()).await;

        let outcome = crate::active::run(&format!("http://{at}/"), true, &[], &[]).await;

        assert!(!outcome.stopped);
    }

    #[test]
    fn nothing_left_undone_leaves_no_notice() {
        assert!(undone_notices(&Undone::default()).is_empty());

        let failed = undone_notices(&Undone {
            failed: 2,
            ..Undone::default()
        });
        assert!(failed[0].ends_with("did not search: 2."), "{failed:?}");
    }

    #[tokio::test]
    async fn a_page_that_ends_right_at_the_limit_leaves_no_notice() {
        let flag = "flag{on_the_last_byte}";
        let mut body = vec![b' '; crate::fetch::MAX_BODY - flag.len()];
        body.extend_from_slice(flag.as_bytes());
        let at = site(vec![("/", body)], Vec::new()).await;

        let result = scanned(at, false).await;

        assert!(flags_of(&result).contains(&flag));
        assert!(result.notices.is_empty(), "{:?}", result.notices);
    }

    #[tokio::test]
    async fn a_long_answer_the_scan_did_not_search_is_not_counted() {
        // The script and every name tried answer with a long 404, which only says nothing
        // is there. The calibration requests get the same, and are only ever measured.
        let page = br#"<script src="/gone.js"></script>"#.to_vec();
        let routes = vec![("/", page), ("/robots.txt", Vec::new())];
        let at = site(routes, past_the_limit("", "x")).await;

        let result = scanned(at, false).await;

        assert!(result.notices.is_empty(), "{:?}", result.notices);
    }

    #[tokio::test]
    async fn the_active_pass_adds_what_it_cut_to_the_same_notice() {
        let routes = vec![
            ("/", past_the_limit("", "x")),
            ("/api", past_the_limit("", "flag{after_the_cut}")),
        ];
        let at = site(routes, Vec::new()).await;

        let passive = scanned(at, false).await;
        assert_eq!(passive.notices, [cut_notice(1).unwrap()]);

        let active = scanned(at, true).await;
        assert_eq!(active.notices.len(), 1, "{:?}", active.notices);
        let count = active.notices[0].split(' ').next().unwrap();
        assert!(count.parse::<usize>().unwrap() > 1, "{:?}", active.notices);
        assert!(!flags_of(&active).contains(&"flag{after_the_cut}"));
    }

    #[test]
    fn config_accepts_a_strong_token_and_exact_origin() {
        let config = config();

        assert_eq!(config.token, TOKEN);
        assert_eq!(config.allowed_origin, "https://trawl.example");
    }

    #[test]
    fn config_rejects_weak_or_invalid_tokens() {
        for token in [
            "short",
            "0123456789abcdef0123456789abcde ",
            "0123456789abcdef0123456789abcde!",
        ] {
            assert!(
                Config::new(
                    false,
                    token.to_string(),
                    "https://trawl.example".to_string()
                )
                .is_err(),
                "accepted {token:?}"
            );
        }

        assert!(Config::new(false, "a".repeat(257), "https://trawl.example".to_string()).is_err());
    }

    #[test]
    fn config_rejects_anything_beyond_an_exact_http_origin() {
        for origin in [
            "trawl.example",
            "ftp://trawl.example",
            "https://trawl.example/",
            "https://trawl.example/path",
            "https://trawl.example?mode=test",
            "https://trawl.example#fragment",
            "https://user@trawl.example",
        ] {
            assert!(
                Config::new(false, TOKEN.to_string(), origin.to_string()).is_err(),
                "accepted {origin:?}"
            );
        }
    }

    #[test]
    fn bearer_auth_requires_the_configured_token() {
        let config = config();

        assert!(authorize_bearer(&authorization(&format!("Bearer {TOKEN}")), &config).is_ok());
        assert!(authorize_bearer(&authorization(&format!("bearer {TOKEN}")), &config).is_ok());

        for headers in [
            HeaderMap::new(),
            authorization("Basic 0123456789abcdef0123456789abcdef"),
            authorization("Bearer 0123456789abcdef0123456789abcdee"),
            authorization("Bearer 0123456789abcdef0123456789abcdef extra"),
        ] {
            let error = authorize_bearer(&headers, &config).unwrap_err();
            assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        }
    }

    #[test]
    fn a_query_token_no_longer_authorizes_fetch() {
        // The query-token form is gone: `?token=` binds to nothing on the request,
        // and the only credential the proxy reads is the bearer header. A request
        // carrying a token only in the query, with no header, is unauthorized.
        let config = config();

        let uri: axum::http::Uri = "http://127.0.0.1/fetch?url=http%3A%2F%2Ft.example%2Fa&token=0123456789abcdef0123456789abcdef"
            .parse()
            .unwrap();
        let query: Query<FetchQuery> = Query::try_from_uri(&uri).unwrap();
        assert_eq!(query.url, "http://t.example/a");

        // No bearer header, token present only in the query: refused.
        let error = authorize_bearer(&HeaderMap::new(), &config).unwrap_err();
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        // The bearer header remains the way in.
        assert!(authorize_bearer(&authorization(&format!("Bearer {TOKEN}")), &config).is_ok());
    }

    #[test]
    fn host_header_must_be_loopback() {
        // The rebinding guard: only loopback names, and only on the bound port.
        for host in [
            "127.0.0.1:8099",
            "localhost:8099",
            "[::1]:8099",
            "127.0.0.1",
            "localhost",
        ] {
            assert!(host_is_allowed(host, 8099), "{host} should be allowed");
        }
        for host in [
            "evil.example",
            "evil.example:8099",
            "127.0.0.1:9000", // right host, wrong port
            "127.0.0.1.evil.example:8099",
            "10.0.0.1:8099",
            // Shapes that read as loopback to one parser and as a stranger to another.
            "127.0.0.1:8099@evil.example",
            "localhost:8099:8099",
            "127.0.0.1:",
            "127.0.0.1:not-a-port",
            "[::1]evil.example:8099",
            "[::1]:not-a-port",
            "::1",
        ] {
            assert!(!host_is_allowed(host, 8099), "{host} should be refused");
        }
    }

    #[test]
    fn a_request_must_carry_exactly_one_host() {
        let host = |value: &'static str| HeaderValue::from_static(value);

        let mut headers = HeaderMap::new();
        assert_eq!(only_host(&headers), None);

        headers.append(header::HOST, host("127.0.0.1:8099"));
        assert_eq!(only_host(&headers), Some("127.0.0.1:8099"));

        headers.append(header::HOST, host("evil.example"));
        assert_eq!(only_host(&headers), None);
    }

    #[test]
    fn a_redirect_is_measured_against_the_address_named() {
        let at = |url: &str| {
            let entry = reqwest::Url::parse(url).unwrap();
            let arrived = landed("http://target.example/", &entry);
            (arrived.same_service, arrived.same_site)
        };

        assert_eq!(at("http://target.example/home"), (true, true));
        assert_eq!(at("https://target.example/"), (false, true));
        assert_eq!(at("http://target.example:8080/"), (false, false));
        assert_eq!(at("http://www.target.example/"), (false, false));
        assert_eq!(at("https://elsewhere.example/"), (false, false));

        let entry = reqwest::Url::parse("http://127.0.0.1:5000/home").unwrap();
        let arrived = landed("http://localhost:5000/", &entry);
        assert!(arrived.same_service && arrived.same_site, "one machine, one port");
    }

    #[tokio::test]
    async fn a_fetch_reaches_local_only_for_an_origin_a_scan_found_local() {
        let config =
            Config::new(true, TOKEN.to_string(), "https://trawl.example".to_string()).unwrap();
        let image = "http://127.0.0.1:5000/shot.png";

        assert!(!fetch_allows_local(image, &config).await, "nothing scanned yet");

        config.remember_local("http://127.0.0.1:5000/");
        assert!(fetch_allows_local(image, &config).await);

        let shared = config.clone();
        assert!(fetch_allows_local(image, &shared).await, "every handler sees it");

        for other in ["http://127.0.0.1:5001/shot.png", "http://localhost:5000/shot.png"] {
            assert!(!fetch_allows_local(other, &config).await, "{other} was never scanned");
        }
    }

    #[tokio::test]
    async fn a_scanner_outside_local_mode_reaches_nothing_local_whatever_it_remembers() {
        let config = self::config();
        config.remember_local("http://127.0.0.1:5000/");

        assert!(!fetch_allows_local("http://127.0.0.1:5000/shot.png", &config).await);
    }

    #[test]
    fn same_origin_distinguishes_port_and_scheme() {
        let entry = reqwest::Url::parse("http://target.example:80/app").unwrap();
        assert!(same_origin("http://target.example/other", &entry));
        // A different port on the same host is a different origin.
        assert!(!same_origin("http://target.example:8080/other", &entry));
        // So is a different scheme.
        assert!(!same_origin("https://target.example/other", &entry));
        assert!(!same_origin("http://other.example/", &entry));
    }

    #[test]
    fn raster_images_pass_type_through_and_nothing_else_does() {
        assert!(is_raster_image("image/png"));
        assert!(is_raster_image("image/jpeg; charset=binary"));
        assert!(is_raster_image("IMAGE/PNG"));
        assert!(is_raster_image("image/vnd.microsoft.icon"));
        assert!(is_raster_image("image/x-icon"));
        // Not raster: a page, a script, a vector image that can carry script.
        assert!(!is_raster_image("text/html"));
        assert!(!is_raster_image("image/svg+xml"));
        assert!(!is_raster_image("application/javascript"));
        assert!(!is_raster_image(""));
    }

    #[test]
    fn local_mode_needs_exactly_one() {
        assert!(local_requested(true, None));
        assert!(local_requested(false, Some("1")));
        // The old bug: any value, even 0, turned it on. Only "1" now.
        assert!(!local_requested(false, Some("0")));
        assert!(!local_requested(false, Some("")));
        assert!(!local_requested(false, Some("true")));
        assert!(!local_requested(false, None));
    }

    #[test]
    fn caps_truncate_and_leave_a_notice() {
        let mut items: Vec<u32> = (0..10).collect();
        let mut notices = Vec::new();
        cap_with_notice(&mut items, 4, "things", &mut notices);
        assert_eq!(items.len(), 4);
        assert_eq!(notices.len(), 1);
        assert!(
            notices[0].contains('6'),
            "notice should name the omitted count"
        );

        // A list within the cap is untouched and leaves no notice.
        let mut small = vec![1, 2];
        let mut none = Vec::new();
        cap_with_notice(&mut small, 4, "things", &mut none);
        assert_eq!(small.len(), 2);
        assert!(none.is_empty());
    }
}
