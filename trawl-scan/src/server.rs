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

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tower_http::cors::CorsLayer;

/// What the scanner was started with. Carried into every handler so a request
/// cannot decide for itself whether local targets are allowed: only the person
/// who started the process can, by starting it that way.
#[derive(Clone)]
pub struct Config {
    pub allow_local: bool,
    token: String,
    allowed_origin: HeaderValue,
}

impl Config {
    pub fn new(allow_local: bool, token: String, origin: String) -> Result<Self, String> {
        validate_token(&token)?;
        let allowed_origin = validate_origin(&origin)?;

        Ok(Self {
            allow_local,
            token,
            allowed_origin,
        })
    }
}

pub fn app(config: Config) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(config.allowed_origin.clone())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]);

    Router::new()
        .route("/health", get(health))
        .route("/scan", post(scan))
        .route("/fetch", get(raw))
        .layer(cors)
        .with_state(config)
}

type ApiError = (StatusCode, String);

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

fn authorize_fetch(
    headers: &HeaderMap,
    query_token: Option<&str>,
    config: &Config,
) -> Result<(), ApiError> {
    let header_matches =
        bearer_token(headers).is_some_and(|token| tokens_equal(token, &config.token));
    let query_matches = query_token.is_some_and(|token| tokens_equal(token, &config.token));

    if header_matches || query_matches {
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

/// What a crawl turned up, grouped the way a person looks for it.
#[derive(Serialize, Default)]
struct ScanResult {
    /// Where the entry request ended up, after redirects.
    target: String,
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
        flags.push(located(found.value, page_url, &format!("{} in the source", found.how)));
    }

    // The response headers carry their own: a plain flag in X-Flag, a base64
    // payload in a cookie, an ETag written backwards.
    for (name, value) in headers {
        let name = name.to_ascii_lowercase();
        for flag in flags_in(value.as_bytes()) {
            flags.push(located(flag, page_url, &format!("in the {name} response header")));
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

fn same_host(url: &str, host: &Option<String>) -> bool {
    host.is_some()
        && &reqwest::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            == host
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
    entry_host: &Option<String>,
    into: &mut Buckets,
) -> Vec<String> {
    use crate::crawl::Kind;
    let mut page_links = Vec::new();

    for reference in references {
        if !same_host(&reference.url, entry_host) {
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
    entry_host: &Option<String>,
    visited: &mut HashSet<String>,
    queue: &mut Vec<String>,
) {
    let Ok(base) = reqwest::Url::parse(page_url) else {
        return;
    };
    for loc in crate::crawl::sitemap_locs(&base, body) {
        if same_host(&loc, entry_host) && visited.insert(loc.clone()) {
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

/// Fetches each text resource once and reads flags out of it, plain and decoded.
/// This is what catches a flag written into a stylesheet or a script the crawl
/// linked but never opened.
async fn harvest_resources(
    config: &Config,
    resources: &[String],
    visited: &mut HashSet<String>,
    result: &mut ScanResult,
) {
    const MAX_RESOURCES: usize = 30;
    let mut fetched = 0;

    for url in resources {
        if fetched >= MAX_RESOURCES {
            break;
        }
        if !is_texty(url) || !visited.insert(url.clone()) {
            continue;
        }
        fetched += 1;

        if let Ok(res) = crate::fetch::fetch(url, config.allow_local).await
            && res.status == 200
        {
            for value in flags_in(&res.body) {
                result.flags.push(located(value, url, ""));
            }
            for found in crate::decode::harvest(&res.body) {
                result
                    .flags
                    .push(located(found.value, url, &format!("{} in the source", found.how)));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn probe_sensitive_paths(
    config: &Config,
    entry_url: &str,
    entry_host: &Option<String>,
    visited: &mut HashSet<String>,
    result: &mut ScanResult,
    images: &mut Vec<String>,
    scripts: &mut Vec<String>,
    assets: &mut Vec<String>,
    external: &mut Vec<String>,
) {
    let Ok(base) = reqwest::Url::parse(entry_url) else {
        return;
    };

    for path in SENSITIVE_PATHS {
        if result.pages.len() >= MAX_PAGES {
            break;
        }
        let Ok(url) = base.join(path) else {
            continue;
        };
        let probe = url.to_string();
        if !visited.insert(probe.clone()) {
            continue;
        }

        if let Ok(page) = crate::fetch::fetch(&probe, config.allow_local).await
            && page.status == 200
            && !page.body.is_empty()
        {
            let (flags, comments, references) = glean(&probe, &page.body, &page.headers);
            result.pages.push(PageResult {
                url: probe.clone(),
                status: page.status,
            });
            result.flags.extend(flags);
            result.comments.extend(comments);

            let mut buckets = Buckets {
                images: &mut *images,
                scripts: &mut *scripts,
                assets: &mut *assets,
                external: &mut *external,
            };
            categorize(references, entry_host, &mut buckets);
        }
    }
}

async fn scan(
    State(config): State<Config>,
    headers: HeaderMap,
    Json(request): Json<ScanRequest>,
) -> Result<Json<ScanResult>, ApiError> {
    authorize_bearer(&headers, &config)?;

    let entry = crate::fetch::fetch(&request.url, config.allow_local)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let entry_url = entry.final_url.clone();

    let mut result = ScanResult {
        target: entry_url.clone(),
        ..Default::default()
    };

    let entry_host = reqwest::Url::parse(&entry_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string));

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
        let (flags, comments, references) = glean(&entry_url, &entry.body, &entry.headers);
        result.pages.push(PageResult {
            url: entry_url.clone(),
            status: entry.status,
        });
        result.flags.extend(flags);
        result.comments.extend(comments);
        enqueue_sitemap(&entry.body, &entry_url, &entry_host, &mut visited, &mut queue);
        bodies.push(entry.body.clone());

        let mut buckets = Buckets {
            images: &mut images,
            scripts: &mut scripts,
            assets: &mut assets,
            external: &mut external,
        };
        for link in categorize(references, &entry_host, &mut buckets) {
            if visited.insert(link.clone()) {
                queue.push(link);
            }
        }
    }

    // robots.txt names paths a crawler is asked to avoid, which is a map to what
    // is worth a look. Its paths join the queue like any other.
    if let Ok(base) = reqwest::Url::parse(&entry_url)
        && let Ok(robots_url) = base.join("/robots.txt")
        && let Ok(robots) = crate::fetch::fetch(robots_url.as_str(), config.allow_local).await
    {
        for path in crate::crawl::robots_paths(&base, &robots.body) {
            if visited.insert(path.clone()) {
                queue.push(path);
            }
        }
    }

    // One level down: fetch each queued page, gather everything it references,
    // but do not follow its own links further.
    let mut cursor = 0;
    while cursor < queue.len() && result.pages.len() < MAX_PAGES {
        let url = queue[cursor].clone();
        cursor += 1;

        if let Ok(page) = crate::fetch::fetch(&url, config.allow_local).await {
            let (flags, comments, references) = glean(&url, &page.body, &page.headers);
            result.pages.push(PageResult {
                url: url.clone(),
                status: page.status,
            });
            result.flags.extend(flags);
            result.comments.extend(comments);
            enqueue_sitemap(&page.body, &url, &entry_host, &mut visited, &mut queue);
            bodies.push(page.body.clone());

            let mut buckets = Buckets {
                images: &mut images,
                scripts: &mut scripts,
                assets: &mut assets,
                external: &mut external,
            };
            categorize(references, &entry_host, &mut buckets);
        }
    }

    // Sensitive files a crawl never links to, tried by name. Standard recon: a
    // source backup left in place, a dotfile served by mistake. Only ones that
    // answer with something are kept, and each still runs the guard.
    probe_sensitive_paths(
        &config,
        &entry_url,
        &entry_host,
        &mut visited,
        &mut result,
        &mut images,
        &mut scripts,
        &mut assets,
        &mut external,
    )
    .await;

    // Scripts and stylesheets the crawl linked but did not open, read for the
    // flags that hide in a CSS escape or a JS constant.
    let resources: Vec<String> = scripts
        .iter()
        .chain(assets.iter())
        .filter(|url| is_texty(url))
        .cloned()
        .collect();
    harvest_resources(&config, &resources, &mut visited, &mut result).await;

    // The active battery, only when the page's authorization affirmation asked
    // for it. This is the half that sends crafted requests.
    if request.active {
        for hit in crate::active::run(&entry_url, config.allow_local, &bodies, &request.hints).await {
            result.flags.push(located(hit.value, &hit.source, &hit.note));
        }
    }

    result.images = sorted(images);
    result.scripts = sorted(scripts);
    result.assets = sorted(assets);
    result.external = sorted(external);

    // One line per finding, keeping the first page it was seen on.
    result.flags = dedup_located(result.flags);
    result.comments = dedup_located(result.comments);

    Ok(Json(result))
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
    token: Option<String>,
}

/// Hands the raw bytes of a guarded URL back to the page.
///
/// This is what lets the browser show a thumbnail of an image on the target, and
/// hand that same image to the offline tools, without the page itself ever
/// reaching across origins: the scanner fetches it, under the same guard as a
/// scan, and returns the bytes with the type the target gave them.
async fn raw(
    State(config): State<Config>,
    headers: HeaderMap,
    Query(query): Query<FetchQuery>,
) -> Result<impl IntoResponse, ApiError> {
    authorize_fetch(&headers, query.token.as_deref(), &config)?;

    let fetched = crate::fetch::fetch(&query.url, config.allow_local)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let content_type = fetched
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    Ok(([(header::CONTENT_TYPE, content_type)], fetched.body))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn fetch_auth_accepts_a_bearer_header_or_query_token() {
        let config = config();
        let bearer = authorization(&format!("Bearer {TOKEN}"));

        assert!(authorize_fetch(&bearer, None, &config).is_ok());
        assert!(authorize_fetch(&HeaderMap::new(), Some(TOKEN), &config).is_ok());
        assert!(authorize_fetch(&authorization("Bearer wrong"), Some(TOKEN), &config).is_ok());

        let error = authorize_fetch(&HeaderMap::new(), None, &config).unwrap_err();
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        let error =
            authorize_fetch(&authorization("Bearer wrong"), Some("wrong"), &config).unwrap_err();
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
    }
}
