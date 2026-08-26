//! Reading a page for everything it points at.
//!
//! A website is made of the things Trawl already reads: pages, images, scripts,
//! the odd comment a developer forgot to strip. So the scanner does not need to
//! understand a site, only to pull it apart into those pieces and hand each to
//! the tool that knows what to do with it. This is the pulling apart.
//!
//! The extraction is deliberately small and hand-written, no HTML parser pulled
//! in for it. It reaches for three attributes that carry a URL, `href`, `src`
//! and `action`, and for the comments between `<!--` and `-->`. That misses the
//! cleverest ways to reference a resource, and it is meant to: a scanner that
//! tries to be a browser is a browser, and this is a net, not a browser. What it
//! catches is the ordinary run of links and assets, which is where a flag left
//! lying around actually is.

use reqwest::Url;

/// What a referenced URL turns out to be, judged by its file extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Something to visit: another page, or an endpoint.
    Page,
    /// An image, which is Cuttlefish's problem once it is fetched.
    Image,
    /// A script, which is where client-side logic and stray endpoints hide.
    Script,
    /// A stylesheet.
    Style,
    /// A font, a document, an archive: fetched and read, not visited.
    Asset,
}

/// One thing a page pointed at, resolved to an absolute URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub url: String,
    pub kind: Kind,
    /// Whether it sits on the same host as the page that referenced it. Off-host
    /// links are reported but never followed: the target is the target.
    pub same_host: bool,
}

/// Pulls the value out of every `href`, `src` and `action` attribute.
///
/// Boundary-checked so `datasrc` is not mistaken for `src`, and it reads both
/// quoted and bare values. Anything stranger than that it lets go by.
fn attribute_values(html: &str) -> Vec<String> {
    let bytes = html.as_bytes();
    let mut out = Vec::new();

    for attr in ["href", "src", "action"] {
        let mut from = 0;
        while let Some(rel) = html[from..].find(attr) {
            let at = from + rel;
            from = at + attr.len();

            // The character before must not be part of a longer name.
            let boundary = at == 0
                || !matches!(bytes[at - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_');
            if !boundary {
                continue;
            }

            let mut i = from;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= bytes.len() || bytes[i] != b'=' {
                continue;
            }
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= bytes.len() {
                break;
            }

            let value = if bytes[i] == b'"' || bytes[i] == b'\'' {
                let quote = bytes[i];
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                &html[start..i]
            } else {
                let start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                    i += 1;
                }
                &html[start..i]
            };

            let value = value.trim();
            if !value.is_empty() {
                out.push(value.to_string());
            }
        }
    }

    out
}

/// Everything between `<!--` and `-->`, which is where a developer leaves the
/// thing they meant to take out.
pub fn comments(body: &[u8]) -> Vec<String> {
    let html = String::from_utf8_lossy(body);
    let mut out = Vec::new();
    let mut rest = html.as_ref();

    while let Some(start) = rest.find("<!--") {
        let after = &rest[start + 4..];
        let Some(end) = after.find("-->") else {
            break;
        };
        let body = after[..end].trim();
        if !body.is_empty() {
            out.push(body.to_string());
        }
        rest = &after[end + 3..];
    }

    out
}

fn classify(url: &Url) -> Kind {
    let last = url
        .path_segments()
        .and_then(|mut s| s.next_back())
        .unwrap_or("");
    let ext = last
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "svg" | "ico" | "tiff" => Kind::Image,
        "js" | "mjs" | "ts" => Kind::Script,
        "css" => Kind::Style,
        "woff" | "woff2" | "ttf" | "otf" | "eot" | "map" | "json" | "xml" | "txt" | "pdf"
        | "zip" | "gz" | "tar" | "wav" | "mp3" | "mp4" | "webm" | "ogg" => Kind::Asset,
        _ => Kind::Page,
    }
}

/// Every reference on a page, resolved against where the page lives.
///
/// Relative links become absolute, anything that is not http(s) is dropped, and
/// the list is deduplicated so a link repeated across a page is one finding.
pub fn references(base: &Url, body: &[u8]) -> Vec<Reference> {
    let html = String::from_utf8_lossy(body);
    let mut out: Vec<Reference> = Vec::new();

    for raw in attribute_values(&html) {
        let Ok(mut abs) = base.join(&raw) else {
            continue;
        };
        if !matches!(abs.scheme(), "http" | "https") {
            continue;
        }

        // A fragment is a place on a page, not a page. Dropping it keeps a
        // skip-to-content link like `#main` from looking like a second page.
        abs.set_fragment(None);

        let same_host = abs.host_str() == base.host_str();
        let url = abs.to_string();

        if out.iter().any(|seen| seen.url == url) {
            continue;
        }

        out.push(Reference {
            kind: classify(&abs),
            same_host,
            url,
        });
    }

    out
}

/// Percent-decodes a URL enough to read a flag out of it.
///
/// A brace in a filename arrives as `%7B` once the URL is normalised, so a flag
/// hidden in a path, `gallery-CTF{...}.png`, is invisible in the encoded form.
/// Turning it back is what lets the flag detector see it.
pub fn decode_url(url: &str) -> String {
    let bytes = url.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);

    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push(high * 16 + low);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

/// The paths a `robots.txt` asks crawlers to stay out of, which is a map to
/// where the interesting things are.
///
/// `Disallow` and `Allow` lines both name paths worth a look; `Sitemap` lines
/// name another file to read. All three are returned, resolved to absolute URLs.
pub fn robots_paths(base: &Url, body: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(body);
    let mut out: Vec<String> = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        let lower = line.to_ascii_lowercase();

        let value = if let Some(rest) = lower.strip_prefix("disallow:") {
            &line[line.len() - rest.len()..]
        } else if let Some(rest) = lower.strip_prefix("allow:") {
            &line[line.len() - rest.len()..]
        } else if let Some(rest) = lower.strip_prefix("sitemap:") {
            &line[line.len() - rest.len()..]
        } else {
            continue;
        };

        let value = value.trim();
        if value.is_empty() || value == "/" {
            continue;
        }

        if let Ok(abs) = base.join(value) {
            let url = abs.to_string();
            if !out.contains(&url) {
                out.push(url);
            }
        }
    }

    out
}

/// The URLs a sitemap lists in its `<loc>` tags, resolved to absolute.
///
/// A sitemap is where a site names pages nothing links to, which is exactly the
/// page a challenge leaves off the menu. The references scanner reads `href`,
/// `src` and `action`, and a `<loc>` is none of those, so a sitemap needs its
/// own small reader.
pub fn sitemap_locs(base: &Url, body: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(body);
    let mut out: Vec<String> = Vec::new();
    let mut rest = text.as_ref();

    while let Some(start) = rest.find("<loc>") {
        let after = &rest[start + 5..];
        let Some(end) = after.find("</loc>") else {
            break;
        };
        let raw = after[..end].trim();
        if let Ok(abs) = base.join(raw) {
            let url = abs.to_string();
            if !out.contains(&url) {
                out.push(url);
            }
        }
        rest = &after[end + 6..];
    }

    out
}

#[cfg(test)]
mod tests;
