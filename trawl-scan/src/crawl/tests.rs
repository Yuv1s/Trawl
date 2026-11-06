use super::*;

fn base() -> Url {
    Url::parse("https://chal.example.com/dir/page.html").unwrap()
}

fn kinds<'a>(refs: &'a [Reference], url: &str) -> Option<&'a Reference> {
    refs.iter().find(|r| r.url == url)
}

const PAGE: &[u8] = br#"
<!DOCTYPE html>
<html>
<head>
  <link rel="stylesheet" href="/assets/site.css">
  <script src="app.js"></script>
  <!-- TODO: remove before deploy, flag is flag{leftover_in_a_comment} -->
</head>
<body>
  <a href="/login">Login</a>
  <a href='../admin/'>Admin</a>
  <a href="https://cdn.other.com/lib.js">external</a>
  <img src="/img/banner.png" data-src="/img/decoy.png">
  <form action="/submit" method="post"></form>
  <a href="mailto:root@example.com">mail</a>
</body>
</html>
"#;

#[test]
fn resolves_relative_links_against_the_page() {
    let refs = references(&base(), PAGE).items;

    // Root-relative and document-relative both resolve correctly.
    assert!(kinds(&refs, "https://chal.example.com/login").is_some());
    assert!(kinds(&refs, "https://chal.example.com/dir/app.js").is_some());
    assert!(kinds(&refs, "https://chal.example.com/admin/").is_some());
}

#[test]
fn classifies_by_extension() {
    let refs = references(&base(), PAGE).items;

    assert_eq!(
        kinds(&refs, "https://chal.example.com/img/banner.png")
            .unwrap()
            .kind,
        Kind::Image
    );
    assert_eq!(
        kinds(&refs, "https://chal.example.com/dir/app.js")
            .unwrap()
            .kind,
        Kind::Script
    );
    assert_eq!(
        kinds(&refs, "https://chal.example.com/assets/site.css")
            .unwrap()
            .kind,
        Kind::Style
    );
    assert_eq!(
        kinds(&refs, "https://chal.example.com/login").unwrap().kind,
        Kind::Page
    );
}

#[test]
fn marks_off_host_references() {
    let refs = references(&base(), PAGE).items;

    let external = kinds(&refs, "https://cdn.other.com/lib.js").expect("external link missed");
    assert!(!external.same_host);
    assert!(refs.iter().filter(|r| r.same_host).count() >= 4);
}

#[test]
fn does_not_mistake_data_src_for_src() {
    // The boundary check earns its place here. `src` reads banner.png, and the
    // `src` inside `data-src` is not a match, so the decoy behind it is left
    // alone rather than reported as a real reference.
    let refs = references(&base(), PAGE).items;
    assert!(kinds(&refs, "https://chal.example.com/img/banner.png").is_some());
    assert!(kinds(&refs, "https://chal.example.com/img/decoy.png").is_none());
}

#[test]
fn drops_non_web_schemes() {
    let refs = references(&base(), PAGE).items;
    assert!(refs.iter().all(|r| r.url.starts_with("http")));
    assert!(refs.iter().all(|r| !r.url.contains("mailto")));
}

#[test]
fn deduplicates_repeated_links() {
    let twice = br#"<a href="/flag">one</a> <a href="/flag">two</a>"#;
    let refs = references(&base(), twice).items;
    assert_eq!(refs.iter().filter(|r| r.url.ends_with("/flag")).count(), 1);
}

#[test]
fn pulls_comments_including_a_flag() {
    let found = comments(PAGE).items;
    assert!(
        found
            .iter()
            .any(|c| c.contains("flag{leftover_in_a_comment}"))
    );
}

#[test]
fn a_comment_with_no_close_is_ignored() {
    assert!(comments(b"text <!-- never closed").items.is_empty());
}

#[test]
fn robots_names_the_paths_it_hides() {
    let robots = b"User-agent: *\nDisallow: /secret/\nDisallow: /admin\nAllow: /public\nSitemap: https://chal.example.com/sitemap.xml\nDisallow: /\n";
    let paths = robots_paths(&base(), robots).items;

    assert!(paths.contains(&"https://chal.example.com/secret/".to_string()));
    assert!(paths.contains(&"https://chal.example.com/admin".to_string()));
    assert!(paths.contains(&"https://chal.example.com/public".to_string()));
    assert!(paths.contains(&"https://chal.example.com/sitemap.xml".to_string()));
    // "Disallow: /" is the whole site, not a hint, and is dropped.
    assert!(!paths.iter().any(|p| p == "https://chal.example.com/"));
}

#[test]
fn empty_or_binary_input_yields_nothing() {
    assert!(references(&base(), b"").items.is_empty());
    assert!(references(&base(), &[0xff, 0x00, 0xfe]).items.is_empty());
    assert!(comments(&[0xff, 0x00]).items.is_empty());
}

#[test]
fn sitemap_locs_finds_a_page_nothing_links_to() {
    let xml = br#"<?xml version="1.0"?>
        <urlset><url><loc>https://chal.example.com/</loc></url>
        <url><loc>https://chal.example.com/archive/tide-ledger-7f3a</loc></url></urlset>"#;
    let locs = sitemap_locs(&base(), xml).items;
    assert!(locs.contains(&"https://chal.example.com/archive/tide-ledger-7f3a".to_string()));
    // The same URL twice is one entry.
    let repeated = br#"<loc>https://chal.example.com/x</loc><loc>https://chal.example.com/x</loc>"#;
    assert_eq!(sitemap_locs(&base(), repeated).items.len(), 1);
    // Not a sitemap: nothing.
    assert!(
        sitemap_locs(&base(), b"<html><body>no locs here</body></html>")
            .items
            .is_empty()
    );
}

#[test]
fn references_and_comments_are_capped_on_a_hostile_page() {
    // A page with far more links and comments than the caps must come back
    // bounded, not with the whole flood, so one document cannot exhaust memory.
    let mut html = String::new();
    for i in 0..(MAX_REFERENCES + 500) {
        html.push_str(&format!("<a href=\"/p/{i}\">{i}</a>"));
    }
    for i in 0..(MAX_COMMENTS + 500) {
        html.push_str(&format!("<!-- c{i} -->"));
    }
    let refs = references(&base(), html.as_bytes());
    assert_eq!(refs.items.len(), MAX_REFERENCES);
    assert!(refs.cut, "the page has to be told it was cut");

    let found = comments(html.as_bytes());
    assert_eq!(found.items.len(), MAX_COMMENTS);
    assert!(found.cut, "the page has to be told it was cut");
}

#[test]
fn decode_url_turns_a_filename_flag_back() {
    assert_eq!(
        decode_url("/static/img/gallery-CTF%7Bin_the_name%7D.png"),
        "/static/img/gallery-CTF{in_the_name}.png"
    );
    // A plain URL is left as it is.
    assert_eq!(decode_url("/about"), "/about");
    // A stray percent that is not an escape is left alone.
    assert_eq!(decode_url("/a%zz/b"), "/a%zz/b");
}

#[test]
fn repeated_attributes_cost_neither_memory_nor_time() {
    // Every bare value used to run to the next space, which here is the end of the page,
    // and each one was copied: gigabytes from a body the fetch cap allows.
    let base = Url::parse("https://example.test/").unwrap();
    let body = "href=".repeat(2 * 1024 * 1024 / 5);

    let started = std::time::Instant::now();
    let found = references(&base, body.as_bytes());

    assert!(found.items.len() <= MAX_REFERENCES);
    assert!(
        started.elapsed().as_secs() < 10,
        "took {:?}",
        started.elapsed()
    );
}

#[test]
fn an_overlong_value_is_skipped_and_the_links_after_it_are_still_read() {
    let base = Url::parse("https://example.test/").unwrap();
    let long = "é".repeat(MAX_ATTRIBUTE_VALUE);
    let body = format!("<a href=\"{long}\">x</a><a href=\"/after\">y</a><a href=/bare>z</a>");

    let urls: Vec<String> = references(&base, body.as_bytes())
        .items
        .into_iter()
        .map(|found| found.url)
        .collect();

    assert!(
        urls.contains(&"https://example.test/after".to_string()),
        "{urls:?}"
    );
    assert!(
        urls.contains(&"https://example.test/bare".to_string()),
        "{urls:?}"
    );
}

#[test]
fn links_nothing_could_fetch_do_not_use_up_a_page_allowance() {
    let mut html = String::new();
    for i in 0..(MAX_REFERENCES + 500) {
        html.push_str(&format!("<a href=\"mailto:a{i}@example.com\">{i}</a>"));
    }
    html.push_str("<a href=\"/the-flag-page\">flag</a>");

    let refs = references(&base(), html.as_bytes());

    assert!(!refs.cut);
    assert!(kinds(&refs.items, "https://chal.example.com/the-flag-page").is_some());
}

#[test]
fn a_page_at_exactly_the_allowance_is_not_cut() {
    let html: String = (0..MAX_REFERENCES)
        .map(|i| format!("<a href=\"/p/{i}\">{i}</a>"))
        .collect();

    let refs = references(&base(), html.as_bytes());

    assert_eq!(refs.items.len(), MAX_REFERENCES);
    assert!(!refs.cut);
}

#[test]
fn a_flood_of_robots_entries_stops_at_the_allowance_and_says_so() {
    // Each entry would hold a copy of a long base: gigabytes from one small file.
    let base = Url::parse(&format!("https://example.test/{}/", "d".repeat(8000))).unwrap();
    let robots: String = (0..(MAX_REFERENCES + 500))
        .map(|i| {
            format!(
                "Allow: {i}
"
            )
        })
        .collect();

    let paths = robots_paths(&base, robots.as_bytes());

    assert_eq!(paths.items.len(), MAX_REFERENCES);
    assert!(paths.cut);
    assert!(
        !robots_paths(
            &base,
            b"Allow: /one
"
        )
        .cut
    );
}

#[test]
fn a_flood_of_sitemap_entries_stops_at_the_allowance_and_says_so() {
    let xml: String = (0..(MAX_REFERENCES + 500))
        .map(|i| format!("<loc>/p/{i}</loc>"))
        .collect();

    let locs = sitemap_locs(&base(), xml.as_bytes());

    assert_eq!(locs.items.len(), MAX_REFERENCES);
    assert!(locs.cut);
}
