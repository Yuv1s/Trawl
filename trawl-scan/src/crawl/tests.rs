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
    let refs = references(&base(), PAGE);

    // Root-relative and document-relative both resolve correctly.
    assert!(kinds(&refs, "https://chal.example.com/login").is_some());
    assert!(kinds(&refs, "https://chal.example.com/dir/app.js").is_some());
    assert!(kinds(&refs, "https://chal.example.com/admin/").is_some());
}

#[test]
fn classifies_by_extension() {
    let refs = references(&base(), PAGE);

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
    let refs = references(&base(), PAGE);

    let external = kinds(&refs, "https://cdn.other.com/lib.js").expect("external link missed");
    assert!(!external.same_host);
    assert!(refs.iter().filter(|r| r.same_host).count() >= 4);
}

#[test]
fn does_not_mistake_data_src_for_src() {
    // The boundary check earns its place here. `src` reads banner.png, and the
    // `src` inside `data-src` is not a match, so the decoy behind it is left
    // alone rather than reported as a real reference.
    let refs = references(&base(), PAGE);
    assert!(kinds(&refs, "https://chal.example.com/img/banner.png").is_some());
    assert!(kinds(&refs, "https://chal.example.com/img/decoy.png").is_none());
}

#[test]
fn drops_non_web_schemes() {
    let refs = references(&base(), PAGE);
    assert!(refs.iter().all(|r| r.url.starts_with("http")));
    assert!(refs.iter().all(|r| !r.url.contains("mailto")));
}

#[test]
fn deduplicates_repeated_links() {
    let twice = br#"<a href="/flag">one</a> <a href="/flag">two</a>"#;
    let refs = references(&base(), twice);
    assert_eq!(refs.iter().filter(|r| r.url.ends_with("/flag")).count(), 1);
}

#[test]
fn pulls_comments_including_a_flag() {
    let found = comments(PAGE);
    assert!(
        found
            .iter()
            .any(|c| c.contains("flag{leftover_in_a_comment}"))
    );
}

#[test]
fn a_comment_with_no_close_is_ignored() {
    assert!(comments(b"text <!-- never closed").is_empty());
}

#[test]
fn robots_names_the_paths_it_hides() {
    let robots = b"User-agent: *\nDisallow: /secret/\nDisallow: /admin\nAllow: /public\nSitemap: https://chal.example.com/sitemap.xml\nDisallow: /\n";
    let paths = robots_paths(&base(), robots);

    assert!(paths.contains(&"https://chal.example.com/secret/".to_string()));
    assert!(paths.contains(&"https://chal.example.com/admin".to_string()));
    assert!(paths.contains(&"https://chal.example.com/public".to_string()));
    assert!(paths.contains(&"https://chal.example.com/sitemap.xml".to_string()));
    // "Disallow: /" is the whole site, not a hint, and is dropped.
    assert!(!paths.iter().any(|p| p == "https://chal.example.com/"));
}

#[test]
fn empty_or_binary_input_yields_nothing() {
    assert!(references(&base(), b"").is_empty());
    assert!(references(&base(), &[0xff, 0x00, 0xfe]).is_empty());
    assert!(comments(&[0xff, 0x00]).is_empty());
}

#[test]
fn sitemap_locs_finds_a_page_nothing_links_to() {
    let xml = br#"<?xml version="1.0"?>
        <urlset><url><loc>https://chal.example.com/</loc></url>
        <url><loc>https://chal.example.com/archive/tide-ledger-7f3a</loc></url></urlset>"#;
    let locs = sitemap_locs(&base(), xml);
    assert!(locs.contains(&"https://chal.example.com/archive/tide-ledger-7f3a".to_string()));
    // The same URL twice is one entry.
    let repeated = br#"<loc>https://chal.example.com/x</loc><loc>https://chal.example.com/x</loc>"#;
    assert_eq!(sitemap_locs(&base(), repeated).len(), 1);
    // Not a sitemap: nothing.
    assert!(sitemap_locs(&base(), b"<html><body>no locs here</body></html>").is_empty());
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
