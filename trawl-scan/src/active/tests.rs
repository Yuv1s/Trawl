use super::*;

#[test]
fn endpoints_from_source_reads_a_fetch_path() {
    let js = br#"async function load() { const r = await fetch("/api/user/search?name=x"); }
        const admin = '/admin/api/logs';
        const css = "/static/img/banner.png";"#;
    let found = endpoints_from_source(&[js.to_vec()]);
    assert!(found.iter().any(|p| p == "/api/user/search"));
    assert!(found.iter().any(|p| p == "/admin/api/logs"));
    // A plain asset path is not an endpoint worth probing.
    assert!(!found.iter().any(|p| p.contains("banner.png")));
}

#[test]
fn endpoints_from_source_is_empty_when_nothing_names_an_api() {
    let html = b"<html><body><a href=\"/about\">About</a></body></html>";
    assert!(endpoints_from_source(&[html.to_vec()]).is_empty());
}

#[test]
fn clean_hints_keeps_usable_tokens_and_drops_the_rest() {
    let hints = vec![
        "  verified_flag_field ".to_string(), // trimmed
        "x-nauticorp-internal".to_string(),   // hyphens are fine
        "api/reconcile".to_string(),          // a path is fine
        "verified_flag_field".to_string(),    // a duplicate, dropped
        "  ".to_string(),                     // empty after trim, dropped
        "drop\"table;--".to_string(),         // the dangerous bytes are stripped
    ];
    let cleaned = clean_hints(&hints);
    assert!(cleaned.contains(&"verified_flag_field".to_string()));
    assert!(cleaned.contains(&"x-nauticorp-internal".to_string()));
    assert!(cleaned.contains(&"api/reconcile".to_string()));
    // One copy of the duplicate, and the quote/semicolon stripped from the last.
    assert_eq!(
        cleaned
            .iter()
            .filter(|h| *h == "verified_flag_field")
            .count(),
        1
    );
    assert!(cleaned.iter().all(|h| !h.contains('"') && !h.contains(';')));
}

#[test]
fn clean_hints_caps_the_count() {
    let many: Vec<String> = (0..100).map(|i| format!("hint{i}")).collect();
    assert!(clean_hints(&many).len() <= MAX_HINTS);
}

#[test]
fn the_wordlist_covers_the_common_api_shapes() {
    // A guard against the list being emptied by accident.
    assert!(ENDPOINTS.contains(&"api/user/search"));
    assert!(ENDPOINTS.contains(&"api/health"));
    assert!(!ENDPOINTS.is_empty());
}
