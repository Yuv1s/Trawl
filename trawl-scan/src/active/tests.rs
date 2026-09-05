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

#[test]
fn carries_a_cookie_a_response_set() {
    let headers = vec![(
        "set-cookie".to_string(),
        "session=abc123def456; Path=/; HttpOnly; SameSite=Lax".to_string(),
    )];
    let found = carriables(&headers, b"");

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].header, "Cookie");
    // The name=value only, without the attributes that follow it.
    assert_eq!(found[0].value, "session=abc123def456");
}

#[test]
fn carries_a_token_from_a_body_as_bearer_and_as_a_cookie() {
    // A site accepts a token one place where another expects the other, so a
    // token it names is tried both ways.
    let body = br#"{"ok":true,"access_token":"9f8e7d6c5b4a3021"}"#;
    let found = carriables(&[], body);

    assert!(
        found
            .iter()
            .any(|c| c.header == "Authorization" && c.value == "Bearer 9f8e7d6c5b4a3021")
    );
    assert!(
        found
            .iter()
            .any(|c| c.header == "Cookie" && c.value == "session=9f8e7d6c5b4a3021")
    );
}

#[test]
fn leaves_a_jwt_to_the_forging_pass() {
    // A JWT has its own pass that recovers the key and forges a fresh token,
    // which reaches further than replaying the one the site sent, so it is not
    // carried verbatim here.
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123signaturehere";
    let body = format!(r#"{{"token":"{jwt}"}}"#);
    let found = carriables(&[], body.as_bytes());

    assert!(
        found.is_empty(),
        "a JWT belongs to forge_and_replay, not the carry pass"
    );
}

#[test]
fn does_not_carry_a_short_or_wordy_value() {
    // A field under a token key that reads like a placeholder, or is too short
    // to be a real secret, is not a credential worth replaying.
    assert!(carriables(&[], br#"{"token":"none"}"#).is_empty());
    assert!(carriables(&[], br#"{"session":"pending"}"#).is_empty());
    assert!(carriables(&[], br#"{"auth":"false"}"#).is_empty());
}

#[test]
fn does_not_carry_a_value_under_an_ordinary_key() {
    // Only the keys a site issues a credential under are carried; an id or a
    // name is not, and carrying everything would be a second wordlist of noise.
    let body = br#"{"id":"1337abcd","username":"administrator"}"#;
    assert!(carriables(&[], body).is_empty());
}

#[test]
fn caps_how_many_values_it_carries() {
    // A page that sets a great many cookies cannot make the flow pass spend its
    // whole budget on one endpoint's worth of replays.
    let headers: Vec<(String, String)> = (0..40)
        .map(|i| ("set-cookie".to_string(), format!("c{i}=value{i}0000")))
        .collect();
    assert!(carriables(&headers, b"").len() <= MAX_CARRIABLES);
}

#[test]
fn reads_a_token_out_of_a_body_whitespace_and_all() {
    // A byte scan rather than a parse, so the spaces a formatter leaves around
    // a colon do not hide the value.
    let body = br#"{ "session" :  "aabbccddeeff0011" }"#;
    let found = carriables(&[], body);
    assert!(found.iter().any(|c| c.value.contains("aabbccddeeff0011")));
}
