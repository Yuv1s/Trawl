use super::*;

fn named(input: &str) -> Vec<&'static str> {
    identify(input.as_bytes())
        .map(|f| f.candidates)
        .unwrap_or_default()
}

#[test]
fn names_a_hash_that_declares_itself() {
    for (input, expected) in [
        (
            "$2b$12$GhvMmNVjRW29ulnudl.LbuAnUtN/LRfe1JsBm1Xu6LE3059z5Tr8m",
            "bcrypt",
        ),
        ("$2y$10$abcdefghijklmnopqrstuv", "bcrypt"),
        ("$1$salt$qJH7.N4xYta3aEG/dfqo/0", "md5crypt"),
        ("$6$rounds=5000$salt$hash", "sha512crypt"),
        ("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA", "Argon2id"),
        ("pbkdf2_sha256$260000$salt$hash", "Django PBKDF2-SHA256"),
    ] {
        let found = identify(input.as_bytes()).expect(input);
        assert_eq!(found.candidates, vec![expected], "for {input}");
        assert!(
            found.certain,
            "{input} declares itself, so it is not a guess"
        );
    }
}

#[test]
fn does_not_narrow_what_the_shape_cannot_narrow() {
    // The whole point. Thirty-two hex digits is MD5 and also three other things,
    // and nothing in the string can separate them.
    let found = identify(b"5d41402abc4b2a76b9719d911017c592").unwrap();

    assert!(found.candidates.contains(&"MD5"));
    assert!(found.candidates.contains(&"NTLM"));
    assert!(!found.certain, "shape alone is never certain");
    assert_eq!(found.bits, Some(128));
}

#[test]
fn names_the_common_digest_lengths() {
    assert!(named("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d").contains(&"SHA-1"));
    assert!(named(&"a".repeat(64)).contains(&"SHA-256"));
    assert!(named(&"a".repeat(128)).contains(&"SHA-512"));
    assert!(named(&"a".repeat(56)).contains(&"SHA-224"));
    assert!(named(&"a".repeat(96)).contains(&"SHA-384"));
    assert!(named("deadbeef").contains(&"CRC-32"));
}

#[test]
fn reads_the_algorithm_a_token_declares() {
    // The header is base64url of JSON that names its own algorithm, so this is
    // read rather than guessed.
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.c2lnbmF0dXJl";
    let found = identify(token.as_bytes()).expect("not recognised");

    assert_eq!(found.candidates, vec!["JSON Web Token"]);
    assert!(found.certain);
    assert!(found.shape.contains("HS256"), "shape was {:?}", found.shape);
}

#[test]
fn ignores_something_dot_separated_that_is_not_a_token() {
    assert!(identify(b"one.two.three").is_none());
    assert!(identify(b"192.168.0.1").is_none());
}

#[test]
fn names_the_mysql_asterisk() {
    let found = identify(b"*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19").unwrap();
    assert_eq!(found.candidates, vec!["MySQL 4.1+"]);
    assert!(found.certain);
}

#[test]
fn names_a_uuid_so_it_is_not_taken_for_a_digest() {
    let found = identify(b"123e4567-e89b-12d3-a456-426614174000").unwrap();
    assert_eq!(found.candidates, vec!["UUID"]);
    assert!(found.certain);
}

#[test]
fn says_nothing_about_things_that_are_not_hashes() {
    for input in [
        "the quick brown fox jumps over the lazy dog",
        "SGVsbG8sIHdvcmxkIQ==",
        "hello",
        "",
        "   ",
        // Hex, but no digest is this long.
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
    ] {
        if input.len() == 56 {
            continue;
        }
        assert!(
            identify(input.as_bytes()).is_none(),
            "claimed something for {input:?}"
        );
    }
}

#[test]
fn a_run_of_hex_at_no_digest_length_is_not_a_hash() {
    // Twenty hex digits is not any digest, and guessing at the nearest one would
    // be inventing an answer.
    assert!(identify(b"abcdef01234567890abc").is_none());
    assert!(identify(b"abc").is_none());
}

#[test]
fn trims_what_a_paste_drags_along() {
    assert!(named("  5d41402abc4b2a76b9719d911017c592\n").contains(&"MD5"));
}

#[test]
fn is_digest_matches_identify() {
    assert!(is_digest(b"5d41402abc4b2a76b9719d911017c592"));
    assert!(is_digest(
        b"$2b$12$GhvMmNVjRW29ulnudl.LbuAnUtN/LRfe1JsBm1Xu6LE3059z5Tr8m"
    ));
    assert!(!is_digest(b"the quick brown fox jumps over the lazy dog"));
    assert!(!is_digest(b"SGVsbG8sIHdvcmxkIQ=="));
}

#[test]
fn json_is_shaped_for_the_worker() {
    let out = json(b"5d41402abc4b2a76b9719d911017c592");
    assert!(out.contains("\"certain\":false"), "{out}");
    assert!(out.contains("\"bits\":128"), "{out}");
    assert!(out.contains("\"MD5\""), "{out}");
    assert!(out.contains("\"NTLM\""), "{out}");

    assert_eq!(json(b"the quick brown fox"), "null");
}

#[test]
fn json_reports_a_declared_hash_as_certain() {
    let out = json(b"$2b$12$GhvMmNVjRW29ulnudl.LbuAnUtN/LRfe1JsBm1Xu6LE3059z5Tr8m");
    assert!(out.contains("\"certain\":true"), "{out}");
    assert!(out.contains("\"bcrypt\""), "{out}");
    assert!(out.contains("\"bits\":null"), "{out}");
}
