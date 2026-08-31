use super::*;

const PROSE: &[u8] = b"the treasure is buried under the old oak tree at the north end of the field";

fn best(found: &[Candidate]) -> String {
    String::from_utf8_lossy(&found[0].plaintext).into_owned()
}

#[test]
fn recovers_a_single_byte_key() {
    let found = single_byte(&apply(PROSE, &[0x42]), &[]);

    assert!(!found.is_empty(), "nothing came back");
    assert_eq!(found[0].key, vec![0x42]);
    assert_eq!(best(&found), String::from_utf8_lossy(PROSE));
}

#[test]
fn recovers_every_single_byte_key_there_is() {
    // One awkward key is an accident; sweeping the range is the test.
    let mut missed = Vec::new();

    for key in 1..=255u8 {
        let found = single_byte(&apply(PROSE, &[key]), &[]);
        if found.first().map(|c| c.plaintext.as_slice()) != Some(PROSE) {
            missed.push(key);
        }
    }

    assert!(missed.is_empty(), "failed on keys {missed:?}");
}

#[test]
fn works_out_how_long_a_repeating_key_is() {
    let key = b"SECRET";
    let long = PROSE.repeat(3);
    let lengths = key_lengths(&apply(&long, key), 32);

    assert!(
        lengths[..3].contains(&key.len()),
        "expected 6 near the front, got {:?}",
        &lengths[..6]
    );
}

#[test]
fn recovers_a_repeating_key() {
    let long = PROSE.repeat(3);
    let found = repeating(&apply(&long, b"SECRET"), &[]).expect("nothing came back");

    assert_eq!(found.key, b"SECRET".to_vec());
    assert_eq!(found.plaintext, long);
}

#[test]
fn recovers_a_repeating_key_of_an_awkward_length() {
    for key in [b"ab".as_slice(), b"key".as_slice(), b"longerkey".as_slice()] {
        let long = PROSE.repeat(4);
        let found = repeating(&apply(&long, key), &[])
            .unwrap_or_else(|| panic!("nothing back for key {:?}", String::from_utf8_lossy(key)));

        assert_eq!(
            found.plaintext,
            long,
            "wrong plaintext for key {:?}",
            String::from_utf8_lossy(key)
        );
    }
}

#[test]
fn finds_a_flag_even_when_it_reads_like_nothing() {
    // Braces and underscores score badly as English, so a flag has to override
    // the readability bar rather than be filtered out by it.
    let flag = b"flag{x0r_k3y_r3c0v3r3d}";
    let found = single_byte(&apply(flag, &[0x1f]), &[]);

    assert!(!found.is_empty(), "the flag was scored away");
    assert_eq!(found[0].plaintext, flag.to_vec());
    assert_eq!(found[0].flags, vec!["flag{x0r_k3y_r3c0v3r3d}"]);
}

#[test]
fn reports_nothing_on_random_bytes() {
    // The control that matters. XOR always produces output, so a tool with no
    // bar on it will invent an answer for anything at all.
    let mut state = 0x2545f491u32;
    let noise: Vec<u8> = (0..400)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 16) as u8
        })
        .collect();

    let found = recover(&noise, &[]);
    assert!(
        !found.found(),
        "invented {:?} out of noise",
        found
            .single
            .first()
            .map(
                |c| String::from_utf8_lossy(&c.plaintext[..40.min(c.plaintext.len())]).into_owned()
            )
    );
}

#[test]
fn reports_nothing_on_a_compressed_looking_blob() {
    // High entropy with structure, which is what an encrypted payload looks
    // like. Nothing here is XOR of English.
    let blob: Vec<u8> = (0..300u32)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 13) as u8)
        .collect();

    assert!(!recover(&blob, &[]).found());
}

#[test]
fn leaves_plain_english_alone() {
    // Already readable, so the identity key is the only one that would "work",
    // and reporting it as a discovery would be noise.
    let found = single_byte(PROSE, &[]);
    assert!(
        found.iter().all(|c| c.plaintext != PROSE),
        "claimed to have decrypted text that was never encrypted"
    );
}

#[test]
fn declines_a_run_too_short_to_judge() {
    assert!(repeating(b"short", &[]).is_none());
    assert!(!recover(b"hi", &[]).found());
}

#[test]
fn xor_undoes_itself() {
    let once = apply(PROSE, b"key");
    assert_ne!(once, PROSE);
    assert_eq!(apply(&once, b"key"), PROSE);
}

#[test]
fn an_empty_key_changes_nothing() {
    assert_eq!(apply(PROSE, b""), PROSE);
}

#[test]
fn prints_a_readable_key_as_text_and_a_binary_one_as_hex() {
    let text = Candidate {
        key: b"SECRET".to_vec(),
        plaintext: Vec::new(),
        score: 0.0,
        flags: Vec::new(),
        convincing: false,
    };
    assert_eq!(text.key_text(), "\"SECRET\"");

    let binary = Candidate {
        key: vec![0x00, 0xff],
        plaintext: Vec::new(),
        score: 0.0,
        flags: Vec::new(),
        convincing: false,
    };
    assert_eq!(binary.key_text(), "00 ff");
}

#[test]
fn counts_differing_bits() {
    assert_eq!(hamming(b"this is a test", b"wokka wokka!!!"), 37);
    assert_eq!(hamming(b"aaa", b"aaa"), 0);
}

#[test]
fn reports_the_shortest_key_rather_than_a_multiple_of_it() {
    // Any multiple of the real key decrypts perfectly, so the length search
    // often lands on one. "KEYKEY" is not wrong, but it is not the answer.
    let long = PROSE.repeat(4);
    let found = repeating(&apply(&long, b"KEY"), &[]).expect("nothing came back");

    assert_eq!(found.key, b"KEY".to_vec());
    assert_eq!(found.plaintext, long);
}

#[test]
fn reduces_a_repeated_key_to_its_period() {
    assert_eq!(shortest_period(b"KEYKEY"), b"KEY".to_vec());
    assert_eq!(shortest_period(b"aaaa"), b"a".to_vec());
    assert_eq!(shortest_period(b"KEY"), b"KEY".to_vec());
    assert_eq!(shortest_period(b"abcabd"), b"abcabd".to_vec());
}
