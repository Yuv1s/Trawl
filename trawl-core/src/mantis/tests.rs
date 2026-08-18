use super::*;

fn peeled(input: &str) -> Peel {
    peel(input.as_bytes())
}

fn text(peel: &Peel) -> String {
    String::from_utf8_lossy(&peel.result).into_owned()
}

fn names(peel: &Peel) -> Vec<&str> {
    peel.steps.iter().map(|s| s.encoding).collect()
}

#[test]
fn scores_prose_above_an_encoded_blob() {
    let prose = plainness(b"the quick brown fox jumps over the lazy dog");
    let blob = plainness(b"dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==");

    assert!(prose > blob, "prose {prose} should beat base64 {blob}");
    assert!(prose > 0.5, "prose scored only {prose}");
}

#[test]
fn scores_binary_noise_lowest() {
    let noise: Vec<u8> = (0..200u32).map(|i| (i.wrapping_mul(7919) % 256) as u8).collect();
    assert!(plainness(&noise) < 0.35, "noise scored {}", plainness(&noise));
}

#[test]
fn peels_a_single_layer() {
    let found = peeled("dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==");

    assert_eq!(names(&found), vec!["base64"]);
    assert_eq!(text(&found), "the quick brown fox jumps over the lazy dog");
}

#[test]
fn peels_a_chain_all_the_way_down() {
    // base64 of hex of the message, which is the shape of a real challenge.
    let message = "meet me at the docks at midnight";
    let as_hex: String = message.bytes().map(|b| format!("{b:02x}")).collect();

    let mut encoded = String::new();
    let raw = as_hex.as_bytes();
    for chunk in raw.chunks(3) {
        let mut buffer = [0u8; 3];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let n = u32::from_be_bytes([0, buffer[0], buffer[1], buffer[2]]);
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for i in 0..4 {
            if i <= chunk.len() {
                encoded.push(alphabet[((n >> (18 - i * 6)) & 63) as usize] as char);
            } else {
                encoded.push('=');
            }
        }
    }

    let found = peeled(&encoded);
    assert_eq!(text(&found), message);
    assert_eq!(names(&found), vec!["base64", "hex"]);
}

#[test]
fn stops_when_it_reaches_the_answer() {
    let found = peeled("dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==");

    // The answer is valid input to several codecs. Peeling past it would take a
    // readable sentence and return noise.
    assert_eq!(found.steps.len(), 1);
    assert!(found.score > 0.5);
}

#[test]
fn leaves_plain_english_completely_alone() {
    for prose in [
        "the quick brown fox jumps over the lazy dog",
        "meet me at the docks at midnight and bring the money",
        "this is an ordinary sentence with nothing hidden in it at all"
    ] {
        let found = peeled(prose);
        assert!(
            found.steps.is_empty(),
            "peeled {:?} into {:?} via {:?}",
            prose,
            text(&found),
            names(&found)
        );
        assert_eq!(text(&found), prose);
    }
}

#[test]
fn leaves_random_noise_alone() {
    // Nothing here decodes to anything readable, so nothing should be claimed.
    let mut state = 0x2545f491u32;
    let noise: String = (0..80)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            char::from(b'a' + (state % 26) as u8)
        })
        .collect();

    let found = peeled(&noise);
    assert!(
        found.steps.is_empty(),
        "invented {:?} out of noise",
        names(&found)
    );
}

#[test]
fn takes_a_flag_as_the_end_of_the_road() {
    let flag = "flag{peeled_all_the_way}";
    let encoded: String = flag.bytes().map(|b| format!("{b:02x}")).collect();

    let found = peeled(&encoded);
    assert_eq!(text(&found), flag);
    assert!(found.steps.last().unwrap().reason.contains("flag shape"));
}

#[test]
fn accepts_a_flag_even_when_it_reads_like_nothing() {
    // Underscores and braces score badly as English. Letting frequency veto a
    // flag would be absurd, so a flag shape overrides the score.
    let flag = "flag{x_y_z_q_j_k}";
    let encoded: String = flag.bytes().map(|b| format!("{b:02x}")).collect();

    assert_eq!(text(&peeled(&encoded)), flag);
}

#[test]
fn recognises_a_file_that_falls_out_of_a_decode() {
    // base64 of a PNG header, which is how a whole file arrives pasted in chat.
    let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut encoded = String::new();
    for chunk in png.chunks(3) {
        let mut buffer = [0u8; 3];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let n = u32::from_be_bytes([0, buffer[0], buffer[1], buffer[2]]);
        for i in 0..4 {
            if i <= chunk.len() {
                encoded.push(alphabet[((n >> (18 - i * 6)) & 63) as usize] as char);
            } else {
                encoded.push('=');
            }
        }
    }

    let found = peeled(&encoded);
    assert!(found.result.starts_with(b"\x89PNG"));
    assert!(found.steps.last().unwrap().reason.contains("PNG"));
}

#[test]
fn solves_a_rotation_without_being_told_the_shift() {
    // Caesar by another name. Every shift decodes, so only the result can say
    // which one was meant.
    let shifted = encodings::rot_n(b"attack at dawn from the north side", 7);
    let found = peel(&shifted);

    assert_eq!(text(&found), "attack at dawn from the north side");
}

#[test]
fn peels_morse() {
    let found = peeled(".... . .-.. .-.. --- / - .... . .-. .");
    assert_eq!(text(&found), "HELLO THERE");
}

#[test]
fn peels_binary_text() {
    let message = "attack at dawn";
    let encoded: String = message
        .bytes()
        .map(|b| format!("{b:08b}"))
        .collect::<Vec<_>>()
        .join(" ");

    assert_eq!(text(&peeled(&encoded)), message);
}

#[test]
fn never_runs_away_on_a_rotation_that_undoes_itself() {
    // ROT13 twice is the identity, so a peeler that does not track where it has
    // been will bounce between two states until it hits the depth limit.
    let found = peeled("Gur dhvpx oebja sbk whzcf bire gur ynml qbt");

    assert_eq!(text(&found), "The quick brown fox jumps over the lazy dog");
    assert!(found.steps.len() <= 2, "took {} steps", found.steps.len());
}

#[test]
fn stops_at_the_depth_limit_rather_than_forever() {
    // Deeply nested, so the guard is what ends it rather than success.
    // Six rounds, not twenty: hex doubles the length each time, so twenty would
    // build a fourteen-megabyte string and the test would be measuring that
    // rather than the guard.
    let mut encoded = "attack at dawn".to_string();
    for _ in 0..6 {
        encoded = encoded.bytes().map(|b| format!("{b:02x}")).collect();
    }

    let found = peeled(&encoded);
    assert!(found.steps.len() <= 8, "ran {} deep", found.steps.len());
}

#[test]
fn reports_an_empty_input_without_falling_over() {
    let found = peel(b"");
    assert!(found.steps.is_empty());
    assert_eq!(found.score, 0.0);
}

#[test]
fn json_is_shaped_for_the_worker() {
    let out = json(b"dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==");

    assert!(out.contains("\"depth\":1"), "{out}");
    assert!(out.contains("\"encoding\":\"base64\""), "{out}");
    assert!(out.contains("the quick brown fox"), "{out}");
}

#[test]
fn json_reports_a_string_it_could_not_peel() {
    let out = json(b"the quick brown fox jumps over the lazy dog");
    assert!(out.contains("\"depth\":0"), "{out}");
    assert!(out.contains("\"steps\":[]"), "{out}");
}

#[test]
fn attacks_the_cipher_hiding_under_an_encoding() {
    // Hex around XOR, which is how these are actually built: the cipher output
    // is unreadable bytes, so it gets wrapped to survive being pasted.
    let message = b"the treasure is buried under the old oak tree at the north end";
    let encrypted = xor::apply(message, b"KEY");
    let wrapped: String = encrypted.iter().map(|b| format!("{b:02x}")).collect();

    let reading = read(wrapped.as_bytes());

    assert_eq!(
        reading.peel.steps.iter().map(|s| s.encoding).collect::<Vec<_>>(),
        vec!["hex"],
        "the wrapper should come off first"
    );

    let found = reading.xor.repeating.expect("the cipher underneath was missed");
    assert_eq!(found.key, b"KEY".to_vec());
    assert_eq!(found.plaintext, message.to_vec());
}

#[test]
fn does_not_attack_something_the_peel_already_solved() {
    // The answer is in hand, so running a cipher attack over it would only
    // produce noise with a confident label on it.
    let reading = read(b"dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==");

    assert_eq!(reading.peel.result, b"the quick brown fox jumps over the lazy dog");
    assert!(!reading.xor.found());
}

#[test]
fn finds_a_single_byte_key_in_a_pasted_string() {
    let flag = b"flag{xor_is_not_encryption}";
    let encrypted = xor::apply(flag, &[0x5a]);
    let wrapped: String = encrypted.iter().map(|b| format!("{b:02x}")).collect();

    let reading = read(wrapped.as_bytes());
    let found = &reading.xor.single;

    assert!(!found.is_empty(), "nothing came back");
    assert_eq!(found[0].plaintext, flag.to_vec());
    assert_eq!(found[0].key, vec![0x5a]);
}

#[test]
fn stays_quiet_on_a_string_with_nothing_in_it() {
    let reading = read(b"this is an ordinary sentence with nothing hidden in it");
    assert!(reading.peel.steps.is_empty());
    assert!(!reading.xor.found());
}

#[test]
fn json_carries_the_cipher_alongside_the_chain() {
    let encrypted = xor::apply(b"meet me at the docks at midnight tonight", &[0x33]);
    let wrapped: String = encrypted.iter().map(|b| format!("{b:02x}")).collect();

    let out = json(wrapped.as_bytes());
    assert!(out.contains("\"encoding\":\"hex\""), "{out}");
    assert!(out.contains("\"kind\":\"single byte\""), "{out}");
    assert!(out.contains("meet me at the docks"), "{out}");
}
