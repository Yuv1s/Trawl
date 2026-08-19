use super::*;

const PROSE: &[u8] = b"the treasure is buried under the old oak tree at the north end of the field";

#[test]
fn every_multiplier_has_an_inverse() {
    for a in MULTIPLIERS {
        assert_eq!((a as u16 * inverse(a) as u16) % 26, 1, "a = {a}");
    }
}

#[test]
fn round_trips_under_every_key() {
    for a in MULTIPLIERS {
        for b in 0..26 {
            assert_eq!(decipher(&encipher(PROSE, a, b), a, b), PROSE, "{a}x + {b}");
        }
    }
}

#[test]
fn keeps_case_and_punctuation() {
    let out = encipher(b"Attack At Dawn!", 5, 8);

    assert_eq!(out[6], b' ');
    assert_eq!(out[14], b'!');
    assert!(out[0].is_ascii_uppercase());
    assert!(out[1].is_ascii_lowercase());
    assert!(out[10].is_ascii_uppercase());
}

#[test]
fn matches_a_worked_example() {
    // 5x + 8 is the textbook affine key. AFFINECIPHER encodes to IHHWVCSWFRCP.
    assert_eq!(encipher(b"AFFINECIPHER", 5, 8), b"IHHWVCSWFRCP".to_vec());
    assert_eq!(decipher(b"IHHWVCSWFRCP", 5, 8), b"AFFINECIPHER".to_vec());
}

#[test]
fn solves_a_multiplied_key() {
    let found = solve(&encipher(PROSE, 7, 11)).expect("nothing came back");

    assert_eq!((found.a, found.b), (7, 11));
    assert_eq!(found.plaintext, PROSE);
}

#[test]
fn solves_the_shift_only_case() {
    // a = 1 is Caesar. Affine covers it, and should say so rather than skipping
    // a key it can genuinely read.
    let found = solve(&encipher(PROSE, 1, 13)).expect("nothing came back");

    assert_eq!((found.a, found.b), (1, 13));
    assert_eq!(found.plaintext, PROSE);
}

#[test]
fn declines_text_that_was_never_enciphered() {
    let mut state = 0x9e3779b97f4a7c15u64;
    let noise: Vec<u8> = (0..200)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            b'a' + (state.wrapping_mul(0x2545f4914f6cdd1d) % 26) as u8
        })
        .collect();

    assert_eq!(solve(&noise), None);
}

#[test]
fn declines_text_too_short_to_judge() {
    assert_eq!(solve(b"short"), None);
    assert_eq!(solve(b""), None);
}
