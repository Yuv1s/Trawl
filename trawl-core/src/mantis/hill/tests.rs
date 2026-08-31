use super::*;

const PROSE: &[u8] = b"the treasure is buried under the old oak tree at the north end of the field";

fn stripped(data: &[u8]) -> Vec<u8> {
    prepare(data).iter().map(|&x| b'A' + x).collect()
}

#[test]
fn every_invertible_key_has_a_matching_inverse() {
    let pair = [3u8, 19];
    for (key, undo) in invertible_keys() {
        assert_eq!(apply(&apply(&pair, &key), &undo), pair, "{key:?}");
    }
}

#[test]
fn round_trips_under_a_sample_of_keys() {
    // Every fourth invertible key, which is enough to catch a broken inverse
    // without running all 211,000 of them twice per test.
    for (key, _) in invertible_keys().into_iter().step_by(4) {
        assert_eq!(decipher(&encipher(PROSE, &key), &key), stripped(PROSE), "{key:?}");
    }
}

#[test]
fn keeps_case_out_and_pads_an_odd_length() {
    let out = encipher(b"cat", &[3, 2, 5, 7]);
    assert_eq!(out.len(), 4); // "CAT" padded to "CATX" before pairing off
    assert!(out.iter().all(u8::is_ascii_uppercase));
}

#[test]
fn matches_a_worked_example() {
    // key = [3,2,5,7], det = 3*7 - 2*5 = 11, and 11's inverse mod 26 is 19, so
    // the key is invertible. "HI" (7, 8) enciphers to:
    //   c0 = 3*7 + 2*8 = 37 mod 26 = 11 -> L
    //   c1 = 5*7 + 7*8 = 91 mod 26 = 13 -> N
    let key = [3, 2, 5, 7];
    assert_eq!(encipher(b"HI", &key), b"LN".to_vec());
    assert_eq!(decipher(b"LN", &key), b"HI".to_vec());
}

#[test]
fn solves_a_hill_key() {
    let key: Key = [3, 2, 5, 7];
    let found = solve(&encipher(PROSE, &key)).expect("nothing came back");

    assert_eq!(found.key, key);
    assert_eq!(found.plaintext, stripped(PROSE));
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

/// `mantis::hill::tests::probe_bar` — run with `-- --nocapture --ignored` to
/// print the table `MIN_SCORE`'s doc comment cites.
#[test]
#[ignore]
fn probe_bar() {
    use crate::mantis::{affine, substitution};

    let message: &[u8] = b"the museum keeps its oldest maps in a locked room beneath the reading hall where the air is kept dry and the light is kept low visitors are welcome on the first thursday of every month";
    let key = [3, 2, 5, 7];
    let sub_key = [
        7u8, 22, 4, 19, 0, 25, 11, 14, 8, 23, 17, 3, 20, 9, 15, 5, 24, 1, 12, 18, 6, 21, 16, 2, 13,
        10,
    ];

    let plain_score = solve(message).map_or(0.0, |c| c.score);
    let hill_score = solve(&encipher(message, &key)).map_or(0.0, |c| c.score);
    let affine_score = solve(&affine::encipher(message, 7, 11)).map_or(0.0, |c| c.score);
    let subst_score = solve(&substitution::encipher(message, &sub_key)).map_or(0.0, |c| c.score);

    println!(
        "plain {plain_score:.3}  hill {hill_score:.3}  affine {affine_score:.3}  substitution {subst_score:.3}"
    );
}
