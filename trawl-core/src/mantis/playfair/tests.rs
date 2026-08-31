use super::*;
use crate::mantis::ngram;

/// Long enough to be a real message, used only by the landscape measurement:
/// there is no solver here for it to feed.
const PROSE: &[u8] =
    b"the museum keeps its oldest maps in a locked room beneath the reading hall, \
where the air is kept dry and the light is kept low. visitors are welcome on the first thursday of \
every month, though the archivist asks that nobody bring a pen. the quiet is the point, she says, \
because a map only gives up its detail to somebody willing to sit with it for an hour.";

const MONARCHY: &[u8; 25] = b"MONARCHYBDEFGIKLPQSTUVWXZ";

#[test]
fn builds_the_textbook_monarchy_square() {
    assert_eq!(letters_to_bytes(&grid_from_keyword(b"MONARCHY")), MONARCHY);
}

#[test]
fn rectangle_rule_matches_a_hand_worked_pair() {
    // MONARCHY square, rows CHYBD (row 1) and EFGIK (row 2). H sits at
    // (1,1), I at (2,3): different row and column, so each keeps its own row
    // and takes the other's column. H -> (1,3) = B. I -> (2,1) = F.
    let grid = grid_from_keyword(b"MONARCHY");
    assert_eq!(encipher(b"HI", &grid), b"BF".to_vec());
    assert_eq!(decipher(b"BF", &grid), b"HI".to_vec());
}

#[test]
fn same_row_rule_matches_a_hand_worked_pair() {
    // Row 0 is MONAR. M(0,0) and O(0,1) share a row, so encipher shifts each
    // one column right, wrapping: M -> O, O -> N.
    let grid = grid_from_keyword(b"MONARCHY");
    assert_eq!(encipher(b"MO", &grid), b"ON".to_vec());
    assert_eq!(decipher(b"ON", &grid), b"MO".to_vec());
}

#[test]
fn same_column_rule_matches_a_hand_worked_pair() {
    // Column 0 is MCELU. M(0,0) and C(1,0) share a column, so encipher shifts
    // each one row down, wrapping: M -> C, C -> E.
    let grid = grid_from_keyword(b"MONARCHY");
    assert_eq!(encipher(b"MC", &grid), b"CE".to_vec());
    assert_eq!(decipher(b"CE", &grid), b"MC".to_vec());
}

#[test]
fn inserts_a_filler_between_a_repeated_letter() {
    // The textbook case: BALLOON's doubled L falls in the middle of a pair,
    // so an X splits it, and the doubled O afterwards does not repeat because
    // the split already moved one L across the boundary.
    assert_eq!(letters_to_bytes(&prepare_plain(b"BALLOON")), b"BALXLOON");
}

#[test]
fn pads_an_odd_letter_with_x_or_q_if_the_letter_is_x() {
    assert_eq!(letters_to_bytes(&prepare_plain(b"CAT")), b"CATX");
    assert_eq!(letters_to_bytes(&prepare_plain(b"BOX")), b"BOXQ");
}

#[test]
fn folds_j_onto_i() {
    let grid = grid_from_keyword(b"MONARCHY");
    assert_eq!(encipher(b"JI", &grid), encipher(b"II", &grid));
}

#[test]
fn round_trips_prose_under_a_keyword() {
    let grid = grid_from_keyword(b"a shuffled looking keyword");
    let cipher = encipher(PROSE, &grid);
    let plain = decipher(&cipher, &grid);

    // Round-tripping does not reproduce PROSE exactly: preparing it folds J
    // onto I, drops spaces and punctuation, uppercases, and splits repeated
    // letters with a filler. What comes back should be that same reading of
    // PROSE, not PROSE itself.
    assert_eq!(plain, letters_to_bytes(&prepare_plain(PROSE)));
}

#[test]
fn a_wrong_keyword_does_not_recover_the_text() {
    let right = grid_from_keyword(b"MONARCHY");
    let wrong = grid_from_keyword(b"DIFFERENT");

    let cipher = encipher(PROSE, &right);
    assert_ne!(decipher(&cipher, &wrong), letters_to_bytes(&prepare_plain(PROSE)));
}

/// The measurement the module doc cites for why there is no ciphertext-only
/// solver: run with `-- --ignored --nocapture` to print it again.
///
/// xorshift64*, the same generator [`super::substitution`] climbs with,
/// walking a fixed number of swaps away from the grid that made `PROSE`'s
/// ciphertext, so the distances are reproducible rather than however a
/// shuffle happened to land.
#[test]
#[ignore]
fn measures_the_landscape() {
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545f4914f6cdd1d)
        }
    }

    fn score(cipher: &[u8], grid: &Grid) -> f32 {
        let pos = positions(grid);
        let plaintext: Vec<u8> = cipher
            .as_chunks::<2>()
            .0
            .iter()
            .flat_map(|&[a, b]| {
                let (a, b) = shift_pair(grid, &pos, a, b, true);
                [ALPHABET[a as usize], ALPHABET[b as usize]]
            })
            .collect();
        ngram::fitness(&plaintext)
    }

    let key = grid_from_keyword(b"SECRET KEYWORD");
    let cipher = prepare_cipher(&encipher(PROSE, &key));
    let mut rng = Rng(0x9e3779b97f4a7c15);

    for swaps in [0usize, 1, 2, 3, 5, 8, 12, 20] {
        let mut near = key;
        for _ in 0..swaps {
            let a = (rng.next() % 25) as usize;
            let b = (rng.next() % 25) as usize;
            near.swap(a, b);
        }
        println!("{swaps} swaps from the key: {:.3}", score(&cipher, &near));
    }
}
