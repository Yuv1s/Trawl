//! Playfair: letters in pairs, moved around a 5x5 square rather than
//! substituted one at a time.
//!
//! The key is the square itself: I and J share a cell, so the other 25
//! letters fill the grid, ordered by a keyword and then by what is left of
//! the alphabet. A pair of plaintext letters becomes a pair of grid
//! positions, and each pair is carried to a new pair of positions by one of
//! three rules — same row, same column, or the corners of the rectangle they
//! sit at — which is what makes Playfair a digraph cipher rather than a
//! letter-for-letter one.
//!
//! There is no solver here that recovers a grid from ciphertext alone, and
//! that omission was measured rather than assumed. A digraph cipher has no
//! slope leading to the answer the way [`super::substitution`]'s does: moving
//! one letter of a substitution key closer to right still reads a little more
//! like English, because the rest of a trigram window is usually untouched by
//! it, but a single swap in a Playfair grid can send an unrelated digraph
//! somewhere else entirely. `tests::measures_the_landscape` decrypts a real
//! ciphertext under grids one, two and three swaps from the key that made it:
//! the trigram fitness goes 0.862, 0.457, 0.107, 0.000. Past two swaps there is
//! nothing to climb, anneal or breed towards, and getting within two swaps of
//! one specific arrangement out of 25! by any undirected search is not a
//! search a realistic budget wins. Published attacks on this cipher reach for
//! machinery well past a swap-and-score climb to get there, and this crate
//! does not reimplement one on the strength of a memory of how they work.
//!
//! What is offered instead is what [`super::keyed`] already offers for
//! Vigenère and Beaufort: hand over a keyword, from the challenge or a guess,
//! and this builds the grid and reads the text through it.

/// A-Z with J folded onto I, since Playfair's grid has no room for both.
const ALPHABET: &[u8; 25] = b"ABCDEFGHIKLMNOPQRSTUVWXYZ";

/// Ascii letter, A through Z, to its index into [`ALPHABET`]. J shares I's
/// slot, which is how the fold is applied: every lookup through this table
/// already treats the two as one letter.
const LETTER_TO_INDEX: [u8; 26] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
];

fn index_of(letter: u8) -> u8 {
    LETTER_TO_INDEX[(letter.to_ascii_uppercase() - b'A') as usize]
}

/// The key square: `grid[position]` is the letter (as an index into
/// [`ALPHABET`]) sitting at that position, row-major.
pub type Grid = [u8; 25];

/// Where each letter sits, the other direction from a [`Grid`]. Built once
/// per decipher or encipher call rather than searched for on every letter.
fn positions(grid: &Grid) -> [u8; 25] {
    let mut pos = [0u8; 25];
    for (at, &letter) in grid.iter().enumerate() {
        pos[letter as usize] = at as u8;
    }
    pos
}

/// Builds a key square from a keyword: its own letters first, deduplicated
/// and in the order they appear, then whatever the keyword left out.
pub fn grid_from_keyword(keyword: &[u8]) -> Grid {
    let mut seen = [false; 25];
    let mut grid = [0u8; 25];
    let mut filled = 0usize;

    let mut place = |letter: u8| {
        let index = index_of(letter) as usize;
        if !seen[index] {
            seen[index] = true;
            grid[filled] = index as u8;
            filled += 1;
        }
    };

    for &byte in keyword.iter().filter(|b| b.is_ascii_alphabetic()) {
        place(byte);
    }
    for letter in ALPHABET {
        place(*letter);
    }

    grid
}

/// One digraph carried from one pair of positions to another, in the
/// direction `decrypt` sets. Encrypting and decrypting are mirror images of
/// the same three rules, so one function answers both.
///
/// Same row: each letter is replaced by its neighbour, right to encipher and
/// left to decipher, wrapping at the edge. Same column: neighbour below to
/// encipher, above to decipher. Otherwise the two positions are corners of a
/// rectangle, and each letter takes the other corner in its own row — a rule
/// that undoes itself, so encipher and decipher agree here without needing a
/// direction at all.
fn shift_pair(grid: &Grid, pos: &[u8; 25], a: u8, b: u8, decrypt: bool) -> (u8, u8) {
    let step: i8 = if decrypt { -1 } else { 1 };
    let (ra, ca) = (pos[a as usize] / 5, pos[a as usize] % 5);
    let (rb, cb) = (pos[b as usize] / 5, pos[b as usize] % 5);

    let at = |row: u8, col: u8| grid[(row * 5 + col) as usize];

    if ra == rb {
        let ca = (ca as i8 + step).rem_euclid(5) as u8;
        let cb = (cb as i8 + step).rem_euclid(5) as u8;
        (at(ra, ca), at(rb, cb))
    } else if ca == cb {
        let ra = (ra as i8 + step).rem_euclid(5) as u8;
        let rb = (rb as i8 + step).rem_euclid(5) as u8;
        (at(ra, ca), at(rb, cb))
    } else {
        (at(ra, cb), at(rb, ca))
    }
}

/// Letters only, folded through [`LETTER_TO_INDEX`], padded with X to an even
/// length. What a decipher reads: real ciphertext, no filler logic needed
/// because that already happened on the way in.
fn prepare_cipher(data: &[u8]) -> Vec<u8> {
    let mut letters: Vec<u8> = data
        .iter()
        .filter(|b| b.is_ascii_alphabetic())
        .map(|&b| index_of(b))
        .collect();

    if letters.len() % 2 == 1 {
        letters.push(index_of(b'X'));
    }

    letters
}

/// Letters only, split into digraphs with a filler between any pair that
/// would otherwise repeat a letter, and a filler on the end if one letter is
/// left over. X is the filler, or Q when the letter itself is X.
fn prepare_plain(data: &[u8]) -> Vec<u8> {
    let raw: Vec<u8> = data
        .iter()
        .filter(|b| b.is_ascii_alphabetic())
        .map(|&b| index_of(b))
        .collect();

    let x = index_of(b'X');
    let q = index_of(b'Q');
    let filler_for = |letter: u8| if letter == x { q } else { x };

    let mut out = Vec::with_capacity(raw.len() + raw.len() / 2);
    let mut i = 0;
    while i < raw.len() {
        let a = raw[i];
        match raw.get(i + 1) {
            Some(&b) if b != a => {
                out.push(a);
                out.push(b);
                i += 2;
            }
            _ => {
                out.push(a);
                out.push(filler_for(a));
                i += 1;
            }
        }
    }
    out
}

fn letters_to_bytes(letters: &[u8]) -> Vec<u8> {
    letters.iter().map(|&i| ALPHABET[i as usize]).collect()
}

/// Enciphers under `grid`. Case, spaces and punctuation are stripped: a
/// digraph either side of a gap is not the digraph the grid was built to
/// move.
pub fn encipher(data: &[u8], grid: &Grid) -> Vec<u8> {
    let pos = positions(grid);
    let plain = prepare_plain(data);

    letters_to_bytes(
        &plain
            .as_chunks::<2>()
            .0
            .iter()
            .flat_map(|&[a, b]| {
                let (a, b) = shift_pair(grid, &pos, a, b, false);
                [a, b]
            })
            .collect::<Vec<u8>>(),
    )
}

/// Deciphers under `grid`.
pub fn decipher(data: &[u8], grid: &Grid) -> Vec<u8> {
    let pos = positions(grid);
    let cipher = prepare_cipher(data);

    letters_to_bytes(
        &cipher
            .as_chunks::<2>()
            .0
            .iter()
            .flat_map(|&[a, b]| {
                let (a, b) = shift_pair(grid, &pos, a, b, true);
                [a, b]
            })
            .collect::<Vec<u8>>(),
    )
}

#[cfg(test)]
mod tests;
