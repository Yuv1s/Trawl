//! Hill: a block of letters as a vector, multiplied by a matrix.
//!
//! Two letters become one column vector and the key is a 2x2 matrix, so
//! enciphering is `key * [p0, p1] mod 26` for every pair in the message.
//! Undoing it needs the matrix's inverse mod 26, which exists only when the
//! determinant shares no factor with 26 — the same condition affine's
//! multiplier answers to, one level up in size.
//!
//! The key space is every 2x2 matrix mod 26, roughly 457,000 of them before
//! the invertible ones are picked out, which brute force clears in the same
//! kind of budget affine's 312 keys does. A 3x3 key is 26⁹, about five
//! trillion, and nothing here reaches for it: this module reads a 2x2 Hill
//! cipher or it says nothing.
//!
//! A block cipher needs a block to work on, so spaces and punctuation are
//! stripped before enciphering rather than carried through the way affine and
//! substitution carry them. That also means the result is scored by trigram
//! fitness rather than plainness: plainness leans on word boundaries and a
//! stripped run of letters has none, whatever it says.

use super::ngram;

/// A 2x2 matrix mod 26, read left to right, top to bottom.
pub type Key = [u8; 4];

/// `a*d - b*c`, reduced into 0..26.
fn determinant(key: &Key) -> u8 {
    let [a, b, c, d] = key.map(|x| x as i32);
    (((a * d - b * c) % 26 + 26) % 26) as u8
}

/// The value that undoes `x` under multiplication mod 26, found by trying all
/// 26 rather than running the extended Euclidean algorithm for one number.
///
/// `None` when `x` shares a factor with 26, which is exactly when no inverse
/// exists.
fn inverse(x: u8) -> Option<u8> {
    (1..26u8).find(|&i| (x as u16 * i as u16) % 26 == 1)
}

/// The matrix that undoes `key`, or `None` when `key` cannot be inverted.
///
/// The textbook formula for a 2x2 inverse mod n: swap the diagonal, negate the
/// off-diagonal, and scale the lot by the determinant's own inverse.
fn invert(key: &Key) -> Option<Key> {
    let det_inv = inverse(determinant(key))? as i32;
    let [a, b, c, d] = key.map(|x| x as i32);

    let reduce = |x: i32| (((det_inv * x) % 26 + 26) % 26) as u8;
    Some([reduce(d), reduce(26 - b), reduce(26 - c), reduce(a)])
}

/// Letters only, folded to A-Z as 0-25, padded with X to an even length so
/// every pair is complete.
fn prepare(data: &[u8]) -> Vec<u8> {
    let mut letters: Vec<u8> = data
        .iter()
        .filter(|b| b.is_ascii_alphabetic())
        .map(|b| b.to_ascii_uppercase() - b'A')
        .collect();

    if letters.len() % 2 == 1 {
        letters.push(b'X' - b'A');
    }

    letters
}

/// Every letter pair in `letters` carried through `key`, as 0-25 values.
fn apply(letters: &[u8], key: &Key) -> Vec<u8> {
    let [a, b, c, d] = key.map(|x| x as u16);

    letters
        .as_chunks::<2>()
        .0
        .iter()
        .flat_map(|&[p0, p1]| {
            let (p0, p1) = (p0 as u16, p1 as u16);
            [
                ((a * p0 + b * p1) % 26) as u8,
                ((c * p0 + d * p1) % 26) as u8,
            ]
        })
        .collect()
}

/// Enciphers letters-only plaintext under `key`. Case, spaces and punctuation
/// are not carried through: a block cipher needs whole blocks, and a gap in
/// one is not the gap the key was built for.
pub fn encipher(data: &[u8], key: &Key) -> Vec<u8> {
    apply(&prepare(data), key)
        .iter()
        .map(|&x| b'A' + x)
        .collect()
}

/// Deciphers under `key`. Hands the prepared letters back unread when `key`
/// has no inverse, which `solve` never passes it but a caller could.
pub fn decipher(data: &[u8], key: &Key) -> Vec<u8> {
    let letters = prepare(data);
    let Some(undo) = invert(key) else {
        return letters.iter().map(|&x| b'A' + x).collect();
    };
    apply(&letters, &undo).iter().map(|&x| b'A' + x).collect()
}

/// Every 2x2 matrix mod 26 with an inverse, paired with that inverse.
///
/// Computed once per solve rather than woven into the search, so the search
/// itself is a plain iteration with no per-key branching.
fn invertible_keys() -> Vec<(Key, Key)> {
    let mut keys = Vec::with_capacity(211_000);

    for a in 0..26u8 {
        for b in 0..26u8 {
            for c in 0..26u8 {
                for d in 0..26u8 {
                    let key = [a, b, c, d];
                    if let Some(undo) = invert(&key) {
                        keys.push((key, undo));
                    }
                }
            }
        }
    }

    keys
}

#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub key: Key,
    pub plaintext: Vec<u8>,
    pub score: f32,
}

/// How readable the result has to be before it is reported.
///
/// Measured against `ngram::fitness`, the same scale substitution answers to,
/// since both read a stripped run of letters. `tests::probe_bar` runs the
/// solver over a real Hill cipher and over plain, affine and substitution text
/// with the bar removed: a real one reads at 0.885 and nothing else clears the
/// solver's own `MIN_LETTERS` floor, since none of them holds together as a
/// 2x2 Hill cipher under any key.
const MIN_SCORE: f32 = 0.7;

/// Shortest text worth attempting.
///
/// Two more than affine's floor: a 2x2 key is four numbers rather than two,
/// and a short block gives fewer of them a chance to be wrong.
const MIN_LETTERS: usize = 24;

/// How much more readable a decryption has to be than the text it came from.
///
/// The identity key is one of the roughly 211,000 invertible ones tried, so
/// text that already read would otherwise solve to itself and be reported as
/// a break.
const MIN_GAIN: f32 = 0.1;

/// Letters of evidence a candidate key is judged on while searching.
///
/// `ngram::fitness`'s own confidence term saturates at 45 letters, past
/// which more text changes its opinion of a key only in the noise, so
/// scoring the other tens of thousands of a long paste on every one of the
/// roughly 211,000 keys tried would be spending real time for zero more
/// evidence. The winning key is re-scored against the whole message once
/// the search is over, which is what [`Candidate::score`] actually reports.
const SEARCH_SAMPLE: usize = 300;

/// Tries every invertible 2x2 key and reports the best reading.
pub fn solve(data: &[u8]) -> Option<Candidate> {
    let prepared = prepare(data);
    if ngram::letters(data).len() < MIN_LETTERS {
        return None;
    }

    let sample = &prepared[..prepared.len().min(SEARCH_SAMPLE)];
    let before = ngram::fitness(data);
    let identity: Key = [1, 0, 0, 1];

    let winner = invertible_keys()
        .into_iter()
        .filter(|(key, _)| key != &identity)
        .map(|(key, undo)| {
            let preview: Vec<u8> = apply(sample, &undo).iter().map(|&x| b'A' + x).collect();
            (key, undo, ngram::fitness(&preview))
        })
        .fold(None::<(Key, Key, f32)>, |best, next| match best {
            Some(current) if current.2 >= next.2 => Some(current),
            _ => Some(next),
        })?;

    let (key, undo, _) = winner;
    let plaintext: Vec<u8> = apply(&prepared, &undo).iter().map(|&x| b'A' + x).collect();
    let score = ngram::fitness(&plaintext);

    (score >= MIN_SCORE && score >= before + MIN_GAIN).then_some(Candidate {
        key,
        plaintext,
        score,
    })
}

#[cfg(test)]
mod tests;
