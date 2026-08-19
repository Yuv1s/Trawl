//! Affine: multiply, then shift.
//!
//! Each letter becomes `a * x + b` reduced modulo 26. Caesar is the case where
//! `a` is one, and the multiply is what stops the answer falling out of a single
//! guess at the commonest letter, because it scatters the alphabet rather than
//! sliding it.
//!
//! Not by much, though. `a` has to be coprime with 26 or the cipher is not
//! reversible, which leaves twelve of them, and `b` has 26 values. That is 312
//! keys, so this is brute force and no cleverness: try all of them, keep the one
//! that reads.

use super::{ngram, plainness};

/// Multipliers coprime with 26, which are the only ones that can be undone.
///
/// Anything sharing a factor with 26 folds two letters onto one, and no key
/// unfolds them.
const MULTIPLIERS: [u8; 12] = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];

/// The multiplier that undoes `a`, found by trying all 26 rather than by
/// running the extended Euclidean algorithm for one small number.
fn inverse(a: u8) -> u8 {
    (1..26u8)
        .find(|&x| (a as u16 * x as u16) % 26 == 1)
        .unwrap()
}

pub fn encipher(data: &[u8], a: u8, b: u8) -> Vec<u8> {
    map(data, |x| (a as u16 * x as u16 + b as u16) % 26)
}

pub fn decipher(data: &[u8], a: u8, b: u8) -> Vec<u8> {
    let undo = inverse(a) as u16;
    map(data, |x| (undo * (x as u16 + 26 - b as u16)) % 26)
}

/// Applies a letter map, keeping case and leaving everything else alone.
fn map(data: &[u8], f: impl Fn(u8) -> u16) -> Vec<u8> {
    data.iter()
        .map(|&byte| {
            if !byte.is_ascii_alphabetic() {
                return byte;
            }

            let out = b'a' + f(byte.to_ascii_lowercase() - b'a') as u8;
            if byte.is_ascii_uppercase() {
                out.to_ascii_uppercase()
            } else {
                out
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub a: u8,
    pub b: u8,
    pub plaintext: Vec<u8>,
    pub score: f32,
}

/// How readable the result has to be before it is reported.
///
/// Measured rather than chosen. `mantis::tests::probe_bars` runs every solver
/// over every cipher with the bars taken off. This one reads a real affine at
/// 0.816 and never gets past 0.315 on anything else:
///
/// ```text
///          input    affine   transposition   substitution
///          plain         -            -             0.916
///     rail fence         -         0.816            0.507
///       columnar         -         0.816            0.491
///         affine     0.816         0.343            0.904
///   substitution     0.315         0.328            0.916
///          noise     0.229         0.231              -
/// ```
const MIN_SCORE: f32 = 0.7;

/// Shortest text worth attempting.
const MIN_LETTERS: usize = 20;

/// How much more readable a decryption has to be than the text it came from.
///
/// Enciphering leaves the letter mix alone up to a relabelling, so text that was
/// never affine still has 312 chances to score respectably. Making each one beat
/// its own input is what keeps this from answering a question nobody asked.
const MIN_GAIN: f32 = 0.1;

/// Tries all 312 keys and reports the best reading.
///
/// The identity is skipped. `a = 1, b = 0` changes nothing, so "solving" to it
/// would be reporting the input back as though it were a result.
pub fn solve(data: &[u8]) -> Option<Candidate> {
    if ngram::letters(data).len() < MIN_LETTERS {
        return None;
    }

    let before = plainness(data);

    MULTIPLIERS
        .iter()
        .flat_map(|&a| (0..26u8).map(move |b| (a, b)))
        .filter(|&(a, b)| (a, b) != (1, 0))
        .map(|(a, b)| {
            let plaintext = decipher(data, a, b);
            let score = plainness(&plaintext);
            Candidate {
                a,
                b,
                plaintext,
                score,
            }
        })
        .filter(|found| found.score >= MIN_SCORE && found.score >= before + MIN_GAIN)
        .fold(None::<Candidate>, |best, next| match best {
            Some(current) if current.score >= next.score => Some(current),
            _ => Some(next),
        })
}

#[cfg(test)]
mod tests;
