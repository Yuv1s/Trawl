//! Ciphers applied under a key somebody already has.
//!
//! Everything else in Mantis recovers keys from the text. That works when there
//! is enough text to work from, and Vigenère needs about sixty letters before
//! its columns say anything: a five letter key across eleven letters gives two
//! letters per column, which is not evidence, it is a coin toss with extra
//! steps. Below that the honest answer is that it cannot be done, and no amount
//! of tuning changes it.
//!
//! What can be done is take a key from somewhere else. Two places:
//!
//! A person hands one over. They read it off the challenge, or guessed it, or
//! the puzzle told them. Nothing here needs to judge that key, because they are
//! vouching for it, so this applies it and shows the result whatever it looks
//! like. That matters most for short answers, where a correct decryption is a
//! token that no scorer can confirm.
//!
//! Or a wordlist supplies one. That is a dictionary attack, and unlike a handed
//! over key it does have to be judged, because a list long enough to be useful
//! is long enough to throw up something that reads by luck.

use super::{bytes, ngram, plainness, playfair, vigenere};

/// What one cipher made of the key.
#[derive(Debug, Clone, PartialEq)]
pub struct Attempt {
    pub cipher: &'static str,
    pub key: String,
    pub plaintext: Vec<u8>,
    pub score: f32,
    pub flags: Vec<String>,
    /// Keys for the layer underneath, when this one did not reach the bottom.
    ///
    /// Enciphering twice is one cipher with a longer key, so the two keys can
    /// never be recovered separately from the text alone. Given the first one
    /// though, the second is an ordinary problem again: apply what you have,
    /// and what comes out is a fresh ciphertext to work on. This is that.
    ///
    /// Empty when the result reads, because then there is no layer underneath.
    pub next: Vec<vigenere::Derived>,
}

/// Beaufort: the key minus the letter, rather than the letter plus the key.
///
/// Its own inverse, which is why it turns up in puzzles, and why a Vigenère
/// solver handed the right key still returns nonsense on it.
fn beaufort(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut at = 0usize;

    data.iter()
        .map(|&byte| {
            if !byte.is_ascii_alphabetic() {
                return byte;
            }

            let base = if byte.is_ascii_uppercase() {
                b'A'
            } else {
                b'a'
            };
            let k = key[at % key.len()].to_ascii_lowercase() - b'a';
            at += 1;

            base + (26 + k - (byte.to_ascii_lowercase() - b'a')) % 26
        })
        .collect()
}

fn letters_of(key: &str) -> Vec<u8> {
    key.bytes()
        .filter(|b| b.is_ascii_alphabetic())
        .map(|b| b.to_ascii_lowercase())
        .collect()
}

/// Where a result stops being another layer and starts being the answer.
const READS: f32 = 0.5;

/// How many keys to offer for the layer underneath.
///
/// A handful. Anyone who has got this far has a key in hand already and is
/// working down, not browsing.
const NEXT_KEYS: usize = 6;

fn judge(cipher: &'static str, key: &str, plaintext: Vec<u8>) -> Attempt {
    Attempt {
        cipher,
        key: key.to_string(),
        flags: bytes::flag_candidates(&plaintext)
            .into_iter()
            .map(|found| found.text)
            .collect(),
        score: plainness(&plaintext),
        plaintext,
        next: Vec::new(),
    }
}

/// Whether an attempt reached the bottom or merely took a layer off.
fn settled(attempt: &Attempt) -> bool {
    attempt.score >= READS || attempt.flags.iter().any(|f| bytes::tag_is_known(f))
}

/// Every cipher that takes a keyword, under the key given, judged by nobody.
///
/// Nothing is filtered and nothing is ranked away. The caller supplied the key,
/// so the caller decides whether the answer is right; refusing to show a result
/// because it does not read like English would defeat the entire point, which is
/// that the answer may well be a token.
pub fn with_key(data: &[u8], key: &str) -> Vec<Attempt> {
    with_key_for_tags(data, key, &[])
}

/// `with_key`, with the caller's configured flag tags steering the cribs that
/// recover what sits underneath each attempt.
pub fn with_key_for_tags(data: &[u8], key: &str, tags: &[String]) -> Vec<Attempt> {
    let mut out = attempts(data, key);

    // What is underneath, for the attempts that did not reach the bottom.
    //
    // Only here, and never in [`dictionary`], which calls [`attempts`] once per
    // word in its list: working out the next layer for each of forty-eight
    // guesses is hundreds of key recoveries to answer a question nobody asked.
    for attempt in &mut out {
        if !settled(attempt) {
            attempt.next = vigenere::derive(&attempt.plaintext, tags);
            attempt.next.truncate(NEXT_KEYS);
        }
    }

    out
}

/// The ciphers alone, without working out what might be underneath them.
fn attempts(data: &[u8], key: &str) -> Vec<Attempt> {
    let letters = letters_of(key);
    if letters.is_empty() || data.is_empty() {
        return Vec::new();
    }

    let mut out = vec![
        judge("Vigenère", key, vigenere::decipher(data, &letters)),
        judge("Beaufort", key, beaufort(data, &letters)),
        judge(
            "Vigenère, enciphering",
            key,
            vigenere::encipher(data, &letters),
        ),
        judge(
            "Playfair",
            key,
            playfair::decipher(data, &playfair::grid_from_keyword(key.as_bytes())),
        ),
    ];

    // The raw key as bytes, which is how a XOR key is usually written down.
    let raw = key.as_bytes();
    if !raw.is_empty() {
        out.push(judge("XOR", key, super::xor::apply(data, raw)));
    }

    // Flags first, and otherwise the order they were built in, which runs from
    // the cipher a keyword most often belongs to down to the least. Sorting the
    // rest by score would be sorting by noise: none of these was judged, and on
    // a short token the readability of a wrong answer and a right one differ by
    // less than nothing, so it would only shuffle the likely answer downwards.
    out.sort_by_key(|attempt| attempt.flags.is_empty());

    out
}

/// Keys worth trying when nobody supplied one.
///
/// A short list on purpose. This is a dictionary attack, and its whole risk is
/// that a long enough list eventually produces something that reads by accident;
/// keeping it to words a person actually reaches for when inventing a key means
/// a hit is worth something. It is not a claim about what any particular puzzle
/// uses, and a key outside this list is the ordinary case rather than a failure.
const WORDLIST: [&str; 48] = [
    "key",
    "secret",
    "password",
    "cipher",
    "crypto",
    "cryptography",
    "vigenere",
    "flag",
    "hidden",
    "message",
    "attack",
    "defend",
    "lemon",
    "alpha",
    "bravo",
    "charlie",
    "delta",
    "echo",
    "sigma",
    "omega",
    "gamma",
    "kappa",
    "python",
    "hacker",
    "security",
    "private",
    "public",
    "encrypt",
    "decrypt",
    "keyword",
    "puzzle",
    "riddle",
    "treasure",
    "shadow",
    "phantom",
    "cipherkey",
    "master",
    "unlock",
    "access",
    "admin",
    "root",
    "login",
    "token",
    "castle",
    "dragon",
    "wizard",
    "matrix",
    "enigma",
];

/// How readable a dictionary hit has to be before it is reported.
///
/// Higher than the bar for a key recovered from the text itself, because this
/// one had 48 chances rather than one. A guessed key that merely scores well is
/// how a tool ends up confidently wrong.
const MIN_SCORE: f32 = 0.65;

/// Shortest text worth a dictionary attack.
///
/// Not for the sake of the attack, which works on anything, but for the sake of
/// judging it: on a short run a wrong key reads about as well as the right one.
const MIN_LETTERS: usize = 40;

/// Tries the wordlist and reports anything that reads or carries a flag.
///
/// Judged, unlike [`with_key`], because nobody vouched for these.
pub fn dictionary(data: &[u8]) -> Option<Attempt> {
    if ngram::letters(data).len() < MIN_LETTERS {
        return None;
    }

    let before = plainness(data);

    WORDLIST
        .iter()
        .flat_map(|key| attempts(data, key))
        .filter(|found| !found.flags.is_empty() || found.score >= MIN_SCORE.max(before + 0.1))
        .fold(None::<Attempt>, |best, next| match best {
            Some(current) if current.score >= next.score => Some(current),
            _ => Some(next),
        })
}

pub fn json(attempts: &[Attempt]) -> String {
    use crate::json::{push_field, push_string};

    let mut out = String::from("[");

    for (i, attempt) in attempts.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "cipher", attempt.cipher);
        out.push(',');
        push_field(&mut out, "key", &attempt.key);
        out.push(',');
        push_string(&mut out, "score");
        out.push_str(&format!(":{:.3},", attempt.score));
        push_field(
            &mut out,
            "plaintext",
            &crate::json::latin1(&attempt.plaintext),
        );
        out.push(',');
        push_string(&mut out, "next");
        out.push(':');
        out.push_str(&vigenere::derived_json(&attempt.next));
        out.push(',');
        push_string(&mut out, "flags");
        out.push_str(":[");
        for (j, flag) in attempt.flags.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            push_string(&mut out, flag);
        }
        out.push_str("]}");
    }

    out.push(']');
    out
}

#[cfg(test)]
mod tests;
