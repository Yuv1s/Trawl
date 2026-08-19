//! The counts themselves, for when the solvers have not settled it.
//!
//! Everything else in Mantis reports a conclusion. This reports the evidence,
//! because sometimes no attack fires and the useful thing is to see why: a
//! cipher nobody here implements still leaves fingerprints in its letter counts,
//! and a person who knows what they are looking at can often name it from the
//! shape alone.
//!
//! Three things are worth looking at. Letter counts say whether the alphabet was
//! substituted or only moved. Repeated pairs and triples say the same thing more
//! sharply. The index of coincidence says whether one alphabet was used or
//! several, which is the difference between Caesar and Vigenère and cannot be
//! seen by eye.

use super::{ngram, vigenere};

/// How often each letter turns up, and how that compares with English.
#[derive(Debug, Clone, PartialEq)]
pub struct Letter {
    pub letter: u8,
    pub count: usize,
    /// Share of all letters, as a percentage.
    pub share: f32,
    /// What English would give this letter, for the same text length.
    pub english: f32,
}

/// A run of letters and how often it repeats.
#[derive(Debug, Clone, PartialEq)]
pub struct Repeat {
    pub text: Vec<u8>,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Table {
    pub letters: Vec<Letter>,
    pub total: usize,
    /// Chance that two letters drawn from the text are the same one.
    ///
    /// English runs near 0.067 because it leans hard on e and t. A text using
    /// several alphabets at once flattens towards 0.038, which is what 26 evenly
    /// used letters would give. The number sits between the two when a keyword
    /// is short relative to the text.
    pub coincidence: f32,
    pub bigrams: Vec<Repeat>,
    pub trigrams: Vec<Repeat>,
}

/// English letter frequencies, in percent, a through z.
const ENGLISH: [f32; 26] = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406,
    6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074,
];

/// How many repeated pairs and triples to report.
///
/// Enough to see a pattern, few enough to read at a glance. Past a dozen the
/// tail is single occurrences that mean nothing.
const REPEATS: usize = 10;

/// Counts every run of `size` letters that occurs more than once, commonest
/// first.
fn repeats(letters: &[u8], size: usize) -> Vec<Repeat> {
    if letters.len() < size {
        return Vec::new();
    }

    let mut seen: Vec<(Vec<u8>, usize)> = Vec::new();

    for window in letters.windows(size) {
        match seen.iter_mut().find(|(text, _)| text == window) {
            Some((_, count)) => *count += 1,
            None => seen.push((window.to_vec(), 1)),
        }
    }

    seen.retain(|(_, count)| *count > 1);
    seen.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    seen.truncate(REPEATS);

    seen.into_iter()
        .map(|(text, count)| Repeat { text, count })
        .collect()
}

pub fn table(data: &[u8]) -> Table {
    let letters = ngram::letters(data);
    let total = letters.len();

    let mut counts = [0usize; 26];
    for &letter in &letters {
        counts[(letter - b'A') as usize] += 1;
    }

    Table {
        letters: (0..26)
            .map(|i| Letter {
                letter: b'A' + i as u8,
                count: counts[i],
                share: if total == 0 {
                    0.0
                } else {
                    counts[i] as f32 * 100.0 / total as f32
                },
                english: ENGLISH[i],
            })
            .collect(),
        total,
        // That one counts from lowercase, and these are folded the other way.
        coincidence: vigenere::index_of_coincidence(
            &letters
                .iter()
                .map(|b| b.to_ascii_lowercase())
                .collect::<Vec<_>>(),
        ),
        bigrams: repeats(&letters, 2),
        trigrams: repeats(&letters, 3),
    }
}

pub fn json(data: &[u8]) -> String {
    use crate::json::{push_field, push_number, push_string};

    let table = table(data);
    let mut out = String::from("{");

    push_number(&mut out, "total", table.total);
    out.push(',');
    push_string(&mut out, "coincidence");
    out.push_str(&format!(":{:.4},", table.coincidence));

    push_string(&mut out, "letters");
    out.push_str(":[");
    for (i, letter) in table.letters.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "letter", &(letter.letter as char).to_string());
        out.push(',');
        push_number(&mut out, "count", letter.count);
        out.push(',');
        push_string(&mut out, "share");
        out.push_str(&format!(":{:.2},", letter.share));
        push_string(&mut out, "english");
        out.push_str(&format!(":{:.3}", letter.english));
        out.push('}');
    }
    out.push_str("],");

    let mut runs = |name: &str, found: &[Repeat], last: bool| {
        push_string(&mut out, name);
        out.push_str(":[");
        for (i, repeat) in found.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('{');
            push_field(&mut out, "text", &String::from_utf8_lossy(&repeat.text));
            out.push(',');
            push_number(&mut out, "count", repeat.count);
            out.push('}');
        }
        out.push(']');
        if !last {
            out.push(',');
        }
    };

    runs("bigrams", &table.bigrams, false);
    runs("trigrams", &table.trigrams, true);

    out.push('}');
    out
}

#[cfg(test)]
mod tests;
