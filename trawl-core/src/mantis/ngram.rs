//! How much a run of letters reads like English, measured rather than guessed.
//!
//! Everything else in Mantis scores candidates with letter frequency and a list
//! of common words. That is enough when the cipher splits into columns, because
//! then each column only has to be told from a wrong shift of itself. It is not
//! enough for simple substitution, which has no columns: the letter frequencies
//! of a wrong key and a right key can sit almost on top of each other, and it is
//! the order letters arrive in that separates them.
//!
//! So this counts trigrams. THE is common, ING is common, QKZ never happens, and
//! a wrong key produces a great many arrangements that English would not. The
//! table is a census of ordinary prose, committed as text under `ngram/` and
//! packed to one byte per cell by build.rs.
//!
//! Two ways to ask. [`weight`] is the raw sum, for choosing between candidates
//! of the same length, where the fastest comparison wins because hill climbing
//! makes millions of them. [`fitness`] normalises that to nought-to-one against
//! measured English, for reporting and for comparing runs of different lengths.

const CELLS: usize = 26 * 26 * 26;

/// One byte per trigram: log10 of its probability, rescaled so an unobserved
/// trigram is 0 and the commonest is 255.
static TABLE: &[u8; CELLS] = include_bytes!(concat!(env!("OUT_DIR"), "/trigrams.bin"));

// ENGLISH and NOISE: where prose and uniform noise fall on that 0-255 scale.
// Computed from the census itself by build.rs, so neither is a number anyone
// chose.
include!(concat!(env!("OUT_DIR"), "/anchors.rs"));

/// Letters only, folded to A-Z. Everything else carries no trigram evidence.
pub fn letters(data: &[u8]) -> Vec<u8> {
    data.iter()
        .filter(|b| b.is_ascii_alphabetic())
        .map(|b| b.to_ascii_uppercase())
        .collect()
}

/// Weight of one trigram cell, indexed as `(a * 26 + b) * 26 + c` over letters
/// numbered from nought.
///
/// [`weight`] reads letters from a slice. A solver that generates them — hill
/// climbing over substitution keys makes millions of candidates and never holds
/// one — would have to allocate a decrypted copy per candidate just to call it.
/// This lets such a solver roll the index itself.
#[inline]
pub fn cell(index: usize) -> u32 {
    TABLE[index] as u32
}

/// Summed trigram weight over already-folded letters.
///
/// Meaningful only against another run of the same length. Hill climbing calls
/// this on every swap it considers, so it stays a tight loop over a slice with
/// no allocation and no floating point.
pub fn weight(letters: &[u8]) -> u32 {
    if letters.len() < 3 {
        return 0;
    }

    let mut total = 0u32;
    let mut cell = (letters[0] - b'A') as usize * 26 + (letters[1] - b'A') as usize;

    for &letter in &letters[2..] {
        cell = (cell % 676) * 26 + (letter - b'A') as usize;
        total += TABLE[cell] as u32;
    }

    total
}

/// Enough letters for the trigram mean to mean anything.
///
/// Short runs are not merely noisy, they are confidently wrong. Drawing letters
/// with English's own frequencies and no order at all — the null this scale is
/// built on, and what a transposition cipher produces — eight of them score a
/// flat 1.000 often enough to matter, because a couple of trigrams can land on
/// THE and ING by luck and there is nothing else in the average to outvote them.
///
/// Worst of 300 draws, before this ramp is applied and after:
///
/// ```text
/// letters      8     12     20     30     45     60     90    140
///     raw  1.000  1.000  0.763  0.588  0.523  0.588  0.527  0.396
///  ramped  0.178  0.267  0.339  0.392  0.523  0.588  0.527  0.396
/// ```
///
/// Scaling back towards nothing in proportion to the evidence is what stops a
/// dozen letters from outscoring a paragraph. It cannot do anything about the
/// spread that remains past 45, which is ordinary variance and is why nothing
/// here treats this number alone as a verdict. `tests::probe_noise_band`
/// regenerates the table.
const EVIDENCE: f32 = 45.0;

/// Trigram weight as nought to one, where nought is noise and one is prose.
///
/// Nought-to-one because the rest of Mantis reports on that scale, not because
/// the number means anything on its own. Text can score above English — a run of
/// nothing but THE would — so the top is clamped.
///
/// Scaled by how many letters went into it. A caller comparing two candidates
/// wants the trigram evidence to decide only when there is some.
pub fn fitness(data: &[u8]) -> f32 {
    let letters = letters(data);
    if letters.len() < 3 {
        return 0.0;
    }

    let mean = weight(&letters) as f32 / (letters.len() - 2) as f32;
    let confidence = (letters.len() as f32 / EVIDENCE).min(1.0);

    ((mean - NOISE) / (ENGLISH - NOISE)).clamp(0.0, 1.0) * confidence
}

#[cfg(test)]
mod tests;
