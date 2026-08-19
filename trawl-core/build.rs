//! Packs the committed trigram census into a dense byte table.
//!
//! The census is committed as text so the numbers can be read and checked, but
//! shipping it that way would put 77KB of ASCII in the .wasm to carry 17KB of
//! information. This turns it into one byte per cell at compile time.
//!
//! A byte holds log10 of the trigram's probability, rescaled so the floor lands
//! on 0 and the commonest trigram on 255. Scoring only ever compares sums over
//! runs of equal length, and that rescaling is affine, so the comparison is the
//! same one the raw log probabilities would give — in integer arithmetic, with
//! no table of floats to carry.

use std::{env, fs, path::Path};

const CELLS: usize = 26 * 26 * 26;

/// Weight given to a trigram the census never saw. Not zero: an unobserved
/// trigram is rare, not impossible, and a zero would make one unlucky letter
/// veto an otherwise correct key outright.
const UNSEEN: f64 = 0.01;

fn main() {
    let source = Path::new("src/mantis/ngram/trigrams.txt");
    println!("cargo::rerun-if-changed={}", source.display());

    let text = fs::read_to_string(source).expect("trigram census missing");

    let mut counts = [0f64; CELLS];
    let mut total = 0f64;

    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }

        let (tri, count) = line.split_once(' ').expect("malformed census line");
        let count: f64 = count.trim().parse().expect("malformed census count");

        let mut index = 0usize;
        for byte in tri.bytes() {
            assert!(byte.is_ascii_uppercase(), "census trigram {tri} is not A-Z");
            index = index * 26 + (byte - b'A') as usize;
        }

        counts[index] = count;
        total += count;
    }

    assert!(total > 0.0, "census is empty");

    let floor = (UNSEEN / total).log10();
    let ceiling = (counts.iter().cloned().fold(0f64, f64::max) / total).log10();
    let span = ceiling - floor;

    let mut packed = [0u8; CELLS];
    for (cell, &count) in counts.iter().enumerate() {
        let probability = count.max(UNSEEN) / total;
        packed[cell] = (((probability.log10() - floor) / span) * 255.0).round() as u8;
    }

    // Where the two ends of the scale sit, so readability is stated against
    // something measured rather than a number picked to feel right.
    //
    // English is the mean byte weighted by how often English produces each
    // trigram. Noise is the same mean when the letters are drawn independently
    // with English's own letter frequencies.
    //
    // That second one has to be the null, not a flat 26-way spread. This table
    // is meant to measure the order letters arrive in, and a text can keep
    // English's letter mix exactly while destroying the order: that is what a
    // transposition cipher is. Scored against a flat alphabet such a text looks
    // half readable, because it lands on high-count cells purely by being made
    // of E and T and A. Scored against this null it lands where it belongs, at
    // nothing, and what is left on the scale is order alone.
    let mut unigram = [0f64; 26];
    for (cell, &count) in counts.iter().enumerate() {
        unigram[cell / 676] += count;
    }
    let mass: f64 = unigram.iter().sum();
    for share in &mut unigram {
        *share /= mass;
    }

    let english: f64 = counts
        .iter()
        .zip(&packed)
        .map(|(&count, &byte)| (count / total) * byte as f64)
        .sum();
    let noise: f64 = packed
        .iter()
        .enumerate()
        .map(|(cell, &byte)| {
            let independent = unigram[cell / 676] * unigram[(cell / 26) % 26] * unigram[cell % 26];
            independent * byte as f64
        })
        .sum();

    let out = Path::new(&env::var("OUT_DIR").unwrap()).to_path_buf();
    fs::write(out.join("trigrams.bin"), packed).unwrap();
    fs::write(
        out.join("anchors.rs"),
        format!("const ENGLISH: f32 = {english:.4};\nconst NOISE: f32 = {noise:.4};\n"),
    )
    .unwrap();
}
