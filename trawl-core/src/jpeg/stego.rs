//! Attacks against payloads hidden in JPEG coefficients.
//!
//! JSteg writes message bits into the least significant bit of every quantized
//! coefficient except those equal to 0 or 1. Those two are skipped because
//! flipping them changes whether a coefficient exists at all, which wrecks the
//! image and the file size at once.
//!
//! That exclusion is also what gives the attack away. Westfeld and Pfitzmann's
//! 1999 chi-square test was written against exactly this: LSB replacement drives
//! the counts of each (2k, 2k+1) pair together, and no photograph does that on
//! its own. The same statistic already lives in `cuttlefish::chi`, so this
//! module maps coefficients into it rather than growing a second copy.
//!
//! F5 is a different matter and is deliberately not claimed. It decrements
//! magnitudes instead of replacing bits, so the pair test does not see it, and
//! the published detector needs a re-compressed estimate of the cover histogram
//! to work from. What is offered instead is the coefficient histogram itself,
//! where F5's dent in the counts of 1 and -1 is visible to a person.

use crate::cuttlefish::{assess, chi};

use super::dct::{Coefficients, DctError};

/// Coefficient values in true entropy-stream order.
///
/// @param include_dc the original JSteg embeds in DC too; most later variants
///        skip it, and reading the wrong one shifts every bit after block one
pub fn values(coefficients: &Coefficients, include_dc: bool) -> Vec<i32> {
    let mut out = Vec::with_capacity(coefficients.total_blocks() * 64);

    for &(component, index) in &coefficients.order {
        let block = &coefficients.blocks[component][index];
        let from = if include_dc { 0 } else { 1 };
        out.extend_from_slice(&block[from..]);
    }

    out
}

/// True for a coefficient JSteg would have written into.
fn carries(value: i32) -> bool {
    value != 0 && value != 1
}

/// Packs the low bits of every eligible coefficient into bytes.
pub fn extract(
    coefficients: &Coefficients,
    include_dc: bool,
    msb_first: bool,
    max_bytes: usize,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut byte = 0u8;
    let mut filled = 0u8;

    for value in values(coefficients, include_dc) {
        if !carries(value) {
            continue;
        }

        // Two's complement, so the low bit of a negative coefficient is the low
        // bit of the number an embedder would have edited.
        let bit = (value as u32 & 1) as u8;

        byte = if msb_first {
            (byte << 1) | bit
        } else {
            byte | (bit << filled)
        };
        filled += 1;

        if filled == 8 {
            out.push(byte);
            byte = 0;
            filled = 0;

            if out.len() >= max_bytes {
                break;
            }
        }
    }

    out
}

#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub include_dc: bool,
    pub msb_first: bool,
    pub reason: String,
    pub preview: String,
    pub readable: usize,
    pub flags: Vec<String>,
    pub bytes_read: usize,
}

/// Both bit orders, with and without DC. Four reads, and a payload that is there
/// falls out of exactly one of them.
pub const COMBINATIONS: usize = 4;

pub fn sweep(coefficients: &Coefficients, max_bytes: usize) -> Vec<Candidate> {
    let mut out = Vec::new();

    for include_dc in [false, true] {
        for msb_first in [true, false] {
            let stream = extract(coefficients, include_dc, msb_first, max_bytes);

            let flags: Vec<String> = crate::bytes::flag_candidates(&stream)
                .into_iter()
                .map(|f| f.text)
                .collect();

            let assessed = assess(&stream);
            if flags.is_empty() && assessed.is_none() {
                continue;
            }

            let (reason, preview, readable) = assessed.unwrap_or_else(|| {
                let joined = flags.join("  ");
                let shown = joined.chars().count();
                (
                    "flag-shaped string in the extracted stream".to_string(),
                    joined,
                    shown,
                )
            });

            out.push(Candidate {
                include_dc,
                msb_first,
                reason,
                preview,
                readable,
                flags,
                bytes_read: stream.len(),
            });
        }
    }

    out
}

/// Coefficients mapped into the byte range the chi-square test works over.
///
/// Adding 128 keeps the pairing intact: 128 is even, so `v` and `v ^ 1` land on
/// `n` and `n ^ 1`. Values 0 and 1 are dropped because JSteg never touches them,
/// and anything outside the range is dropped rather than clamped, which would
/// pile unrelated counts onto the end bins.
fn chi_samples(coefficients: &Coefficients, include_dc: bool) -> Vec<u8> {
    values(coefficients, include_dc)
        .into_iter()
        .filter(|&v| carries(v) && (-128..128).contains(&v))
        .map(|v| (v + 128) as u8)
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChiResult {
    pub detected: bool,
    pub embedded_fraction: f32,
    pub peak_probability: f32,
    pub samples: usize,
    pub points: Vec<chi::Point>,
}

/// The chi-square attack over increasing prefixes of the coefficient stream.
///
/// The prefix sweep is the part that matters: JSteg fills from the start, so a
/// short message leaves a strong fit over the first few percent and nothing
/// after it. Testing the whole image at once would average that away.
pub fn chi_square(coefficients: &Coefficients, steps: usize) -> ChiResult {
    let samples = chi_samples(coefficients, false);
    let points = chi::sweep(&samples, steps);
    let verdict = chi::verdict(&points);

    ChiResult {
        detected: verdict.detected,
        embedded_fraction: verdict.embedded_fraction,
        peak_probability: verdict.peak_probability,
        samples: samples.len(),
        points,
    }
}

/// How far either side of zero the reported histogram runs.
pub const HISTOGRAM_RANGE: i32 = 12;

/// Counts of each small coefficient value, AC only.
///
/// Reported, not judged. A clean photograph falls away smoothly from zero and is
/// close to symmetric; F5 leaves a visible dent at 1 and -1, and OutGuess
/// flattens the pairs. Naming which of those happened needs the original file,
/// so the counts are shown and the reader draws the conclusion.
pub fn histogram(coefficients: &Coefficients) -> Vec<(i32, u64)> {
    let mut counts = vec![0u64; (HISTOGRAM_RANGE * 2 + 1) as usize];

    for value in values(coefficients, false) {
        if (-HISTOGRAM_RANGE..=HISTOGRAM_RANGE).contains(&value) {
            counts[(value + HISTOGRAM_RANGE) as usize] += 1;
        }
    }

    (-HISTOGRAM_RANGE..=HISTOGRAM_RANGE)
        .map(|v| (v, counts[(v + HISTOGRAM_RANGE) as usize]))
        .collect()
}

/// Everything the JPEG coefficient tools produce, as JSON.
pub fn json(file: &[u8], max_bytes: usize, steps: usize) -> String {
    use crate::json::{push_bool, push_field, push_number, push_string};

    let coefficients = match super::dct::coefficients(file) {
        Ok(c) => c,
        Err(DctError::NotJpeg) => return "null".to_string(),
        Err(e) => {
            let mut out = String::from("{");
            push_field(&mut out, "error", &e.to_string());
            out.push('}');
            return out;
        }
    };

    let mut out = String::from("{");
    push_number(&mut out, "width", coefficients.frame.width);
    out.push(',');
    push_number(&mut out, "height", coefficients.frame.height);
    out.push(',');
    push_number(&mut out, "components", coefficients.frame.components.len());
    out.push(',');
    push_number(&mut out, "blocks", coefficients.total_blocks());
    out.push(',');
    push_number(&mut out, "scans", coefficients.scans);
    out.push(',');
    push_bool(&mut out, "progressive", coefficients.frame.progressive);
    out.push(',');
    push_bool(&mut out, "truncated", coefficients.truncated);
    out.push(',');
    push_number(&mut out, "combinations", COMBINATIONS);
    out.push(',');

    let chi = chi_square(&coefficients, steps);
    push_string(&mut out, "chi");
    out.push_str(":{");
    push_bool(&mut out, "detected", chi.detected);
    out.push(',');
    push_string(&mut out, "embeddedFraction");
    out.push_str(&format!(":{:.4}", chi.embedded_fraction));
    out.push(',');
    push_string(&mut out, "peakProbability");
    out.push_str(&format!(":{:.4}", chi.peak_probability));
    out.push(',');
    push_number(&mut out, "samples", chi.samples);
    out.push(',');
    push_string(&mut out, "points");
    out.push_str(":[");
    for (i, point) in chi.points.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"fraction\":{:.4},\"p\":{:.4},\"chiSquare\":{:.3},\"degrees\":{}}}",
            point.fraction, point.p_embedding, point.chi_square, point.degrees
        ));
    }
    out.push_str("]},");

    push_string(&mut out, "histogram");
    out.push_str(":[");
    for (i, (value, count)) in histogram(&coefficients).iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("{{\"value\":{value},\"count\":{count}}}"));
    }
    out.push_str("],");

    push_string(&mut out, "candidates");
    out.push_str(":[");
    for (i, candidate) in sweep(&coefficients, max_bytes).iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_bool(&mut out, "includeDc", candidate.include_dc);
        out.push(',');
        push_bool(&mut out, "msbFirst", candidate.msb_first);
        out.push(',');
        push_field(&mut out, "reason", &candidate.reason);
        out.push(',');
        push_field(&mut out, "preview", &candidate.preview);
        out.push(',');
        push_number(&mut out, "readable", candidate.readable);
        out.push(',');
        push_number(&mut out, "bytesRead", candidate.bytes_read);
        out.push(',');
        push_string(&mut out, "flags");
        out.push_str(":[");
        for (j, flag) in candidate.flags.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            push_string(&mut out, flag);
        }
        out.push_str("]}");
    }
    out.push_str("]}");

    out
}

#[cfg(test)]
mod tests;
