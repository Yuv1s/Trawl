//! RS analysis, an estimator rather than a yes-or-no test.
//!
//! Fridrich, J., Goljan, M. and Du, R. (2001), "Reliable Detection of LSB
//! Steganography in Color and Grayscale Images", Proc. ACM Workshop on
//! Multimedia and Security, pp. 27-30.
//!
//! The idea: neighbouring pixels in a real image are correlated, so a group of
//! them is smoother than chance. Flipping their low bits usually makes the group
//! rougher. Flipping them the *other* way, by pairing each value with its lower
//! neighbour instead of its upper one, is an operation a natural image responds
//! to symmetrically, but LSB embedding is not symmetric under it. Measure both
//! and the gap between them scales with how much was embedded.

/// Smoothness of a group: total variation across it. Rougher groups score higher.
fn discriminate(group: &[u8; 4]) -> u32 {
    (0..3)
        .map(|i| group[i + 1].abs_diff(group[i]) as u32)
        .sum()
}

/// F₁ pairs 2i with 2i+1, which is exactly what writing a bit into the low bit does.
fn flip_up(value: u8) -> u8 {
    value ^ 1
}

/// F₋₁ pairs 2i-1 with 2i instead. 0 and 255 have no partner inside the range and
/// stay put, which is the usual practical reading of the paper's definition.
fn flip_down(value: u8) -> u8 {
    match value {
        0 | 255 => value,
        v if v % 2 == 1 => v + 1,
        v => v - 1,
    }
}

/// Fridrich's mask: flip two of the four, leave two alone.
const MASK: [i8; 4] = [0, 1, 1, 0];

fn apply(group: &[u8; 4], mask: [i8; 4]) -> [u8; 4] {
    let mut out = *group;
    for i in 0..4 {
        out[i] = match mask[i] {
            1 => flip_up(out[i]),
            -1 => flip_down(out[i]),
            _ => out[i],
        };
    }
    out
}

fn negate(mask: [i8; 4]) -> [i8; 4] {
    [-mask[0], -mask[1], -mask[2], -mask[3]]
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Counts {
    pub regular: f64,
    pub singular: f64,
    pub regular_negated: f64,
    pub singular_negated: f64,
    pub groups: usize,
}

/// Walks disjoint runs of four horizontally adjacent samples, per channel.
///
/// Adjacency is the whole point: the discrimination function measures local
/// smoothness, so groups have to be spatially contiguous rather than four
/// samples picked out of a flat buffer.
///
/// @param flip_all applies F₁ to every sample first, which is how the paper gets
///        its second measurement point
pub fn scan(
    rgba: &[u8],
    width: usize,
    height: usize,
    channels: usize,
    flip_all: bool,
) -> Counts {
    let mut counts = Counts::default();
    let negated = negate(MASK);

    for channel in 0..channels {
        for y in 0..height {
            let row = y * width;
            let mut x = 0;

            while x + 4 <= width {
                let mut group = [0u8; 4];
                for (i, slot) in group.iter_mut().enumerate() {
                    let value = rgba[(row + x + i) * 4 + channel];
                    *slot = if flip_all { flip_up(value) } else { value };
                }

                let base = discriminate(&group);
                let with_mask = discriminate(&apply(&group, MASK));
                let with_negated = discriminate(&apply(&group, negated));

                if with_mask > base {
                    counts.regular += 1.0;
                } else if with_mask < base {
                    counts.singular += 1.0;
                }

                if with_negated > base {
                    counts.regular_negated += 1.0;
                } else if with_negated < base {
                    counts.singular_negated += 1.0;
                }

                counts.groups += 1;
                x += 4;
            }
        }
    }

    if counts.groups > 0 {
        let total = counts.groups as f64;
        counts.regular /= total;
        counts.singular /= total;
        counts.regular_negated /= total;
        counts.singular_negated /= total;
    }

    counts
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Estimate {
    pub rate: f32,
    pub reliable: bool,
    pub counts: Counts,
    pub flipped: Counts,
}

/// Solves the paper's quadratic for the embedding rate.
///
/// With d0 and d₋0 measured on the image and d1 and d₋1 on the image with every
/// low bit flipped, the rate p satisfies
///
///   2(d1 + d0)x² + (d₋0 − d₋1 − d1 − 3d0)x + (d0 − d₋0) = 0,   p = x / (x − ½)
///
/// The root nearer zero is the physical one; the other is an artefact of squaring.
fn solve(d0: f64, d1: f64, dn0: f64, dn1: f64) -> Option<f64> {
    let a = 2.0 * (d1 + d0);
    let b = dn0 - dn1 - d1 - 3.0 * d0;
    let c = d0 - dn0;

    let x = if a.abs() < 1e-12 {
        if b.abs() < 1e-12 {
            return None;
        }
        -c / b
    } else {
        let discriminant = b * b - 4.0 * a * c;
        if discriminant < 0.0 {
            return None;
        }
        let root = discriminant.sqrt();
        let first = (-b + root) / (2.0 * a);
        let second = (-b - root) / (2.0 * a);
        if first.abs() <= second.abs() { first } else { second }
    };

    if (x - 0.5).abs() < 1e-12 {
        return None;
    }
    Some(x / (x - 0.5))
}

pub fn analyse(rgba: &[u8], width: usize, height: usize, channels: usize) -> Estimate {
    let counts = scan(rgba, width, height, channels, false);
    let flipped = scan(rgba, width, height, channels, true);

    let d0 = counts.regular - counts.singular;
    let dn0 = counts.regular_negated - counts.singular_negated;
    let d1 = flipped.regular - flipped.singular;
    let dn1 = flipped.regular_negated - flipped.singular_negated;

    let solved = if counts.groups < 64 { None } else { solve(d0, d1, dn0, dn1) };

    match solved {
        Some(p) if p.is_finite() => Estimate {
            rate: p.clamp(0.0, 1.0) as f32,
            // A solution far outside the valid range means the model did not fit,
            // and clamping it would hide that.
            reliable: (-0.15..=1.15).contains(&p),
            counts,
            flipped,
        },
        _ => Estimate {
            rate: 0.0,
            reliable: false,
            counts,
            flipped,
        },
    }
}

/// Detection threshold. Below this the estimate is within the noise floor of a
/// clean image and is not worth calling a finding.
pub const DETECTION_FLOOR: f32 = 0.05;

pub fn json(estimate: &Estimate) -> String {
    use crate::json::{push_bool, push_number, push_string};

    let number = |out: &mut String, key: &str, value: f64| {
        push_string(out, key);
        out.push(':');
        out.push_str(&format!("{value:.4}"));
    };

    let mut out = String::from("{");
    push_string(&mut out, "rate");
    out.push(':');
    out.push_str(&format!("{:.4}", estimate.rate));
    out.push(',');
    push_bool(&mut out, "reliable", estimate.reliable);
    out.push(',');
    push_bool(
        &mut out,
        "detected",
        estimate.reliable && estimate.rate > DETECTION_FLOOR,
    );
    out.push(',');
    push_number(&mut out, "groups", estimate.counts.groups);
    out.push(',');
    number(&mut out, "regular", estimate.counts.regular);
    out.push(',');
    number(&mut out, "singular", estimate.counts.singular);
    out.push(',');
    number(&mut out, "regularNegated", estimate.counts.regular_negated);
    out.push(',');
    number(&mut out, "singularNegated", estimate.counts.singular_negated);
    out.push('}');
    out
}

#[cfg(test)]
mod tests;
