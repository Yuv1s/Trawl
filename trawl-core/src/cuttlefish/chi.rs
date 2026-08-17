//! Chi-square attack on sequential LSB embedding.
//!
//! Westfeld, A. and Pfitzmann, A. (1999), "Attacks on Steganographic Systems",
//! Information Hiding, LNCS 1768, pp. 61-76.
//!
//! The idea: LSB embedding turns the values 2i and 2i+1 into a pair that a
//! payload bit chooses between. A natural image has no reason for those two
//! counts to match, but a random payload drives them together, because each
//! value is equally likely to be flipped into the other. So the test asks how
//! well the observed histogram fits the *equalised* distribution. A good fit
//! means embedding.
//!
//! Run over increasing prefixes, the fit stays good while the payload lasts and
//! collapses where it stops, which puts a number on the payload length.

/// Log-gamma by the Lanczos approximation, g = 7, n = 9.
/// Coefficients from Press et al., "Numerical Recipes", 3rd ed., §6.1.
fn ln_gamma(x: f64) -> f64 {
    const C: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];

    if x < 0.5 {
        // Reflection, so the series stays in its region of convergence.
        return (std::f64::consts::PI / (std::f64::consts::PI * x).sin()).ln() - ln_gamma(1.0 - x);
    }

    let z = x - 1.0;
    let mut a = C[0];
    for (i, &c) in C.iter().enumerate().skip(1) {
        a += c / (z + i as f64);
    }
    let t = z + 7.5;

    0.5 * (2.0 * std::f64::consts::PI).ln() + (z + 0.5) * t.ln() - t + a.ln()
}

const EPS: f64 = 1e-14;
const TINY: f64 = 1e-300;

/// Regularised lower incomplete gamma P(a, x), by its series expansion.
fn gamma_p_series(a: f64, x: f64) -> f64 {
    let mut term = 1.0 / a;
    let mut sum = term;
    let mut n = a;

    for _ in 0..1000 {
        n += 1.0;
        term *= x / n;
        sum += term;
        if term.abs() < sum.abs() * EPS {
            break;
        }
    }

    sum * (-x + a * x.ln() - ln_gamma(a)).exp()
}

/// Regularised upper incomplete gamma Q(a, x), by its continued fraction,
/// evaluated with the modified Lentz method.
fn gamma_q_fraction(a: f64, x: f64) -> f64 {
    let mut b = x + 1.0 - a;
    let mut c = 1.0 / TINY;
    let mut d = 1.0 / b;
    let mut h = d;

    for i in 1..1000 {
        let an = -(i as f64) * (i as f64 - a);
        b += 2.0;

        d = an * d + b;
        if d.abs() < TINY {
            d = TINY;
        }
        c = b + an / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;

        let delta = d * c;
        h *= delta;
        if (delta - 1.0).abs() < EPS {
            break;
        }
    }

    (-x + a * x.ln() - ln_gamma(a)).exp() * h
}

/// Q(a, x), the complement of the regularised lower incomplete gamma.
///
/// The series converges quickly below x = a + 1 and the continued fraction above
/// it, so each is used where it behaves.
pub fn gamma_q(a: f64, x: f64) -> f64 {
    if x < 0.0 || a <= 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return 1.0;
    }

    if x < a + 1.0 {
        1.0 - gamma_p_series(a, x)
    } else {
        gamma_q_fraction(a, x)
    }
}

/// Probability that a chi-square statistic this small or smaller arises from the
/// equalised model, which Westfeld reads as the probability of embedding.
pub fn embedding_probability(chi_square: f64, degrees: usize) -> f64 {
    if degrees == 0 {
        return 0.0;
    }
    gamma_q(degrees as f64 / 2.0, chi_square / 2.0)
}

/// Pairs whose expected count falls below this are dropped: the chi-square
/// approximation is unreliable on sparse bins, and keeping them lets a handful
/// of near-empty values dominate the statistic.
const MIN_EXPECTED: f64 = 4.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point {
    /// Where this prefix ends, as a fraction of all samples.
    pub fraction: f32,
    pub samples: usize,
    pub chi_square: f32,
    pub degrees: usize,
    pub p_embedding: f32,
}

/// Chi-square over one histogram of 8-bit sample values.
pub fn statistic(histogram: &[u64; 256]) -> (f64, usize) {
    let mut chi_square = 0.0;
    let mut used = 0usize;

    for pair in 0..128 {
        let low = histogram[pair * 2] as f64;
        let high = histogram[pair * 2 + 1] as f64;
        let expected = (low + high) / 2.0;

        if expected < MIN_EXPECTED {
            continue;
        }

        // Only one term per pair: the two deviations are equal and opposite, so
        // summing both would double the statistic without adding information.
        chi_square += (low - expected).powi(2) / expected;
        used += 1;
    }

    (chi_square, used.saturating_sub(1))
}

/// Runs the test over increasing prefixes of the sample sequence.
///
/// @param samples 8-bit values in the order an embedder would traverse them
/// @param steps how many prefixes to evaluate
pub fn sweep(samples: &[u8], steps: usize) -> Vec<Point> {
    if samples.is_empty() || steps == 0 {
        return Vec::new();
    }

    let mut histogram = [0u64; 256];
    let mut points = Vec::with_capacity(steps);
    let mut cursor = 0usize;

    for step in 1..=steps {
        let end = (samples.len() * step / steps).max(1);
        for &value in &samples[cursor..end] {
            histogram[value as usize] += 1;
        }
        cursor = end;

        let (chi_square, degrees) = statistic(&histogram);
        points.push(Point {
            fraction: end as f32 / samples.len() as f32,
            samples: end,
            chi_square: chi_square as f32,
            degrees,
            p_embedding: embedding_probability(chi_square, degrees) as f32,
        });
    }

    points
}

/// A payload is called present only where the fit is strong over a prefix large
/// enough that a handful of pairs cannot have produced it by luck.
const STRONG: f32 = 0.95;
const MIN_FRACTION: f32 = 0.01;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Verdict {
    pub detected: bool,
    /// Where the fit collapses, which is the payload boundary.
    pub embedded_fraction: f32,
    pub peak_probability: f32,
}

pub fn verdict(points: &[Point]) -> Verdict {
    let peak = points
        .iter()
        .filter(|p| p.fraction >= MIN_FRACTION && p.degrees > 0)
        .map(|p| p.p_embedding)
        .fold(0.0f32, f32::max);

    let boundary = points
        .iter()
        .filter(|p| p.p_embedding > 0.5 && p.degrees > 0)
        .map(|p| p.fraction)
        .fold(0.0f32, f32::max);

    Verdict {
        detected: peak > STRONG,
        embedded_fraction: boundary,
        peak_probability: peak,
    }
}

#[cfg(test)]
mod tests;
