//! Short-time Fourier transform, for the case where the payload is a picture
//! drawn in the frequency domain.
//!
//! Someone writes text into a spectrogram, renders it back to audio, and the
//! file sounds like static until you look at it the right way. There is nothing
//! statistical to detect here, so this module measures nothing and claims
//! nothing: it produces the image and lets a person read it.
//!
//! The FFT is a plain iterative radix-2 Cooley-Tukey. Window sizes are powers of
//! two by construction, so there is no mixed-radix case to handle.

/// Bit-reversal permutation, done in place.
///
/// Cooley-Tukey reads its input in bit-reversed order. Permuting up front lets
/// the butterflies run over contiguous memory afterwards.
fn reverse_bits(re: &mut [f32], im: &mut [f32]) {
    let n = re.len();
    let mut j = 0usize;

    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j |= bit;

        if i < j {
            re.swap(i, j);
            im.swap(i, j);
        }
    }
}

/// In-place forward FFT. `re.len()` must be a power of two.
pub fn fft(re: &mut [f32], im: &mut [f32]) {
    let n = re.len();
    debug_assert_eq!(n, im.len());
    debug_assert!(n.is_power_of_two());
    if n < 2 {
        return;
    }

    reverse_bits(re, im);

    let mut len = 2usize;
    while len <= n {
        let angle = -2.0 * core::f64::consts::PI / len as f64;
        let (step_sin, step_cos) = angle.sin_cos();

        for start in (0..n).step_by(len) {
            let (mut w_re, mut w_im) = (1.0f64, 0.0f64);

            for k in 0..len / 2 {
                let a = start + k;
                let b = a + len / 2;

                let t_re = re[b] as f64 * w_re - im[b] as f64 * w_im;
                let t_im = re[b] as f64 * w_im + im[b] as f64 * w_re;

                re[b] = (re[a] as f64 - t_re) as f32;
                im[b] = (im[a] as f64 - t_im) as f32;
                re[a] = (re[a] as f64 + t_re) as f32;
                im[a] = (im[a] as f64 + t_im) as f32;

                let next_re = w_re * step_cos - w_im * step_sin;
                w_im = w_re * step_sin + w_im * step_cos;
                w_re = next_re;
            }
        }

        len <<= 1;
    }
}

/// Hann window. Tapering each frame to zero at both ends stops the discontinuity
/// at the frame edge from smearing energy across every bin.
fn hann(size: usize) -> Vec<f32> {
    (0..size)
        .map(|i| {
            let t = i as f64 / (size - 1) as f64;
            (0.5 - 0.5 * (2.0 * core::f64::consts::PI * t).cos()) as f32
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Spectrogram {
    pub width: usize,
    pub height: usize,
    pub window: usize,
    pub hop: usize,
    /// Top row of the image, in Hz. The bottom row is always 0.
    pub max_frequency: f32,
    pub seconds: f32,
    /// Grayscale, row 0 at the top, so high frequencies come first.
    pub pixels: Vec<u8>,
}

/// Quietest level the image shows. Anything below this is black; without a floor
/// the empty parts of a clean recording fill with dither and the picture drowns.
const FLOOR_DB: f32 = -90.0;

pub fn analyse(
    samples: &[f32],
    sample_rate: u32,
    window: usize,
    target_width: usize,
) -> Option<Spectrogram> {
    let window = window.next_power_of_two().clamp(64, 4096);
    if samples.len() < window || target_width == 0 {
        return None;
    }

    let bins = window / 2;
    let frames = samples.len().saturating_sub(window) / (window / 4) + 1;
    // Overlap by three quarters at full resolution, then stride further for a
    // long file so the image stays a readable width instead of a smear.
    let hop = if frames <= target_width {
        window / 4
    } else {
        ((samples.len() - window) / target_width).max(1)
    };

    let columns = (samples.len() - window) / hop + 1;
    let taper = hann(window);

    let mut magnitudes = vec![0f32; columns * bins];
    let mut peak = f32::MIN;

    let mut re = vec![0f32; window];
    let mut im = vec![0f32; window];

    for column in 0..columns {
        let start = column * hop;
        for i in 0..window {
            re[i] = samples[start + i] * taper[i];
            im[i] = 0.0;
        }

        fft(&mut re, &mut im);

        for bin in 0..bins {
            let power = re[bin] * re[bin] + im[bin] * im[bin];
            // 10log10 of power is the same as 20log10 of magnitude, without the
            // square root.
            let db = if power > 0.0 {
                10.0 * power.log10()
            } else {
                FLOOR_DB
            };
            magnitudes[column * bins + bin] = db;
            if db > peak {
                peak = db;
            }
        }
    }

    // Normalise against the loudest bin in this file rather than a fixed scale,
    // so a quiet recording is still legible. Silence has no loudest bin, and
    // dividing by it would render an empty file as solid white.
    let mut pixels = vec![0u8; columns * bins];
    if peak <= FLOOR_DB {
        return Some(Spectrogram {
            width: columns,
            height: bins,
            window,
            hop,
            max_frequency: sample_rate as f32 / 2.0,
            seconds: samples.len() as f32 / sample_rate.max(1) as f32,
            pixels,
        });
    }

    for column in 0..columns {
        for bin in 0..bins {
            let db = magnitudes[column * bins + bin] - peak;
            let level = ((db - FLOOR_DB) / -FLOOR_DB).clamp(0.0, 1.0);
            // Row 0 is the top of the image, and the top is the highest bin.
            let row = bins - 1 - bin;
            pixels[row * columns + column] = (level * 255.0).round() as u8;
        }
    }

    Some(Spectrogram {
        width: columns,
        height: bins,
        window,
        hop,
        max_frequency: sample_rate as f32 / 2.0,
        seconds: samples.len() as f32 / sample_rate.max(1) as f32,
        pixels,
    })
}

/// Dimensions and axis labels. The pixels travel alongside rather than inside,
/// since base64 of a megabyte of grayscale would cost more than the transform.
pub fn json(spec: &Spectrogram) -> String {
    use crate::json::{push_number, push_string};

    let mut out = String::from("{");
    push_number(&mut out, "width", spec.width);
    out.push(',');
    push_number(&mut out, "height", spec.height);
    out.push(',');
    push_number(&mut out, "window", spec.window);
    out.push(',');
    push_number(&mut out, "hop", spec.hop);
    out.push(',');
    push_string(&mut out, "maxFrequency");
    out.push_str(&format!(":{:.1}", spec.max_frequency));
    out.push(',');
    push_string(&mut out, "seconds");
    out.push_str(&format!(":{:.3}", spec.seconds));
    out.push('}');
    out
}

#[cfg(test)]
mod tests;
