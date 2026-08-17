//! Cuttlefish — steganography. Operates on decoded RGBA, never on file bytes.

use crate::bytes;

pub mod chi;
pub mod rs;

/// Channel orders worth sweeping. Index into an RGBA pixel.
pub const CHANNEL_SETS: [(&str, &[usize]); 7] = [
    ("rgb", &[0, 1, 2]),
    ("bgr", &[2, 1, 0]),
    ("r", &[0]),
    ("g", &[1]),
    ("b", &[2]),
    ("rgba", &[0, 1, 2, 3]),
    ("a", &[3]),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub channels: &'static str,
    pub bit: u8,
    pub msb_first: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub params: Params,
    pub reason: String,
    pub preview: String,
    /// Length of the readable run, so the caller can tell when the preview
    /// stopped short of it rather than presenting a clipped message as whole.
    pub readable: usize,
    pub flags: Vec<String>,
    pub bytes_read: usize,
}

fn channel_indices(name: &str) -> Option<&'static [usize]> {
    CHANNEL_SETS
        .iter()
        .find(|(label, _)| *label == name)
        .map(|(_, idx)| *idx)
}

/// Reads one bit plane out of the chosen channels, in pixel order, packing bits
/// into bytes. This is the operation `zsteg -a` brute-forces; the parameters are
/// the search space.
///
/// @param rgba four bytes per pixel, exactly as decoded
/// @param max_bytes stop here, so a sweep stays cheap on a 12-megapixel image
pub fn extract(
    rgba: &[u8],
    channels: &[usize],
    bit: u8,
    msb_first: bool,
    max_bytes: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(max_bytes.min(1 << 16));
    let mut acc = 0u8;
    let mut filled = 0u8;

    for pixel in rgba.chunks_exact(4) {
        for &c in channels {
            let value = (pixel[c] >> bit) & 1;
            if msb_first {
                acc = (acc << 1) | value;
            } else {
                acc |= value << filled;
            }
            filled += 1;

            if filled == 8 {
                out.push(acc);
                acc = 0;
                filled = 0;
                if out.len() >= max_bytes {
                    return out;
                }
            }
        }
    }

    out
}

/// Thresholds are chosen so random data clears them roughly once per fifty
/// sweeps, not once per sweep. A detector that fires on noise is worse than none.
const MIN_RUN_ANYWHERE: usize = 16;
const MIN_RUN_AT_START: usize = 8;

/// Length alone is not enough. A smooth gradient's upper bit planes extract as a
/// long printable run of one repeated character, which is structure rather than a
/// payload. Real text carries variety.
const MIN_DISTINCT: usize = 6;

/// How much of a readable run the sweep quotes. The full stream is available
/// through `extract_named`; this is the summary, and the UI says when it clipped.
const PREVIEW_LIMIT: usize = 512;

fn assess(stream: &[u8]) -> Option<(String, String, usize)> {
    if let Some(format) = bytes::identify(stream) {
        let preview: String = String::from_utf8_lossy(&stream[..stream.len().min(48)])
            .chars()
            .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '.' })
            .collect();
        let shown = preview.chars().count();
        return Some((format!("{format} signature at offset 0"), preview, shown));
    }

    let (start, run) = bytes::longest_printable_run(stream);
    let long_enough = run >= MIN_RUN_ANYWHERE || (start == 0 && run >= MIN_RUN_AT_START);
    if !long_enough {
        return None;
    }

    if bytes::distinct_bytes(&stream[start..start + run]) < MIN_DISTINCT {
        return None;
    }

    let preview: String =
        String::from_utf8_lossy(&stream[start..start + run.min(PREVIEW_LIMIT)]).into_owned();
    let where_ = if start == 0 {
        format!("text at offset 0, {run} characters")
    } else {
        format!("printable run of {run} at offset {start}")
    };

    Some((where_, preview, run))
}

/// Sweeps the parameter space and reports only combinations that produced
/// something a clean image would not.
///
/// @param has_alpha skip alpha combinations when the source had no alpha channel,
///        since a synthesised 255 gives a constant plane and pure noise findings
pub fn sweep(rgba: &[u8], has_alpha: bool, max_bytes: usize) -> Vec<Candidate> {
    let mut out = Vec::new();

    for (label, channels) in CHANNEL_SETS {
        if !has_alpha && channels.contains(&3) {
            continue;
        }

        for bit in 0..3u8 {
            for msb_first in [true, false] {
                let stream = extract(rgba, channels, bit, msb_first, max_bytes);

                let flags: Vec<String> = bytes::flag_candidates(&stream)
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
                    params: Params {
                        channels: label,
                        bit,
                        msb_first,
                    },
                    reason,
                    preview,
                    readable,
                    flags,
                    bytes_read: stream.len(),
                });
            }
        }
    }

    out
}

/// Sweep results as JSON, ready to leave the worker.
pub fn sweep_json(rgba: &[u8], has_alpha: bool, max_bytes: usize) -> String {
    use crate::json::{push_bool, push_field, push_number, push_string};

    let found = sweep(rgba, has_alpha, max_bytes);
    let mut out = String::from("{");

    push_number(&mut out, "pixels", rgba.len() / 4);
    out.push(',');
    push_number(&mut out, "combinations", combination_count(has_alpha));
    out.push(',');
    push_string(&mut out, "candidates");
    out.push_str(":[");

    for (i, candidate) in found.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "channels", candidate.params.channels);
        out.push(',');
        push_number(&mut out, "bit", candidate.params.bit as usize);
        out.push(',');
        push_bool(&mut out, "msbFirst", candidate.params.msb_first);
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

pub fn combination_count(has_alpha: bool) -> usize {
    let sets = CHANNEL_SETS
        .iter()
        .filter(|(_, ch)| has_alpha || !ch.contains(&3))
        .count();
    sets * 3 * 2
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PlaneStat {
    pub channel: usize,
    pub bit: u8,
    /// Fraction of adjacent pairs, horizontally and vertically, whose bit differs.
    /// Near 0.5 is indistinguishable from noise; near 0 means the plane carries
    /// image structure.
    ///
    /// Reported, never judged. A fine gradient flips bit 1 on almost every step,
    /// so a high rate in an upper plane is ordinary rather than suspicious, and
    /// any threshold that called it suspicious would be invented rather than
    /// derived. Chi-square and RS are the detectors that get to make claims.
    pub transition_rate: f32,
}

/// One bit plane of one channel as 0 or 255 per pixel, at full resolution.
pub fn plane_full(rgba: &[u8], channel: usize, bit: u8) -> Vec<u8> {
    rgba.chunks_exact(4)
        .map(|p| if (p[channel] >> bit) & 1 == 1 { 255 } else { 0 })
        .collect()
}

/// Every plane downsampled for the wall, plus the statistics that rank them.
///
/// One pass over the image fills every plane's accumulator at once, because
/// thirty-two separate passes over a twelve-megapixel buffer is thirty-two times
/// the memory traffic for the same arithmetic.
///
/// Returns the stats as JSON and the thumbnails as one grayscale block, ordered
/// channel-major then bit ascending.
pub fn plane_wall(
    rgba: &[u8],
    width: usize,
    height: usize,
    channels: usize,
    target_width: usize,
) -> (String, usize, usize, Vec<u8>) {
    let tw = target_width.clamp(1, width);
    let th = (height * tw / width).max(1);
    let cells = tw * th;
    let planes = channels * 8;

    let mut sums = vec![0u32; planes * cells];
    let mut counts = vec![0u32; cells];
    let mut transitions = vec![0u64; planes];
    // Vertical neighbours matter as much as horizontal: a vertical gradient shows
    // zero horizontal change, which would report every one of its planes as flat.
    let mut previous_row = vec![0u8; width * channels];

    for y in 0..height {
        let ty = (y * th / height).min(th - 1);
        let mut previous = [0u8; 4];

        for x in 0..width {
            let tx = (x * tw / width).min(tw - 1);
            let cell = ty * tw + tx;
            counts[cell] += 1;

            let pixel = &rgba[(y * width + x) * 4..(y * width + x) * 4 + 4];

            for c in 0..channels {
                let value = pixel[c];
                let above = previous_row[x * channels + c];

                for bit in 0..8usize {
                    let set = (value >> bit) & 1;
                    sums[(c * 8 + bit) * cells + cell] += set as u32;
                    if x > 0 && ((previous[c] >> bit) & 1) != set {
                        transitions[c * 8 + bit] += 1;
                    }
                    if y > 0 && ((above >> bit) & 1) != set {
                        transitions[c * 8 + bit] += 1;
                    }
                }

                previous[c] = value;
                previous_row[x * channels + c] = value;
            }
        }
    }

    let mut thumbnails = vec![0u8; planes * cells];
    for plane in 0..planes {
        for cell in 0..cells {
            let count = counts[cell].max(1);
            thumbnails[plane * cells + cell] = ((sums[plane * cells + cell] * 255) / count) as u8;
        }
    }

    let pairs =
        (width.saturating_sub(1) * height + width * height.saturating_sub(1)).max(1) as f32;
    let stats: Vec<PlaneStat> = (0..planes)
        .map(|p| PlaneStat {
            channel: p / 8,
            bit: (p % 8) as u8,
            transition_rate: transitions[p] as f32 / pairs,
        })
        .collect();

    (stats_json(&stats, tw, th, channels), tw, th, thumbnails)
}

fn stats_json(stats: &[PlaneStat], tw: usize, th: usize, channels: usize) -> String {
    use crate::json::{push_number, push_string};

    let mut out = String::from("{");
    push_number(&mut out, "thumbWidth", tw);
    out.push(',');
    push_number(&mut out, "thumbHeight", th);
    out.push(',');
    push_number(&mut out, "channels", channels);
    out.push(',');
    push_string(&mut out, "planes");
    out.push_str(":[");

    for (i, stat) in stats.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_number(&mut out, "channel", stat.channel);
        out.push(',');
        push_number(&mut out, "bit", stat.bit as usize);
        out.push(',');
        push_string(&mut out, "transitionRate");
        out.push(':');
        out.push_str(&format!("{:.4}", stat.transition_rate));
        out.push('}');
    }

    out.push_str("]}");
    out
}

/// Sample values in the order a sequential embedder walks them.
///
/// Alpha is excluded on purpose. It is constant on most images, and a single
/// value holding every count would dominate the histogram and drown the channels
/// that carry the picture.
pub fn traversal_samples(rgba: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rgba.len() / 4 * 3);
    for pixel in rgba.chunks_exact(4) {
        out.extend_from_slice(&pixel[..3]);
    }
    out
}

/// The chi-square sweep as JSON, ready to leave the worker.
pub fn chi_square_json(rgba: &[u8], steps: usize) -> String {
    use crate::json::{push_bool, push_number, push_string};

    let samples = traversal_samples(rgba);
    let points = chi::sweep(&samples, steps);
    let result = chi::verdict(&points);

    let mut out = String::from("{");
    push_bool(&mut out, "detected", result.detected);
    out.push(',');
    push_string(&mut out, "embeddedFraction");
    out.push(':');
    out.push_str(&format!("{:.4}", result.embedded_fraction));
    out.push(',');
    push_string(&mut out, "peakProbability");
    out.push(':');
    out.push_str(&format!("{:.4}", result.peak_probability));
    out.push(',');
    push_number(&mut out, "samples", samples.len());
    out.push(',');
    push_string(&mut out, "points");
    out.push_str(":[");

    for (i, point) in points.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_string(&mut out, "fraction");
        out.push(':');
        out.push_str(&format!("{:.4}", point.fraction));
        out.push(',');
        push_string(&mut out, "p");
        out.push(':');
        out.push_str(&format!("{:.4}", point.p_embedding));
        out.push(',');
        push_string(&mut out, "chiSquare");
        out.push(':');
        out.push_str(&format!("{:.2}", point.chi_square));
        out.push(',');
        push_number(&mut out, "degrees", point.degrees);
        out.push('}');
    }

    out.push_str("]}");
    out
}

/// Full extraction for one combination, once the user has picked it.
pub fn extract_named(
    rgba: &[u8],
    channels: &str,
    bit: u8,
    msb_first: bool,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    channel_indices(channels).map(|idx| extract(rgba, idx, bit, msb_first, max_bytes))
}

#[cfg(test)]
mod tests;
