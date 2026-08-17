//! Cuttlefish — steganography. Operates on decoded RGBA, never on file bytes.

use crate::bytes;

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

fn assess(stream: &[u8]) -> Option<(String, String)> {
    if let Some(format) = bytes::identify(stream) {
        return Some((
            format!("{format} signature at offset 0"),
            String::from_utf8_lossy(&stream[..stream.len().min(48)])
                .chars()
                .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '.' })
                .collect(),
        ));
    }

    let (start, run) = bytes::longest_printable_run(stream);
    let long_enough = run >= MIN_RUN_ANYWHERE || (start == 0 && run >= MIN_RUN_AT_START);
    if !long_enough {
        return None;
    }

    if bytes::distinct_bytes(&stream[start..start + run]) < MIN_DISTINCT {
        return None;
    }

    let preview: String = String::from_utf8_lossy(&stream[start..start + run.min(96)]).into_owned();
    let where_ = if start == 0 {
        "text at offset 0".to_string()
    } else {
        format!("printable run of {run} at offset {start}")
    };

    Some((where_, preview))
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

                let (reason, preview) = assessed.unwrap_or_else(|| {
                    ("flag-shaped string in the extracted stream".to_string(), flags.join("  "))
                });

                out.push(Candidate {
                    params: Params {
                        channels: label,
                        bit,
                        msb_first,
                    },
                    reason,
                    preview,
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
