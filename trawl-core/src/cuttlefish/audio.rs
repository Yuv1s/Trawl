//! The LSB sweep, pointed at samples instead of pixels.
//!
//! An audio sample is a number the same way a colour channel is, so the attack
//! is the same one: take one bit from each, pack them into bytes, see whether
//! anything readable falls out. Only the traversal differs, since a waveform has
//! no second axis to walk down.
//!
//! Judgement is deliberately shared with the image sweep. Two copies of "is this
//! a payload" would drift, and the whole project rests on not claiming a find
//! the tool cannot check.

use super::assess;
use crate::bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    /// None reads every channel interleaved, as stored.
    pub channel: Option<usize>,
    pub label: String,
    pub bit: u8,
    pub msb_first: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub params: Params,
    pub reason: String,
    pub preview: String,
    pub readable: usize,
    pub flags: Vec<String>,
    pub bytes_read: usize,
}

/// Which channel selections are worth trying for a given channel count.
///
/// On a mono file "every channel" and "channel 0" are the same read, so listing
/// both would double the reported search space without searching anything.
pub fn channel_sets(channels: usize) -> Vec<(Option<usize>, String)> {
    if channels <= 1 {
        return vec![(None, "mono".to_string())];
    }

    let name = |c: usize| match (channels, c) {
        (2, 0) => "left".to_string(),
        (2, 1) => "right".to_string(),
        _ => format!("channel {}", c + 1),
    };

    let mut out = vec![(None, "all channels".to_string())];
    out.extend((0..channels).map(|c| (Some(c), name(c))));
    out
}

/// Packs one bit plane of the samples into bytes.
///
/// @param samples interleaved, as `wav::integer_samples` returns them
/// @param channel None for every sample, or one channel of an interleaved stream
pub fn extract(
    samples: &[i32],
    channels: usize,
    channel: Option<usize>,
    bit: u8,
    msb_first: bool,
    max_bytes: usize,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut byte = 0u8;
    let mut filled = 0u8;

    let step = if channel.is_some() { channels } else { 1 };
    let start = channel.unwrap_or(0);

    for value in samples.iter().skip(start).step_by(step.max(1)) {
        // Two's complement means bit 0 of a negative sample is still bit 0.
        let b = ((*value as u32) >> bit) & 1;

        byte = if msb_first {
            (byte << 1) | b as u8
        } else {
            byte | ((b as u8) << filled)
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

pub fn sweep(samples: &[i32], channels: usize, max_bytes: usize) -> Vec<Candidate> {
    let mut out = Vec::new();

    for (channel, label) in channel_sets(channels) {
        for bit in 0..3u8 {
            for msb_first in [true, false] {
                let stream = extract(samples, channels, channel, bit, msb_first, max_bytes);

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
                        channel,
                        label: label.clone(),
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

/// Channel selections, times three bit planes, times two bit orders.
pub fn combination_count(channels: usize) -> usize {
    channel_sets(channels).len() * 3 * 2
}

pub fn sweep_json(samples: &[i32], channels: usize, max_bytes: usize) -> String {
    use crate::json::{push_bool, push_field, push_number, push_string};

    let found = sweep(samples, channels, max_bytes);
    let mut out = String::from("{");

    push_number(&mut out, "samples", samples.len());
    out.push(',');
    push_number(&mut out, "combinations", combination_count(channels));
    out.push(',');
    push_string(&mut out, "candidates");
    out.push_str(":[");

    for (i, candidate) in found.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "channels", &candidate.params.label);
        out.push(',');
        push_string(&mut out, "channelIndex");
        match candidate.params.channel {
            Some(c) => out.push_str(&format!(":{c}")),
            None => out.push_str(":null"),
        }
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

#[cfg(test)]
mod tests;
