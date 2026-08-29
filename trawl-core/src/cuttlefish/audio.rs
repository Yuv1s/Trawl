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

#[derive(Debug, Clone, PartialEq)]
pub struct ToneFinding {
    pub kind: &'static str,
    pub decoded: String,
    pub confidence: f32,
    pub units: usize,
}

fn mono(samples: &[i32], channels: usize) -> Vec<f32> {
    if channels == 0 {
        return Vec::new();
    }

    samples
        .chunks(channels)
        .map(|frame| frame.iter().map(|&v| v as f64).sum::<f64>() as f32 / frame.len() as f32)
        .collect()
}

fn goertzel(samples: &[f32], sample_rate: u32, frequency: f32) -> f64 {
    if samples.is_empty() || sample_rate == 0 {
        return 0.0;
    }

    let omega = 2.0 * core::f64::consts::PI * frequency as f64 / sample_rate as f64;
    let coeff = 2.0 * omega.cos();
    let mut one = 0.0f64;
    let mut two = 0.0f64;
    for &sample in samples {
        let next = sample as f64 + coeff * one - two;
        two = one;
        one = next;
    }
    (one * one + two * two - coeff * one * two).max(0.0)
}

fn strongest(samples: &[f32], sample_rate: u32, frequencies: &[f32]) -> (usize, f64, f64) {
    let mut ranked: Vec<(usize, f64)> = frequencies
        .iter()
        .enumerate()
        .map(|(i, &frequency)| (i, goertzel(samples, sample_rate, frequency)))
        .collect();
    ranked.sort_by(|a, b| b.1.total_cmp(&a.1));
    let first = ranked.first().copied().unwrap_or((0, 0.0));
    (first.0, first.1, ranked.get(1).map_or(0.0, |value| value.1))
}

pub fn detect_dtmf(samples: &[i32], channels: usize, sample_rate: u32) -> Option<ToneFinding> {
    const LOW: [f32; 4] = [697.0, 770.0, 852.0, 941.0];
    const HIGH: [f32; 4] = [1209.0, 1336.0, 1477.0, 1633.0];
    const KEYS: [[char; 4]; 4] = [
        ['1', '2', '3', 'A'],
        ['4', '5', '6', 'B'],
        ['7', '8', '9', 'C'],
        ['*', '0', '#', 'D'],
    ];

    let signal = mono(samples, channels);
    let window = ((sample_rate as usize * 40) / 1000).max(64);
    let hop = window / 2;
    if signal.len() < window || hop == 0 {
        return None;
    }

    let mut frames = Vec::new();
    for frame in signal.windows(window).step_by(hop) {
        let rms = (frame.iter().map(|v| (*v as f64) * (*v as f64)).sum::<f64>()
            / frame.len() as f64)
            .sqrt();
        if rms < 64.0 {
            frames.push(None);
            continue;
        }

        let (low, low_power, low_next) = strongest(frame, sample_rate, &LOW);
        let (high, high_power, high_next) = strongest(frame, sample_rate, &HIGH);
        let clean = low_power > low_next * 3.0 && high_power > high_next * 3.0;
        frames.push(clean.then_some(KEYS[low][high]));
    }

    let mut decoded = String::new();
    let mut at = 0;
    let mut accepted = 0usize;
    while at < frames.len() {
        let value = frames[at];
        let mut end = at + 1;
        while end < frames.len() && frames[end] == value {
            end += 1;
        }
        if let Some(key) = value
            && end - at >= 2
            && !decoded.ends_with(key)
        {
            decoded.push(key);
            accepted += end - at;
        }
        at = end;
    }

    (!decoded.is_empty()).then_some(ToneFinding {
        kind: "DTMF",
        decoded,
        confidence: accepted as f32 / frames.len().max(1) as f32,
        units: frames.len(),
    })
}

fn morse_char(code: &str) -> Option<char> {
    Some(match code {
        ".-" => 'A', "-..." => 'B', "-.-." => 'C', "-.." => 'D', "." => 'E',
        "..-." => 'F', "--." => 'G', "...." => 'H', ".." => 'I', ".---" => 'J',
        "-.-" => 'K', ".-.." => 'L', "--" => 'M', "-." => 'N', "---" => 'O',
        ".--." => 'P', "--.-" => 'Q', ".-." => 'R', "..." => 'S', "-" => 'T',
        "..-" => 'U', "...-" => 'V', ".--" => 'W', "-..-" => 'X', "-.--" => 'Y',
        "--.." => 'Z', ".----" => '1', "..---" => '2', "...--" => '3', "....-" => '4',
        "....." => '5', "-...." => '6', "--..." => '7', "---.." => '8', "----." => '9',
        "-----" => '0', _ => return None,
    })
}

pub fn detect_morse(samples: &[i32], channels: usize, sample_rate: u32) -> Option<ToneFinding> {
    let signal = mono(samples, channels);
    let window = ((sample_rate as usize * 10) / 1000).max(32);
    let hop = window;
    if signal.len() < window * 8 || hop == 0 {
        return None;
    }

    let rms: Vec<f64> = signal
        .chunks(window)
        .map(|frame| {
            (frame.iter().map(|v| (*v as f64) * (*v as f64)).sum::<f64>()
                / frame.len().max(1) as f64)
                .sqrt()
        })
        .collect();
    let peak = rms.iter().copied().fold(0.0f64, f64::max);
    if peak < 64.0 {
        return None;
    }
    let threshold = peak * 0.25;
    let states: Vec<bool> = rms.iter().map(|&value| value >= threshold).collect();

    let mut runs = Vec::new();
    let mut at = 0;
    while at < states.len() {
        let on = states[at];
        let mut end = at + 1;
        while end < states.len() && states[end] == on {
            end += 1;
        }
        runs.push((on, end - at));
        at = end;
    }
    let shortest = runs.iter().filter(|(on, _)| *on).map(|(_, len)| *len).min()?;
    if shortest == 0 {
        return None;
    }

    let mut decoded = String::new();
    let mut code = String::new();
    let mut valid = 0usize;
    for (on, length) in runs {
        let units = (length as f32 / shortest as f32).round() as usize;
        if on {
            code.push(if units >= 2 { '-' } else { '.' });
            continue;
        }
        if units >= 3 && !code.is_empty() {
            if let Some(letter) = morse_char(&code) {
                decoded.push(letter);
                valid += 1;
            } else {
                decoded.push('?');
            }
            code.clear();
        }
        if units >= 6 && !decoded.ends_with(' ') {
            decoded.push(' ');
        }
    }
    if !code.is_empty() {
        if let Some(letter) = morse_char(&code) {
            decoded.push(letter);
            valid += 1;
        }
    }
    let letters = decoded.chars().filter(|c| !c.is_whitespace()).count();
    (letters >= 2 && valid * 4 >= letters * 3).then_some(ToneFinding {
        kind: "Morse",
        decoded,
        confidence: valid as f32 / letters.max(1) as f32,
        units: rms.len(),
    })
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

pub fn sweep_json(samples: &[i32], channels: usize, sample_rate: u32, max_bytes: usize) -> String {
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

    out.push_str("],");
    push_string(&mut out, "tones");
    out.push_str(":[");
    let tones: Vec<ToneFinding> = [
        detect_morse(samples, channels, sample_rate),
        detect_dtmf(samples, channels, sample_rate),
    ]
    .into_iter()
    .flatten()
    .collect();
    for (i, tone) in tones.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "kind", tone.kind);
        out.push(',');
        push_field(&mut out, "decoded", &tone.decoded);
        out.push(',');
        push_string(&mut out, "confidence");
        out.push_str(&format!(":{:.4}", tone.confidence));
        out.push(',');
        push_number(&mut out, "units", tone.units);
        out.push('}');
    }
    out.push_str("]}");
    out
}

#[cfg(test)]
mod tests;
