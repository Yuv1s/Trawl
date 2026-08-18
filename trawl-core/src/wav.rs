//! RIFF/WAVE parsing and sample decoding.
//!
//! WAV is the audio equivalent of BMP: uncompressed samples with a header on
//! front, so anything written into the low bits survives the round trip. That
//! makes it the format audio stego challenges are almost always built on.
//!
//! The container is a chunk list, which means it has the same two hiding places
//! PNG has. Chunks the player does not recognise get skipped rather than
//! rejected, and anything past the size the RIFF header declares is never read
//! at all.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WavError {
    NotWav,
    Truncated,
    NoFormat,
    NoData,
    UnsupportedDepth(u16),
    UnsupportedFormat(u16),
    FloatSamples,
    ZeroChannels,
}

impl fmt::Display for WavError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotWav => write!(f, "not a WAV: no RIFF/WAVE signature"),
            Self::Truncated => write!(f, "a chunk header runs past the end of the file"),
            Self::NoFormat => write!(f, "no fmt chunk, so the samples cannot be read"),
            Self::NoData => write!(f, "no data chunk"),
            Self::UnsupportedDepth(bits) => write!(f, "unsupported sample depth {bits}"),
            Self::UnsupportedFormat(tag) => write!(
                f,
                "audio format {tag} is compressed; only uncompressed PCM decodes"
            ),
            Self::FloatSamples => write!(
                f,
                "floating-point samples have no meaningful low bit to read"
            ),
            Self::ZeroChannels => write!(f, "the header declares zero channels"),
        }
    }
}

pub const PCM: u16 = 1;
pub const IEEE_FLOAT: u16 = 3;
const EXTENSIBLE: u16 = 0xfffe;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Format {
    /// 1 for PCM, 3 for float, after any WAVE_FORMAT_EXTENSIBLE unwrapping.
    pub tag: u16,
    pub channels: usize,
    pub sample_rate: u32,
    pub bits_per_sample: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiffChunk {
    pub id: String,
    /// Offset of the four-byte id, not of the payload.
    pub offset: usize,
    pub length: usize,
    /// False when the declared length ran past the end of the file.
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wav {
    pub format: Format,
    pub chunks: Vec<RiffChunk>,
    pub data_offset: usize,
    pub data_length: usize,
    pub frames: usize,
    /// Bytes past the end the RIFF header declares, which a player never reads.
    pub trailing: Option<(usize, usize)>,
}

impl Wav {
    pub fn duration_seconds(&self) -> f32 {
        if self.format.sample_rate == 0 {
            return 0.0;
        }
        self.frames as f32 / self.format.sample_rate as f32
    }
}

pub fn has_signature(file: &[u8]) -> bool {
    file.len() >= 12 && &file[0..4] == b"RIFF" && &file[8..12] == b"WAVE"
}

fn u16_at(file: &[u8], at: usize) -> Option<u16> {
    let b = file.get(at..at + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(file: &[u8], at: usize) -> Option<u32> {
    let b = file.get(at..at + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Walks the chunk list without interpreting any of it.
///
/// Kept separate from `parse` so a file with a broken fmt chunk still gets a
/// chunk listing, which is usually where the interesting part is anyway.
pub fn chunks(file: &[u8]) -> Result<Vec<RiffChunk>, WavError> {
    if !has_signature(file) {
        return Err(WavError::NotWav);
    }

    let declared_end = 8 + u32_at(file, 4).ok_or(WavError::Truncated)? as usize;

    let mut out = Vec::new();
    let mut at = 12;

    while at + 8 <= file.len() {
        let raw = &file[at..at + 4];
        let id: String = raw
            .iter()
            // The space in "fmt " is part of the id, so graphic alone is too strict.
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        let length = u32_at(file, at + 4).ok_or(WavError::Truncated)? as usize;
        let complete = at + 8 + length <= file.len();

        // Past the size the header declares, keep walking only while what is
        // there still parses as a chunk. Some writers get the RIFF size wrong
        // and leave real chunks beyond it, which is worth reading; appended
        // payload is not, and listing it as a chunk with a nonsense length says
        // something about the file that is not true.
        if at >= declared_end && !(complete && raw.iter().all(|b| b.is_ascii_graphic() || *b == b' '))
        {
            break;
        }

        out.push(RiffChunk {
            id,
            offset: at,
            length,
            complete,
        });

        if !complete {
            break;
        }

        // RIFF pads odd-length payloads to an even boundary.
        at += 8 + length + (length & 1);
    }

    Ok(out)
}

fn read_format(file: &[u8], chunk: &RiffChunk) -> Result<Format, WavError> {
    let at = chunk.offset + 8;
    if chunk.length < 16 {
        return Err(WavError::NoFormat);
    }

    let mut tag = u16_at(file, at).ok_or(WavError::Truncated)?;
    let channels = u16_at(file, at + 2).ok_or(WavError::Truncated)? as usize;
    let sample_rate = u32_at(file, at + 4).ok_or(WavError::Truncated)?;
    let bits_per_sample = u16_at(file, at + 14).ok_or(WavError::Truncated)?;

    // WAVE_FORMAT_EXTENSIBLE keeps the real tag in the first two bytes of the
    // SubFormat GUID, 24 bytes into the fmt payload.
    if tag == EXTENSIBLE && chunk.length >= 40 {
        tag = u16_at(file, at + 24).ok_or(WavError::Truncated)?;
    }

    if channels == 0 {
        return Err(WavError::ZeroChannels);
    }

    Ok(Format {
        tag,
        channels,
        sample_rate,
        bits_per_sample,
    })
}

pub fn parse(file: &[u8]) -> Result<Wav, WavError> {
    let chunks = chunks(file)?;

    let fmt = chunks
        .iter()
        .find(|c| c.id == "fmt ")
        .ok_or(WavError::NoFormat)?;
    let format = read_format(file, fmt)?;

    if format.tag != PCM && format.tag != IEEE_FLOAT {
        return Err(WavError::UnsupportedFormat(format.tag));
    }

    let data = chunks
        .iter()
        .find(|c| c.id == "data")
        .ok_or(WavError::NoData)?;

    let data_offset = data.offset + 8;
    // Streamed files write 0 or 0xffffffff for the data length and let the
    // reader work it out, so the file itself is the authority.
    let data_length = data.length.min(file.len().saturating_sub(data_offset));

    let bytes_per_sample = (format.bits_per_sample as usize).div_ceil(8);
    if bytes_per_sample == 0 {
        return Err(WavError::UnsupportedDepth(format.bits_per_sample));
    }
    let frames = data_length / (bytes_per_sample * format.channels);

    let declared_end = 8 + u32_at(file, 4).ok_or(WavError::Truncated)? as usize;
    let trailing = if declared_end < file.len() {
        Some((declared_end, file.len() - declared_end))
    } else {
        None
    };

    Ok(Wav {
        format,
        chunks,
        data_offset,
        data_length,
        frames,
        trailing,
    })
}

/// Sample values exactly as stored, interleaved by channel.
///
/// Returned at native scale rather than normalised, because the whole point of
/// reading a WAV for stego is bit 0 of the stored integer. Rescaling would move
/// it.
pub fn integer_samples(file: &[u8], wav: &Wav) -> Result<Vec<i32>, WavError> {
    if wav.format.tag == IEEE_FLOAT {
        return Err(WavError::FloatSamples);
    }

    let width = (wav.format.bits_per_sample as usize).div_ceil(8);
    let count = wav.frames * wav.format.channels;
    let mut out = Vec::with_capacity(count);

    for i in 0..count {
        let at = wav.data_offset + i * width;
        let b = file.get(at..at + width).ok_or(WavError::Truncated)?;

        let value = match wav.format.bits_per_sample {
            // 8-bit WAV is unsigned with 128 as silence, unlike every other depth.
            8 => b[0] as i32 - 128,
            16 => i16::from_le_bytes([b[0], b[1]]) as i32,
            24 => i32::from_le_bytes([0, b[0], b[1], b[2]]) >> 8,
            32 => i32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            other => return Err(WavError::UnsupportedDepth(other)),
        };

        out.push(value);
    }

    Ok(out)
}

/// Every channel averaged into one track, scaled to roughly -1.0 to 1.0.
///
/// The spectrogram wants amplitude rather than stored bits, and a hidden picture
/// is drawn across all channels, so mixing down loses nothing and halves the
/// work on a stereo file.
pub fn mono(file: &[u8], wav: &Wav) -> Result<Vec<f32>, WavError> {
    let channels = wav.format.channels;
    let width = (wav.format.bits_per_sample as usize).div_ceil(8);
    let mut out = Vec::with_capacity(wav.frames);

    if wav.format.tag == IEEE_FLOAT {
        if wav.format.bits_per_sample != 32 {
            return Err(WavError::UnsupportedDepth(wav.format.bits_per_sample));
        }

        for frame in 0..wav.frames {
            let mut sum = 0.0f32;
            for c in 0..channels {
                let at = wav.data_offset + (frame * channels + c) * 4;
                let b = file.get(at..at + 4).ok_or(WavError::Truncated)?;
                sum += f32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            }
            out.push(sum / channels as f32);
        }

        return Ok(out);
    }

    let full_scale = match wav.format.bits_per_sample {
        8 => 128.0,
        16 => 32768.0,
        24 => 8_388_608.0,
        32 => 2_147_483_648.0,
        other => return Err(WavError::UnsupportedDepth(other)),
    };

    for frame in 0..wav.frames {
        let mut sum = 0.0f32;
        for c in 0..channels {
            let at = wav.data_offset + (frame * channels + c) * width;
            let b = file.get(at..at + width).ok_or(WavError::Truncated)?;
            let value = match wav.format.bits_per_sample {
                8 => b[0] as i32 - 128,
                16 => i16::from_le_bytes([b[0], b[1]]) as i32,
                24 => i32::from_le_bytes([0, b[0], b[1], b[2]]) >> 8,
                32 => i32::from_le_bytes([b[0], b[1], b[2], b[3]]),
                other => return Err(WavError::UnsupportedDepth(other)),
            };
            sum += value as f32 / full_scale;
        }
        out.push(sum / channels as f32);
    }

    Ok(out)
}

/// Text inside chunks a player skips: LIST/INFO tags, and anything unrecognised.
///
/// A comment in an unknown chunk is the audio version of a PNG tEXt, and it is
/// where a surprising number of challenges put the flag.
pub fn chunk_text(file: &[u8], wav: &Wav) -> Vec<(String, usize, String)> {
    let mut out = Vec::new();

    for chunk in &wav.chunks {
        if chunk.id == "data" || chunk.id == "fmt " || !chunk.complete {
            continue;
        }

        let at = chunk.offset + 8;
        let Some(payload) = file.get(at..at + chunk.length) else {
            continue;
        };

        for found in crate::bytes::ascii_strings(payload, 4) {
            out.push((chunk.id.clone(), at + found.offset, found.text));
        }
    }

    out
}

fn format_name(tag: u16, bits: u16) -> String {
    match tag {
        PCM => format!("{bits}-bit PCM"),
        IEEE_FLOAT => format!("{bits}-bit float"),
        other => format!("format {other}"),
    }
}

/// The whole walk as JSON, or `null` when the file is not a WAV at all.
///
/// A parse failure past the signature still returns an object carrying the
/// reason, because "this is a WAV and here is what is wrong with it" is worth
/// more to someone working a challenge than a blank panel.
pub fn structure_json(file: &[u8]) -> String {
    use crate::json::{push_bool, push_field, push_number, push_string};

    if !has_signature(file) {
        return "null".to_string();
    }

    let mut out = String::from("{");

    let parsed = match parse(file) {
        Ok(wav) => wav,
        Err(e) => {
            push_field(&mut out, "error", &e.to_string());
            out.push(',');
            push_string(&mut out, "chunks");
            out.push_str(":[");
            for (i, chunk) in chunks(file).unwrap_or_default().iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('{');
                push_field(&mut out, "id", &chunk.id);
                out.push(',');
                push_number(&mut out, "offset", chunk.offset);
                out.push(',');
                push_number(&mut out, "length", chunk.length);
                out.push(',');
                push_bool(&mut out, "complete", chunk.complete);
                out.push('}');
            }
            out.push_str("]}");
            return out;
        }
    };

    push_field(
        &mut out,
        "encoding",
        &format_name(parsed.format.tag, parsed.format.bits_per_sample),
    );
    out.push(',');
    push_number(&mut out, "channels", parsed.format.channels);
    out.push(',');
    push_number(&mut out, "sampleRate", parsed.format.sample_rate as usize);
    out.push(',');
    push_number(
        &mut out,
        "bitsPerSample",
        parsed.format.bits_per_sample as usize,
    );
    out.push(',');
    push_number(&mut out, "frames", parsed.frames);
    out.push(',');
    push_string(&mut out, "seconds");
    out.push_str(&format!(":{:.3}", parsed.duration_seconds()));
    out.push(',');
    push_number(&mut out, "dataOffset", parsed.data_offset);
    out.push(',');
    push_number(&mut out, "dataLength", parsed.data_length);
    out.push(',');

    push_string(&mut out, "chunks");
    out.push_str(":[");
    for (i, chunk) in parsed.chunks.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "id", &chunk.id);
        out.push(',');
        push_number(&mut out, "offset", chunk.offset);
        out.push(',');
        push_number(&mut out, "length", chunk.length);
        out.push(',');
        push_bool(&mut out, "complete", chunk.complete);
        out.push('}');
    }
    out.push_str("],");

    push_string(&mut out, "text");
    out.push_str(":[");
    for (i, (id, offset, text)) in chunk_text(file, &parsed).iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "chunk", id);
        out.push(',');
        push_number(&mut out, "offset", *offset);
        out.push(',');
        push_field(&mut out, "text", text);
        out.push('}');
    }
    out.push_str("],");

    push_string(&mut out, "trailing");
    match parsed.trailing {
        Some((offset, length)) => {
            out.push_str(":{");
            push_number(&mut out, "offset", offset);
            out.push(',');
            push_number(&mut out, "length", length);
            out.push('}');
        }
        None => out.push_str(":null"),
    }

    out.push('}');
    out
}

#[cfg(test)]
mod tests;
