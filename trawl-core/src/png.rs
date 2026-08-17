//! Non-interlaced PNG decoding, exact to the bit.
//!
//! Inflate is not here. `DecompressionStream` does that on the JS side, so this
//! module takes the already-inflated IDAT stream and does the parts a browser
//! will not do faithfully: unfiltering and sample expansion.

use core::fmt;

pub const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub width: u32,
    pub height: u32,
    pub bit_depth: u8,
    pub color_type: u8,
    pub interlace: u8,
}

impl Header {
    pub fn channels(&self) -> Result<usize, PngError> {
        match self.color_type {
            0 | 3 => Ok(1),
            2 => Ok(3),
            4 => Ok(2),
            6 => Ok(4),
            other => Err(PngError::UnsupportedColorType(other)),
        }
    }

    /// Bytes per complete pixel, rounded up, floored at 1. This is the filter
    /// offset from PNG spec 9.2, not the storage size of a pixel.
    pub fn filter_bpp(&self) -> Result<usize, PngError> {
        let bits = self.channels()? * self.bit_depth as usize;
        Ok(bits.div_ceil(8).max(1))
    }

    pub fn stride(&self) -> Result<usize, PngError> {
        let bits = self.width as usize * self.channels()? * self.bit_depth as usize;
        Ok(bits.div_ceil(8))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub kind: [u8; 4],
    pub offset: usize,
    pub data_offset: usize,
    pub length: usize,
    pub crc_ok: bool,
}

impl Chunk {
    pub fn is(&self, kind: &[u8; 4]) -> bool {
        self.kind == *kind
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PngError {
    NotPng,
    MissingHeader,
    ZeroDimension,
    UnsupportedColorType(u8),
    UnsupportedBitDepth { color_type: u8, bit_depth: u8 },
    Interlaced,
    MissingPalette,
    PaletteIndexOutOfRange { index: u8, entries: usize },
    BadFilterType(u8),
    ShortPixelData { expected: usize, actual: usize },
}

impl fmt::Display for PngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPng => write!(f, "not a PNG: signature mismatch"),
            Self::MissingHeader => write!(f, "no IHDR chunk"),
            Self::ZeroDimension => write!(f, "IHDR declares a zero width or height"),
            Self::UnsupportedColorType(t) => write!(f, "unsupported colour type {t}"),
            Self::UnsupportedBitDepth {
                color_type,
                bit_depth,
            } => write!(f, "bit depth {bit_depth} unsupported for colour type {color_type}"),
            Self::Interlaced => write!(
                f,
                "Adam7 interlacing is not supported; decoding would be silently wrong"
            ),
            Self::MissingPalette => write!(f, "indexed image with no PLTE chunk"),
            Self::PaletteIndexOutOfRange { index, entries } => {
                write!(f, "palette index {index} outside a {entries}-entry PLTE")
            }
            Self::BadFilterType(t) => write!(f, "unknown row filter type {t}"),
            Self::ShortPixelData { expected, actual } => {
                write!(f, "inflated data is {actual} bytes, expected {expected}")
            }
        }
    }
}

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
};

fn crc32(bytes: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &b in bytes {
        c = CRC_TABLE[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    c ^ 0xffff_ffff
}

fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 4)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub fn has_signature(file: &[u8]) -> bool {
    file.starts_with(&SIGNATURE)
}

/// Walks every chunk, stopping at the first one that cannot be read.
///
/// Deliberately tolerant: a chunk claiming more bytes than the file holds is a
/// finding worth reporting, not a reason to refuse the whole file. Callers get
/// what was parsed and decide what a short walk means.
pub fn chunks(file: &[u8]) -> Vec<Chunk> {
    let mut out = Vec::new();
    let mut at = SIGNATURE.len();

    while at + 8 <= file.len() {
        let Some(length) = be_u32(file, at) else { break };
        let length = length as usize;

        let kind_at = at + 4;
        let data_at = kind_at + 4;
        let crc_at = data_at + length;
        if crc_at + 4 > file.len() {
            break;
        }

        let kind = [file[kind_at], file[kind_at + 1], file[kind_at + 2], file[kind_at + 3]];
        let declared = be_u32(file, crc_at).unwrap_or(0);

        out.push(Chunk {
            kind,
            offset: at,
            data_offset: data_at,
            length,
            crc_ok: crc32(&file[kind_at..crc_at]) == declared,
        });

        if &kind == b"IEND" {
            break;
        }
        at = crc_at + 4;
    }

    out
}

fn chunk_data(file: &[u8], chunk: Chunk) -> &[u8] {
    &file[chunk.data_offset..chunk.data_offset + chunk.length]
}

pub fn header(file: &[u8]) -> Result<Header, PngError> {
    if !has_signature(file) {
        return Err(PngError::NotPng);
    }

    let chunks = chunks(file);
    let ihdr = chunks
        .iter()
        .find(|c| c.is(b"IHDR") && c.length >= 13)
        .ok_or(PngError::MissingHeader)?;

    let data = chunk_data(file, *ihdr);
    let header = Header {
        width: be_u32(data, 0).ok_or(PngError::MissingHeader)?,
        height: be_u32(data, 4).ok_or(PngError::MissingHeader)?,
        bit_depth: data[8],
        color_type: data[9],
        interlace: data[12],
    };

    if header.width == 0 || header.height == 0 {
        return Err(PngError::ZeroDimension);
    }

    let depth_ok = match header.color_type {
        0 => matches!(header.bit_depth, 1 | 2 | 4 | 8),
        3 => matches!(header.bit_depth, 1 | 2 | 4 | 8),
        2 | 4 | 6 => header.bit_depth == 8,
        other => return Err(PngError::UnsupportedColorType(other)),
    };
    if !depth_ok {
        return Err(PngError::UnsupportedBitDepth {
            color_type: header.color_type,
            bit_depth: header.bit_depth,
        });
    }

    Ok(header)
}

/// Concatenated IDAT payloads, ready to hand to `DecompressionStream('deflate')`.
pub fn idat(file: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in chunks(file).into_iter().filter(|c| c.is(b"IDAT")) {
        out.extend_from_slice(chunk_data(file, chunk));
    }
    out
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = a as i16 + b as i16 - c as i16;
    let pa = (p - a as i16).abs();
    let pb = (p - b as i16).abs();
    let pc = (p - c as i16).abs();

    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

/// Reverses the per-row filters, producing packed samples with no filter bytes.
pub fn unfilter(
    filtered: &[u8],
    stride: usize,
    bpp: usize,
    height: usize,
) -> Result<Vec<u8>, PngError> {
    let expected = (stride + 1) * height;
    if filtered.len() < expected {
        return Err(PngError::ShortPixelData {
            expected,
            actual: filtered.len(),
        });
    }

    let mut out = vec![0u8; stride * height];

    for y in 0..height {
        let filter_type = filtered[y * (stride + 1)];
        let row_start = y * (stride + 1) + 1;
        let src = &filtered[row_start..row_start + stride];

        // split_at_mut hands out two non-overlapping &mut slices, which is how the
        // previous row stays readable while the current row is being written.
        let (done, rest) = out.split_at_mut(y * stride);
        let prev = if y == 0 { None } else { Some(&done[(y - 1) * stride..]) };
        let cur = &mut rest[..stride];

        for i in 0..stride {
            let a = if i >= bpp { cur[i - bpp] } else { 0 };
            let b = prev.map_or(0, |row| row[i]);
            let c = match (prev, i >= bpp) {
                (Some(row), true) => row[i - bpp],
                _ => 0,
            };

            cur[i] = match filter_type {
                0 => src[i],
                1 => src[i].wrapping_add(a),
                2 => src[i].wrapping_add(b),
                3 => src[i].wrapping_add(((a as u16 + b as u16) / 2) as u8),
                4 => src[i].wrapping_add(paeth(a, b, c)),
                other => return Err(PngError::BadFilterType(other)),
            };
        }
    }

    Ok(out)
}

/// Reads the `index`-th sample of a sub-byte-depth row, scaled to 0..=255.
fn packed_sample(row: &[u8], index: usize, bit_depth: u8) -> u8 {
    let per_byte = 8 / bit_depth as usize;
    let byte = row[index / per_byte];
    let shift = 8 - bit_depth as usize * (index % per_byte + 1);
    let max = (1u16 << bit_depth) - 1;
    let raw = (byte >> shift) & max as u8;
    ((raw as u16 * 255) / max) as u8
}

fn expand(
    samples: &[u8],
    header: &Header,
    palette: &[u8],
    transparency: &[u8],
) -> Result<Vec<u8>, PngError> {
    let width = header.width as usize;
    let height = header.height as usize;
    let stride = header.stride()?;
    let mut rgba = vec![0u8; width * height * 4];

    for y in 0..height {
        let row = &samples[y * stride..(y + 1) * stride];

        for x in 0..width {
            let out = (y * width + x) * 4;

            match header.color_type {
                0 => {
                    let value = if header.bit_depth == 8 {
                        row[x]
                    } else {
                        packed_sample(row, x, header.bit_depth)
                    };
                    rgba[out] = value;
                    rgba[out + 1] = value;
                    rgba[out + 2] = value;
                    rgba[out + 3] = 255;
                }
                2 => {
                    rgba[out..out + 3].copy_from_slice(&row[x * 3..x * 3 + 3]);
                    rgba[out + 3] = 255;
                }
                3 => {
                    let per_byte = 8 / header.bit_depth as usize;
                    let index = if header.bit_depth == 8 {
                        row[x]
                    } else {
                        let byte = row[x / per_byte];
                        let shift = 8 - header.bit_depth as usize * (x % per_byte + 1);
                        (byte >> shift) & ((1u16 << header.bit_depth) - 1) as u8
                    };

                    let entries = palette.len() / 3;
                    let base = index as usize * 3;
                    if base + 3 > palette.len() {
                        return Err(PngError::PaletteIndexOutOfRange { index, entries });
                    }
                    rgba[out..out + 3].copy_from_slice(&palette[base..base + 3]);
                    rgba[out + 3] = transparency.get(index as usize).copied().unwrap_or(255);
                }
                4 => {
                    let value = row[x * 2];
                    rgba[out] = value;
                    rgba[out + 1] = value;
                    rgba[out + 2] = value;
                    rgba[out + 3] = row[x * 2 + 1];
                }
                6 => rgba[out..out + 4].copy_from_slice(&row[x * 4..x * 4 + 4]),
                other => return Err(PngError::UnsupportedColorType(other)),
            }
        }
    }

    Ok(rgba)
}

/// Decodes to non-premultiplied RGBA8.
///
/// @param file the original bytes, read for IHDR, PLTE and tRNS
/// @param inflated the concatenated IDAT payloads after zlib decompression
pub fn decode(file: &[u8], inflated: &[u8]) -> Result<Vec<u8>, PngError> {
    let header = header(file)?;
    if header.interlace != 0 {
        return Err(PngError::Interlaced);
    }

    let chunks = chunks(file);
    let find = |kind: &[u8; 4]| {
        chunks
            .iter()
            .find(|c| c.is(kind))
            .map(|c| chunk_data(file, *c))
            .unwrap_or(&[])
    };

    let palette = find(b"PLTE");
    let transparency = find(b"tRNS");
    if header.color_type == 3 && palette.is_empty() {
        return Err(PngError::MissingPalette);
    }

    let samples = unfilter(
        inflated,
        header.stride()?,
        header.filter_bpp()?,
        header.height as usize,
    )?;

    expand(&samples, &header, palette, transparency)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextChunk {
    pub kind: [u8; 4],
    pub keyword: String,
    pub text: String,
    pub compressed: bool,
}

/// Reads `tEXt` and uncompressed `iTXt`. Compressed payloads are reported as
/// present but left empty: inflate lives on the JS side, and claiming to have
/// read something we have not is worse than saying so.
pub fn text_chunks(file: &[u8]) -> Vec<TextChunk> {
    let mut out = Vec::new();

    for chunk in chunks(file) {
        let is_text = chunk.is(b"tEXt") || chunk.is(b"zTXt") || chunk.is(b"iTXt");
        if !is_text {
            continue;
        }

        let data = chunk_data(file, chunk);
        let Some(split) = data.iter().position(|&b| b == 0) else {
            continue;
        };
        let keyword = crate::json::latin1(&data[..split]);
        let rest = &data[split + 1..];

        let (text, compressed) = if chunk.is(b"tEXt") {
            (crate::json::latin1(rest), false)
        } else if chunk.is(b"zTXt") {
            (String::new(), true)
        } else {
            // iTXt: compression flag, method, language tag, translated keyword, text
            let compressed = rest.first().is_some_and(|&flag| flag != 0);
            let body = rest
                .get(2..)
                .map(|b| {
                    let mut fields = b.splitn(3, |&x| x == 0);
                    fields.nth(2).unwrap_or(&[])
                })
                .unwrap_or(&[]);
            let text = if compressed {
                String::new()
            } else {
                String::from_utf8_lossy(body).into_owned()
            };
            (text, compressed)
        };

        out.push(TextChunk {
            kind: chunk.kind,
            keyword,
            text,
            compressed,
        });
    }

    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagHit {
    pub offset: usize,
    pub text: String,
    pub region: String,
    pub credible: bool,
}

fn itxt_is_compressed(file: &[u8], chunk: Chunk) -> bool {
    let data = chunk_data(file, chunk);
    data.iter()
        .position(|&b| b == 0)
        .and_then(|split| data.get(split + 1))
        .is_some_and(|&flag| flag != 0)
}

/// Where a byte offset sits, and whether a flag-shaped match there means anything.
///
/// A `tag{payload}` shape found inside a deflate stream is a coincidence, not a
/// find: compressed bytes are close to uniform, so the shape turns up by chance
/// across a large enough file. Suppressing those is the difference between a
/// detector and a random number generator.
fn region_of(file: &[u8], chunks: &[Chunk], offset: usize) -> (String, bool) {
    for chunk in chunks {
        if offset < chunk.data_offset || offset >= chunk.data_offset + chunk.length {
            continue;
        }

        let kind = crate::json::latin1(&chunk.kind);
        let compressed = chunk.is(b"IDAT")
            || chunk.is(b"zTXt")
            || (chunk.is(b"iTXt") && itxt_is_compressed(file, *chunk));

        return (format!("inside {kind}"), !compressed);
    }

    if let Some((start, _)) = trailing_data(file)
        && offset >= start
    {
        return ("after IEND".to_string(), true);
    }

    ("chunk framing".to_string(), false)
}

/// Flag-shaped matches with the region they came from attached.
pub fn located_flags(file: &[u8]) -> Vec<FlagHit> {
    let chunks = chunks(file);

    crate::bytes::flag_candidates(file)
        .into_iter()
        .map(|found| {
            let (region, credible) = region_of(file, &chunks, found.offset);
            FlagHit {
                offset: found.offset,
                text: found.text,
                region,
                credible,
            }
        })
        .collect()
}

/// Offset and length of anything after the IEND chunk. A PNG is complete at IEND,
/// so bytes past it were put there deliberately.
pub fn trailing_data(file: &[u8]) -> Option<(usize, usize)> {
    let iend = chunks(file).into_iter().find(|c| c.is(b"IEND"))?;
    let end = iend.data_offset + iend.length + 4;
    (file.len() > end).then(|| (end, file.len() - end))
}

/// A chunk type whose first letter is lowercase is ancillary: a decoder may skip
/// it. That is exactly where payloads get parked.
pub fn is_ancillary(kind: &[u8; 4]) -> bool {
    kind[0].is_ascii_lowercase()
}

/// The whole container walk as JSON, ready to leave the worker.
pub fn structure_json(file: &[u8]) -> String {
    use crate::json::{push_bool, push_field, push_number, push_string};

    let mut out = String::from("{");

    push_string(&mut out, "signature");
    out.push(':');
    out.push_str(if has_signature(file) { "true" } else { "false" });

    out.push(',');
    push_number(&mut out, "size", file.len());

    out.push(',');
    push_string(&mut out, "header");
    out.push(':');
    match header(file) {
        Ok(h) => {
            out.push('{');
            push_number(&mut out, "width", h.width as usize);
            out.push(',');
            push_number(&mut out, "height", h.height as usize);
            out.push(',');
            push_number(&mut out, "bitDepth", h.bit_depth as usize);
            out.push(',');
            push_number(&mut out, "colorType", h.color_type as usize);
            out.push(',');
            push_number(&mut out, "interlace", h.interlace as usize);
            out.push('}');
        }
        Err(e) => {
            out.push('{');
            push_field(&mut out, "error", &e.to_string());
            out.push('}');
        }
    }

    out.push(',');
    push_string(&mut out, "chunks");
    out.push_str(":[");
    for (i, chunk) in chunks(file).iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "kind", &crate::json::latin1(&chunk.kind));
        out.push(',');
        push_number(&mut out, "offset", chunk.offset);
        out.push(',');
        push_number(&mut out, "length", chunk.length);
        out.push(',');
        push_number(&mut out, "dataOffset", chunk.data_offset);
        out.push(',');
        push_bool(&mut out, "crcOk", chunk.crc_ok);
        out.push(',');
        push_bool(&mut out, "ancillary", is_ancillary(&chunk.kind));
        out.push('}');
    }
    out.push(']');

    out.push(',');
    push_string(&mut out, "text");
    out.push_str(":[");
    for (i, text) in text_chunks(file).iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "kind", &crate::json::latin1(&text.kind));
        out.push(',');
        push_field(&mut out, "keyword", &text.keyword);
        out.push(',');
        push_field(&mut out, "text", &text.text);
        out.push(',');
        push_bool(&mut out, "compressed", text.compressed);
        out.push('}');
    }
    out.push(']');

    out.push(',');
    push_string(&mut out, "flags");
    out.push_str(":[");
    for (i, found) in located_flags(file).iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_number(&mut out, "offset", found.offset);
        out.push(',');
        push_field(&mut out, "text", &found.text);
        out.push(',');
        push_field(&mut out, "region", &found.region);
        out.push(',');
        push_bool(&mut out, "credible", found.credible);
        out.push('}');
    }
    out.push(']');

    out.push(',');
    push_string(&mut out, "strings");
    out.push(':');
    {
        let all = crate::bytes::ascii_strings(file, 6);
        out.push('{');
        push_number(&mut out, "total", all.len());
        out.push(',');
        push_string(&mut out, "sample");
        out.push_str(":[");
        for (i, found) in all.iter().take(300).enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('{');
            push_number(&mut out, "offset", found.offset);
            out.push(',');
            push_field(&mut out, "text", &found.text);
            out.push('}');
        }
        out.push_str("]}");
    }

    out.push(',');
    push_string(&mut out, "trailing");
    out.push(':');
    match trailing_data(file) {
        Some((offset, length)) => {
            out.push('{');
            push_number(&mut out, "offset", offset);
            out.push(',');
            push_number(&mut out, "length", length);
            out.push('}');
        }
        None => out.push_str("null"),
    }

    out.push('}');
    out
}

#[cfg(test)]
mod tests;
