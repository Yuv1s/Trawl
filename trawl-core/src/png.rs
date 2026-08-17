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

    /// For call sites that have already validated the colour type.
    fn channels_unchecked(&self) -> usize {
        self.channels().unwrap_or(1)
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

/// Exposed so tests elsewhere can build valid PNG chunks.
pub fn crc_of(bytes: &[u8]) -> u32 {
    crc32(bytes)
}

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
        0 => matches!(header.bit_depth, 1 | 2 | 4 | 8 | 16),
        3 => matches!(header.bit_depth, 1 | 2 | 4 | 8),
        2 | 4 | 6 => matches!(header.bit_depth, 8 | 16),
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

/// The payload of the first chunk of a given type, if the file has one.
pub fn chunk_payload<'a>(file: &'a [u8], kind: &[u8; 4]) -> Option<&'a [u8]> {
    chunks(file)
        .into_iter()
        .find(|c| c.is(kind))
        .map(|c| chunk_data(file, c))
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

/// Writes one pixel of a row into the RGBA buffer.
///
/// At 16 bits per sample the high byte is taken, which is the standard reduction
/// and keeps the picture intact. The low half of a 16-bit image is not examined
/// by any detector yet, and that is a known gap rather than a silent one.
fn write_pixel(
    row: &[u8],
    x: usize,
    header: &Header,
    palette: &[u8],
    transparency: &[u8],
    rgba: &mut [u8],
    out: usize,
) -> Result<(), PngError> {
    let wide = header.bit_depth == 16;
    let step = if wide { 2 } else { 1 };
    let sample = |channel: usize| row[(x * header.channels_unchecked() + channel) * step];

    match header.color_type {
        0 => {
            let value = match header.bit_depth {
                16 => sample(0),
                8 => row[x],
                depth => packed_sample(row, x, depth),
            };
            rgba[out] = value;
            rgba[out + 1] = value;
            rgba[out + 2] = value;
            rgba[out + 3] = 255;
        }
        2 => {
            for c in 0..3 {
                rgba[out + c] = sample(c);
            }
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

            let base = index as usize * 3;
            if base + 3 > palette.len() {
                return Err(PngError::PaletteIndexOutOfRange {
                    index,
                    entries: palette.len() / 3,
                });
            }
            rgba[out..out + 3].copy_from_slice(&palette[base..base + 3]);
            rgba[out + 3] = transparency.get(index as usize).copied().unwrap_or(255);
        }
        4 => {
            let value = sample(0);
            rgba[out] = value;
            rgba[out + 1] = value;
            rgba[out + 2] = value;
            rgba[out + 3] = sample(1);
        }
        6 => {
            for c in 0..4 {
                rgba[out + c] = sample(c);
            }
        }
        other => return Err(PngError::UnsupportedColorType(other)),
    }

    Ok(())
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
            write_pixel(row, x, header, palette, transparency, &mut rgba, (y * width + x) * 4)?;
        }
    }

    Ok(rgba)
}

/// Adam7 pass geometry: starting column, starting row, column step, row step.
const ADAM7: [(usize, usize, usize, usize); 7] = [
    (0, 0, 8, 8),
    (4, 0, 8, 8),
    (0, 4, 4, 8),
    (2, 0, 4, 4),
    (0, 2, 2, 4),
    (1, 0, 2, 2),
    (0, 1, 1, 2),
];

/// Decodes an interlaced image.
///
/// Adam7 stores seven progressively finer passes, each filtered independently
/// with its own width. Rather than reassembling packed samples and expanding
/// afterwards, each pass writes straight to its scattered positions in the RGBA
/// buffer, which avoids repacking sub-byte rows.
fn decode_interlaced(
    inflated: &[u8],
    header: &Header,
    palette: &[u8],
    transparency: &[u8],
) -> Result<Vec<u8>, PngError> {
    let width = header.width as usize;
    let height = header.height as usize;
    let channels = header.channels()?;
    let bpp = header.filter_bpp()?;

    let mut rgba = vec![0u8; width * height * 4];
    let mut consumed = 0usize;

    for (x0, y0, dx, dy) in ADAM7 {
        let pass_width = width.saturating_sub(x0).div_ceil(dx);
        let pass_height = height.saturating_sub(y0).div_ceil(dy);
        if pass_width == 0 || pass_height == 0 {
            continue;
        }

        let stride = (pass_width * channels * header.bit_depth as usize).div_ceil(8);
        let needed = (stride + 1) * pass_height;

        let slice = inflated
            .get(consumed..consumed + needed)
            .ok_or(PngError::ShortPixelData {
                expected: consumed + needed,
                actual: inflated.len(),
            })?;
        consumed += needed;

        let samples = unfilter(slice, stride, bpp, pass_height)?;

        for row in 0..pass_height {
            let line = &samples[row * stride..(row + 1) * stride];
            for col in 0..pass_width {
                let x = x0 + col * dx;
                let y = y0 + row * dy;
                write_pixel(
                    line,
                    col,
                    header,
                    palette,
                    transparency,
                    &mut rgba,
                    (y * width + x) * 4,
                )?;
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
    if header.interlace > 1 {
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

    if header.interlace == 1 {
        return decode_interlaced(inflated, &header, palette, transparency);
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
    /// Where the zlib stream starts, so the caller can inflate it. Zero when the
    /// chunk carries plain text.
    pub payload_offset: usize,
    pub payload_length: usize,
}

/// Reads `tEXt` and uncompressed `iTXt` outright, and locates the zlib stream in
/// the compressed variants so the caller can inflate it.
///
/// Inflate is a platform call on the JS side, so this module reports where the
/// stream is rather than pretending to have read it.
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

        let (text, compressed, payload_at) = if chunk.is(b"tEXt") {
            (crate::json::latin1(rest), false, None)
        } else if chunk.is(b"zTXt") {
            // keyword \0 method <zlib>
            (String::new(), true, Some(split + 2))
        } else {
            // iTXt: keyword \0 flag method language \0 translated \0 text
            let compressed = rest.first().is_some_and(|&flag| flag != 0);

            let body_at = rest.get(2..).and_then(|after| {
                let language = after.iter().position(|&b| b == 0)?;
                let translated = after[language + 1..].iter().position(|&b| b == 0)?;
                Some(split + 1 + 2 + language + 1 + translated + 1)
            });

            let text = match (compressed, body_at) {
                (false, Some(at)) => String::from_utf8_lossy(&data[at..]).into_owned(),
                _ => String::new(),
            };

            (text, compressed, if compressed { body_at } else { None })
        };

        let (payload_offset, payload_length) = match payload_at {
            Some(at) if at <= chunk.length => {
                (chunk.data_offset + at, chunk.length - at)
            }
            _ => (0, 0),
        };

        out.push(TextChunk {
            kind: chunk.kind,
            keyword,
            text,
            compressed,
            payload_offset,
            payload_length,
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Palette {
    pub entries: usize,
    /// Colours appearing more than once. Two indices that paint the same pixel
    /// let an encoder choose between them, which carries a bit per pixel and
    /// leaves the picture untouched.
    pub duplicates: Vec<(String, usize)>,
    /// Entries no pixel refers to.
    pub unused: usize,
    /// Bits an encoder could hide using duplicate entries alone.
    pub capacity_bits: usize,
}

/// Reads PLTE and, when pixel data is available, which entries actually get used.
pub fn palette(file: &[u8], indices: Option<&[u8]>) -> Option<Palette> {
    let plte = chunk_payload(file, b"PLTE")?;
    let entries = plte.len() / 3;

    let mut seen: Vec<(&[u8], Vec<usize>)> = Vec::new();
    for i in 0..entries {
        let colour = &plte[i * 3..i * 3 + 3];
        match seen.iter_mut().find(|(c, _)| *c == colour) {
            Some((_, at)) => at.push(i),
            None => seen.push((colour, vec![i])),
        }
    }

    let duplicates: Vec<(String, usize)> = seen
        .iter()
        .filter(|(_, at)| at.len() > 1)
        .map(|(c, at)| (format!("#{:02x}{:02x}{:02x}", c[0], c[1], c[2]), at.len()))
        .collect();

    let mut used = [false; 256];
    if let Some(data) = indices {
        for &index in data {
            used[index as usize] = true;
        }
    }

    let unused = if indices.is_some() {
        (0..entries).filter(|&i| !used[i]).count()
    } else {
        0
    };

    // Each pixel painted with a duplicated colour can choose among its copies.
    let capacity_bits = match indices {
        Some(data) => seen
            .iter()
            .filter(|(_, at)| at.len() > 1)
            .map(|(_, at)| {
                let bits = (usize::BITS - (at.len() - 1).leading_zeros()) as usize;
                let pixels = data
                    .iter()
                    .filter(|&&i| at.contains(&(i as usize)))
                    .count();
                bits * pixels
            })
            .sum(),
        None => 0,
    };

    Some(Palette {
        entries,
        duplicates,
        unused,
        capacity_bits,
    })
}

/// Raw palette indices, one per pixel, for an indexed image.
pub fn palette_indices(file: &[u8], inflated: &[u8]) -> Option<Vec<u8>> {
    let header = header(file).ok()?;
    if header.color_type != 3 || header.interlace != 0 {
        return None;
    }

    let stride = header.stride().ok()?;
    let samples = unfilter(inflated, stride, header.filter_bpp().ok()?, header.height as usize).ok()?;
    let width = header.width as usize;
    let per_byte = 8 / header.bit_depth as usize;

    let mut out = Vec::with_capacity(width * header.height as usize);
    for y in 0..header.height as usize {
        let row = &samples[y * stride..(y + 1) * stride];
        for x in 0..width {
            out.push(if header.bit_depth == 8 {
                row[x]
            } else {
                let byte = row[x / per_byte];
                let shift = 8 - header.bit_depth as usize * (x % per_byte + 1);
                (byte >> shift) & ((1u16 << header.bit_depth) - 1) as u8
            });
        }
    }

    Some(out)
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
        out.push(',');
        push_number(&mut out, "payloadOffset", text.payload_offset);
        out.push(',');
        push_number(&mut out, "payloadLength", text.payload_length);
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

    // Strings are a byte-level concern and belong to the survey, which runs on
    // every format. Emitting them here too would be the same work twice.

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
