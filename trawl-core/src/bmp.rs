//! Uncompressed BMP decoding.
//!
//! Windows bitmaps are close to raw pixels with a header bolted on, which makes
//! them a common CTF container: there is no compression to fight, so a payload
//! written into the low bits survives untouched.
//!
//! Three details catch people out. Rows are stored bottom-up unless the declared
//! height is negative. Each row is padded to a four-byte boundary. And colours
//! are stored blue first.

use core::fmt;

use crate::pixels::MAX_PIXELS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BmpError {
    NotBmp,
    Truncated,
    UnsupportedDepth(u16),
    UnsupportedCompression(u32),
    ZeroDimension,
    TooLarge,
}

impl fmt::Display for BmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotBmp => write!(f, "not a BMP: signature mismatch"),
            Self::Truncated => write!(f, "the header or pixel data runs past the end of the file"),
            Self::UnsupportedDepth(bpp) => write!(f, "unsupported bit depth {bpp}"),
            Self::UnsupportedCompression(c) => write!(
                f,
                "compression method {c} is not supported; only uncompressed BMP decodes"
            ),
            Self::ZeroDimension => write!(f, "the header declares a zero width or height"),
            Self::TooLarge => write!(f, "the header declares more pixels than Trawl will decode"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub width: usize,
    pub height: usize,
    pub bits_per_pixel: u16,
    /// Rows are stored bottom-up unless the declared height was negative.
    pub top_down: bool,
    pub palette_entries: usize,
    pub data_offset: usize,
}

pub fn has_signature(file: &[u8]) -> bool {
    file.starts_with(b"BM")
}

fn u16_at(file: &[u8], at: usize) -> Option<u16> {
    let b = file.get(at..at + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(file: &[u8], at: usize) -> Option<u32> {
    let b = file.get(at..at + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn header(file: &[u8]) -> Result<Header, BmpError> {
    if !has_signature(file) {
        return Err(BmpError::NotBmp);
    }

    let data_offset = u32_at(file, 10).ok_or(BmpError::Truncated)? as usize;
    let dib_size = u32_at(file, 14).ok_or(BmpError::Truncated)? as usize;
    if dib_size < 40 {
        // BITMAPCOREHEADER and friends predate anything worth analysing.
        return Err(BmpError::Truncated);
    }

    let width = u32_at(file, 18).ok_or(BmpError::Truncated)? as i32;
    let raw_height = u32_at(file, 22).ok_or(BmpError::Truncated)? as i32;
    let bits_per_pixel = u16_at(file, 28).ok_or(BmpError::Truncated)?;
    let compression = u32_at(file, 30).ok_or(BmpError::Truncated)?;
    let declared_colours = u32_at(file, 46).ok_or(BmpError::Truncated)? as usize;

    if compression != 0 {
        return Err(BmpError::UnsupportedCompression(compression));
    }
    if !matches!(bits_per_pixel, 1 | 4 | 8 | 24 | 32) {
        return Err(BmpError::UnsupportedDepth(bits_per_pixel));
    }
    if width <= 0 || raw_height == 0 {
        return Err(BmpError::ZeroDimension);
    }

    // Capped at what a pixel can index. The field is 32 bits, and walking four
    // billion entries that are mostly past the end of the file is a hang.
    let palette_entries = if bits_per_pixel <= 8 {
        let reachable = 1usize << bits_per_pixel;
        if declared_colours > 0 {
            declared_colours.min(reachable)
        } else {
            reachable
        }
    } else {
        0
    };

    Ok(Header {
        width: width as usize,
        height: raw_height.unsigned_abs() as usize,
        bits_per_pixel,
        top_down: raw_height < 0,
        palette_entries,
        data_offset,
    })
}

/// The colour table, stored blue first with a padding byte.
pub fn palette(file: &[u8]) -> Option<Vec<[u8; 3]>> {
    let header = header(file).ok()?;
    if header.palette_entries == 0 {
        return None;
    }

    let dib_size = u32_at(file, 14)? as usize;
    let start = dib_size.checked_add(14)?;

    Some(
        (0..header.palette_entries)
            .filter_map(|i| {
                let at = start.checked_add(i * 4)?;
                let e = file.get(at..at.checked_add(3)?)?;
                Some([e[2], e[1], e[0]])
            })
            .collect(),
    )
}

/// Bytes of pixel data the geometry needs, or nothing when the number does not fit.
///
/// Counted without wrapping. 65536 by 65536 at 32 bits is 2^34 bytes, which is zero
/// in a 32-bit `usize`, and zero bytes needed passes every check that follows.
fn pixel_bytes(header: &Header) -> Option<(usize, usize)> {
    let row_bits = (header.width as u64).checked_mul(header.bits_per_pixel as u64)?;
    let stride = usize::try_from(row_bits.div_ceil(32).checked_mul(4)?).ok()?;
    Some((stride, stride.checked_mul(header.height)?))
}

/// Decodes to non-premultiplied RGBA8.
pub fn decode(file: &[u8]) -> Result<(Header, Vec<u8>), BmpError> {
    let header = header(file)?;
    let table = palette(file).unwrap_or_default();

    // A file cannot hold what a number too large to count asks for, so a geometry
    // that overflows is a truncated file like any other that asks for too much.
    let (stride, body) = pixel_bytes(&header).ok_or(BmpError::Truncated)?;
    let needed = header
        .data_offset
        .checked_add(body)
        .ok_or(BmpError::Truncated)?;
    if file.len() < needed {
        return Err(BmpError::Truncated);
    }

    // The file has paid for its rows, but at one bit per pixel that still buys 32
    // bytes of RGBA per byte of file.
    let pixels = header
        .width
        .checked_mul(header.height)
        .filter(|&pixels| pixels <= MAX_PIXELS)
        .ok_or(BmpError::TooLarge)?;

    let mut rgba = vec![0u8; pixels * 4];
    // 32-bit BI_RGB leaves the fourth byte undefined, and plenty of encoders
    // write zero there. Treating that as fully transparent would blank the
    // image, so alpha is only honoured when something actually set it.
    let alpha_used = header.bits_per_pixel == 32
        && (0..header.height).any(|row| {
            let base = header.data_offset + row * stride;
            (0..header.width).any(|x| file.get(base + x * 4 + 3).is_some_and(|&a| a != 0))
        });

    for row in 0..header.height {
        let source = header.data_offset + row * stride;
        let y = if header.top_down {
            row
        } else {
            header.height - 1 - row
        };

        for x in 0..header.width {
            let out = (y * header.width + x) * 4;

            let (r, g, b, a) = match header.bits_per_pixel {
                24 => {
                    let p = &file[source + x * 3..source + x * 3 + 3];
                    (p[2], p[1], p[0], 255)
                }
                32 => {
                    let p = &file[source + x * 4..source + x * 4 + 4];
                    (p[2], p[1], p[0], if alpha_used { p[3] } else { 255 })
                }
                depth => {
                    let per_byte = 8 / depth as usize;
                    let byte = file[source + x / per_byte];
                    let shift = 8 - depth as usize * (x % per_byte + 1);
                    let index = ((byte >> shift) & ((1u16 << depth) - 1) as u8) as usize;
                    let [r, g, b] = table.get(index).copied().unwrap_or([0, 0, 0]);
                    (r, g, b, 255)
                }
            };

            rgba[out] = r;
            rgba[out + 1] = g;
            rgba[out + 2] = b;
            rgba[out + 3] = a;
        }
    }

    Ok((header, rgba))
}

#[cfg(test)]
mod tests;
