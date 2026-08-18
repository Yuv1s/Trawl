//! GIF decoding, including the LZW variant the format uses.
//!
//! GIF is indexed, so its colour table is a hiding place in the same way a PNG
//! palette is, and its comment blocks hold plain text. The pixel data is LZW
//! compressed, which is the one part that needs real work: there is no platform
//! call for it the way `DecompressionStream` covers deflate.
//!
//! Only the first frame is decoded. Later frames of an animation are a known
//! gap rather than a silent one, and the frame count is reported.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GifError {
    NotGif,
    Truncated,
    NoImage,
    BadCode,
}

impl fmt::Display for GifError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotGif => write!(f, "not a GIF: signature mismatch"),
            Self::Truncated => write!(f, "the file ends part way through a block"),
            Self::NoImage => write!(f, "no image descriptor before the trailer"),
            Self::BadCode => write!(f, "the compressed data contains an impossible code"),
        }
    }
}

pub fn has_signature(file: &[u8]) -> bool {
    file.starts_with(b"GIF87a") || file.starts_with(b"GIF89a")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub width: usize,
    pub height: usize,
    pub frames: usize,
    pub interlaced: bool,
    pub palette_entries: usize,
}

fn u16_at(file: &[u8], at: usize) -> Option<usize> {
    let b = file.get(at..at + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]) as usize)
}

/// Walks the length-prefixed sub-blocks that follow most GIF structures,
/// returning their concatenated contents and where they end.
fn sub_blocks(file: &[u8], mut at: usize) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    loop {
        let len = *file.get(at)? as usize;
        at += 1;
        if len == 0 {
            return Some((out, at));
        }
        out.extend_from_slice(file.get(at..at + len)?);
        at += len;
    }
}

fn colour_table(file: &[u8], at: usize, entries: usize) -> Vec<[u8; 3]> {
    (0..entries)
        .filter_map(|i| {
            let e = file.get(at + i * 3..at + i * 3 + 3)?;
            Some([e[0], e[1], e[2]])
        })
        .collect()
}

/// Where the first image descriptor sits, plus what the walk learned on the way.
struct Scan {
    image_at: Option<usize>,
    frames: usize,
    comments: Vec<(usize, String)>,
    transparent: Option<u8>,
}

fn scan(file: &[u8]) -> Result<Scan, GifError> {
    if !has_signature(file) {
        return Err(GifError::NotGif);
    }

    let packed = *file.get(10).ok_or(GifError::Truncated)?;
    let global_entries = if packed & 0x80 != 0 {
        2usize << (packed & 0x07)
    } else {
        0
    };

    let mut at = 13 + global_entries * 3;
    let mut found = Scan {
        image_at: None,
        frames: 0,
        comments: Vec::new(),
        transparent: None,
    };

    while let Some(&marker) = file.get(at) {
        match marker {
            0x3b => break,
            0x21 => {
                let label = *file.get(at + 1).ok_or(GifError::Truncated)?;
                let (data, next) = sub_blocks(file, at + 2).ok_or(GifError::Truncated)?;

                if label == 0xfe {
                    found.comments.push((at, crate::json::latin1(&data)));
                }
                if label == 0xf9 && data.first().is_some_and(|flags| flags & 1 != 0) {
                    // Graphic control: the transparent index applies to the next image.
                    if found.image_at.is_none() {
                        found.transparent = data.get(3).copied();
                    }
                }
                at = next;
            }
            0x2c => {
                found.frames += 1;
                if found.image_at.is_none() {
                    found.image_at = Some(at);
                }

                let packed = *file.get(at + 9).ok_or(GifError::Truncated)?;
                let local = if packed & 0x80 != 0 {
                    2usize << (packed & 0x07)
                } else {
                    0
                };
                let (_, next) =
                    sub_blocks(file, at + 10 + local * 3 + 1).ok_or(GifError::Truncated)?;
                at = next;
            }
            _ => return Err(GifError::Truncated),
        }
    }

    Ok(found)
}

/// GIF's LZW: codes are packed least significant bit first, and the code width
/// grows as the dictionary fills.
fn lzw(min_code_size: u8, data: &[u8], limit: usize) -> Result<Vec<u8>, GifError> {
    if !(2..=11).contains(&min_code_size) {
        return Err(GifError::BadCode);
    }

    let clear = 1u16 << min_code_size;
    let end = clear + 1;

    let mut prefix = [0u16; 4096];
    let mut suffix = [0u8; 4096];
    for (i, entry) in suffix.iter_mut().take(clear as usize).enumerate() {
        *entry = i as u8;
    }

    let mut next = end + 1;
    let mut width = min_code_size + 1;
    let mut previous: Option<u16> = None;

    let mut out = Vec::with_capacity(limit.min(1 << 20));
    let mut stack = Vec::with_capacity(4096);

    let mut bit = 0usize;
    let total_bits = data.len() * 8;

    while bit + width as usize <= total_bits {
        let mut code = 0u16;
        for i in 0..width {
            let at = bit + i as usize;
            let set = (data[at / 8] >> (at % 8)) & 1;
            code |= (set as u16) << i;
        }
        bit += width as usize;

        if code == clear {
            next = end + 1;
            width = min_code_size + 1;
            previous = None;
            continue;
        }
        if code == end {
            break;
        }

        let mut walk = if code < next {
            code
        } else if code == next && previous.is_some() {
            // The one self-referential case: the encoder emitted a code it was
            // defining in the same step.
            previous.unwrap()
        } else {
            return Err(GifError::BadCode);
        };

        stack.clear();
        while walk >= clear {
            if stack.len() > 4096 {
                return Err(GifError::BadCode);
            }
            stack.push(suffix[walk as usize]);
            walk = prefix[walk as usize];
        }
        stack.push(suffix[walk as usize]);
        let first = suffix[walk as usize];

        out.extend(stack.iter().rev());
        if code == next {
            out.push(first);
        }

        if let Some(p) = previous
            && next < 4096
        {
            prefix[next as usize] = p;
            suffix[next as usize] = first;
            next += 1;
            if next == (1 << width) && width < 12 {
                width += 1;
            }
        }

        previous = Some(code);
        if out.len() >= limit {
            break;
        }
    }

    Ok(out)
}

/// Row order for an interlaced GIF: four passes over progressively finer rows.
const PASSES: [(usize, usize); 4] = [(0, 8), (4, 8), (2, 4), (1, 2)];

/// Decodes the first frame to non-premultiplied RGBA8.
pub fn decode(file: &[u8]) -> Result<(Header, Vec<u8>), GifError> {
    let found = scan(file)?;
    let at = found.image_at.ok_or(GifError::NoImage)?;

    let left = u16_at(file, at + 1).ok_or(GifError::Truncated)?;
    let top = u16_at(file, at + 3).ok_or(GifError::Truncated)?;
    let frame_width = u16_at(file, at + 5).ok_or(GifError::Truncated)?;
    let frame_height = u16_at(file, at + 7).ok_or(GifError::Truncated)?;
    let packed = *file.get(at + 9).ok_or(GifError::Truncated)?;

    let screen_width = u16_at(file, 6).ok_or(GifError::Truncated)?;
    let screen_height = u16_at(file, 8).ok_or(GifError::Truncated)?;
    let width = screen_width.max(left + frame_width).max(1);
    let height = screen_height.max(top + frame_height).max(1);

    let global_packed = *file.get(10).ok_or(GifError::Truncated)?;
    let table = if packed & 0x80 != 0 {
        colour_table(file, at + 10, 2usize << (packed & 0x07))
    } else if global_packed & 0x80 != 0 {
        colour_table(file, 13, 2usize << (global_packed & 0x07))
    } else {
        Vec::new()
    };

    let local_bytes = if packed & 0x80 != 0 {
        (2usize << (packed & 0x07)) * 3
    } else {
        0
    };
    let code_at = at + 10 + local_bytes;
    let min_code_size = *file.get(code_at).ok_or(GifError::Truncated)?;
    let (compressed, _) = sub_blocks(file, code_at + 1).ok_or(GifError::Truncated)?;

    let indices = lzw(min_code_size, &compressed, frame_width * frame_height)?;

    let mut rgba = vec![0u8; width * height * 4];
    let interlaced = packed & 0x40 != 0;

    for row in 0..frame_height {
        let y = if interlaced {
            let mut seen = 0;
            let mut resolved = row;
            for (start, step) in PASSES {
                let count = frame_height.saturating_sub(start).div_ceil(step);
                if row < seen + count {
                    resolved = start + (row - seen) * step;
                    break;
                }
                seen += count;
            }
            resolved
        } else {
            row
        };

        for x in 0..frame_width {
            let Some(&index) = indices.get(row * frame_width + x) else {
                continue;
            };
            let out = ((top + y) * width + left + x) * 4;
            if out + 4 > rgba.len() {
                continue;
            }

            let [r, g, b] = table.get(index as usize).copied().unwrap_or([0, 0, 0]);
            rgba[out] = r;
            rgba[out + 1] = g;
            rgba[out + 2] = b;
            rgba[out + 3] = if found.transparent == Some(index) { 0 } else { 255 };
        }
    }

    Ok((
        Header {
            width,
            height,
            frames: found.frames,
            interlaced,
            palette_entries: table.len(),
        },
        rgba,
    ))
}

/// Comment blocks, which hold plain text and are a common hiding place.
pub fn comments(file: &[u8]) -> Vec<(usize, String)> {
    scan(file).map(|s| s.comments).unwrap_or_default()
}

#[cfg(test)]
mod tests;
