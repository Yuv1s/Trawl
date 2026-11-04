//! GIF decoding, including the LZW variant the format uses.
//!
//! GIF is indexed, so its colour table is a hiding place in the same way a PNG
//! palette is, and its comment blocks hold plain text. The pixel data is LZW
//! compressed, which is the one part that needs real work: there is no platform
//! call for it the way `DecompressionStream` covers deflate.
//!
//! This version decodes all frames, composites them according to their disposal
//! methods, and produces consecutive-frame absolute differences for stego
//! analysis.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GifError {
    NotGif,
    Truncated,
    NoImage,
    BadCode,
    DimensionOverflow,
    ZeroDimension,
    FrameLimit,
    WorkLimit,
}

impl fmt::Display for GifError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotGif => write!(f, "not a GIF: signature mismatch"),
            Self::Truncated => write!(f, "the file ends part way through a block"),
            Self::NoImage => write!(f, "no image descriptor before the trailer"),
            Self::BadCode => write!(f, "the compressed data contains an impossible code"),
            Self::DimensionOverflow => write!(f, "frame dimensions overflow logical screen"),
            Self::ZeroDimension => write!(f, "the header declares a zero width or height"),
            Self::FrameLimit => write!(f, "too many frames for automatic analysis"),
            Self::WorkLimit => write!(f, "the canvas is larger than Trawl will composite"),
        }
    }
}

pub fn has_signature(file: &[u8]) -> bool {
    file.starts_with(b"GIF87a") || file.starts_with(b"GIF89a")
}

/// How long one frame shows and what happens to it afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// Hundredths of a second.
    pub delay: u16,
    pub disposal: u8,
}

impl Timing {
    /// The method's name, in the words the frame list reads. Values above three are
    /// reserved by the format, so one is worth showing rather than hiding.
    pub fn disposal_name(&self) -> &'static str {
        match self.disposal {
            0 => "none",
            1 => "doNotDispose",
            2 => "background",
            3 => "previous",
            _ => "reserved",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub width: usize,
    pub height: usize,
    pub frames: usize,
    pub declared_frames: usize,
    pub interlaced: bool,
    pub palette_entries: usize,
    /// One per frame analysed, in order.
    pub timings: Vec<Timing>,
}

/// One image descriptor plus the Graphic Control Extension it belongs to, and
/// everything needed to decode the frame later without re-walking the file.
pub struct FrameInfo {
    pub index: usize,
    pub left: usize,
    pub top: usize,
    pub width: usize,
    pub height: usize,
    pub interlaced: bool,
    /// The frame's own palette, when it has one. Otherwise the global table.
    pub local_palette: Option<Vec<[u8; 3]>>,
    pub transparent: Option<u8>,
    pub delay: u16,
    pub disposal: u8,
    /// The LZW minimum code size and the compressed sub-block contents.
    pub min_code_size: u8,
    pub data: Vec<u8>,
}

/// Parsed file, split so the decoder can composite without re-walking blocks.
struct Parsed {
    screen_width: usize,
    screen_height: usize,
    global_palette: Vec<[u8; 3]>,
    background: Option<[u8; 3]>,
    frames: Vec<FrameInfo>,
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

/// Row order for an interlaced GIF: four passes over progressively finer rows.
const PASSES: [(usize, usize); 4] = [(0, 8), (4, 8), (2, 4), (1, 2)];

/// Work budgets. A valid animation over these is reported as capped, not an error.
const MAX_FRAMES: usize = 128;

/// Largest canvas worth compositing. Unlike the two others this one is refused
/// outright, because even a single frame has to be painted onto all of it.
const MAX_CANVAS_PIXELS: usize = 16_000_000;

/// Canvas pixels across every frame kept. Each frame costs a whole canvas however
/// little of it the frame paints, and its difference from the last costs another, so
/// a 1x1 frame on a 4000x4000 screen is 128 MB and 128 of them fit in two kilobytes
/// of file.
const MAX_COMPOSITED_PIXELS: usize = 64_000_000;

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
    let total_bits = data.len().saturating_mul(8);

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

/// Parses the header and every frame descriptor in one pass, associating each
/// Graphic Control Extension with the image right after it.
fn parse(file: &[u8]) -> Result<Parsed, GifError> {
    if !has_signature(file) {
        return Err(GifError::NotGif);
    }

    let packed = *file.get(10).ok_or(GifError::Truncated)?;
    let global_entries = if packed & 0x80 != 0 {
        2usize << (packed & 0x07)
    } else {
        0
    };

    let screen_width = u16_at(file, 6).ok_or(GifError::Truncated)?;
    let screen_height = u16_at(file, 8).ok_or(GifError::Truncated)?;
    // No canvas to paint and no pixels to hand on, and every tool downstream divides
    // by these.
    if screen_width == 0 || screen_height == 0 {
        return Err(GifError::ZeroDimension);
    }
    let background_index = *file.get(11).ok_or(GifError::Truncated)? as usize;
    let global_palette = colour_table(file, 13, global_entries);
    let background = if global_entries > 0 {
        global_palette.get(background_index).copied()
    } else {
        None
    };

    let mut at = 13 + global_entries * 3;
    let mut frames = Vec::new();
    let mut pending_gce: Option<(Option<u8>, u16, u8)> = None;

    while let Some(&marker) = file.get(at) {
        match marker {
            0x3b => break, // Trailer
            0x21 => {
                let label = *file.get(at + 1).ok_or(GifError::Truncated)?;
                let (data, next) = sub_blocks(file, at + 2).ok_or(GifError::Truncated)?;

                if label == 0xf9 && data.len() >= 4 {
                    // Graphic Control Extension: applies to the NEXT image descriptor
                    let flags = data[0];
                    let delay = u16::from_le_bytes([data[1], data[2]]);
                    let transparent = if flags & 1 != 0 { Some(data[3]) } else { None };
                    let disposal = (flags >> 2) & 0x07;
                    pending_gce = Some((transparent, delay, disposal));
                }
                at = next;
            }
            0x2c => {
                if frames.len() >= MAX_FRAMES * 2 {
                    // The parser accepts a larger number so that a valid animation
                    // over the work budget is reported as capped by compose(),
                    // not rejected as malformed. The hard ceiling prevents
                    // absurd allocations in the frame vector.
                    return Err(GifError::FrameLimit);
                }

                let left = u16_at(file, at + 1).ok_or(GifError::Truncated)?;
                let top = u16_at(file, at + 3).ok_or(GifError::Truncated)?;
                let frame_width = u16_at(file, at + 5).ok_or(GifError::Truncated)?;
                let frame_height = u16_at(file, at + 7).ok_or(GifError::Truncated)?;
                let packed = *file.get(at + 9).ok_or(GifError::Truncated)?;

                if left + frame_width > screen_width || top + frame_height > screen_height {
                    return Err(GifError::DimensionOverflow);
                }

                let local_entries = if packed & 0x80 != 0 {
                    2usize << (packed & 0x07)
                } else {
                    0
                };
                let local_palette = if local_entries > 0 {
                    Some(colour_table(file, at + 10, local_entries))
                } else {
                    None
                };

                let local_bytes = local_entries * 3;
                let code_at = at + 10 + local_bytes;
                let min_code_size = *file.get(code_at).ok_or(GifError::Truncated)?;
                let (data, next) = sub_blocks(file, code_at + 1).ok_or(GifError::Truncated)?;

                let (transparent, delay, disposal) = pending_gce.take().unwrap_or((None, 0, 0));

                frames.push(FrameInfo {
                    index: frames.len(),
                    left,
                    top,
                    width: frame_width,
                    height: frame_height,
                    interlaced: packed & 0x40 != 0,
                    local_palette,
                    transparent,
                    delay,
                    disposal,
                    min_code_size,
                    data,
                });

                at = next;
            }
            _ => return Err(GifError::Truncated),
        }
    }

    match frames.len() {
        0 => Err(GifError::NoImage),
        _ => Ok(Parsed {
            screen_width,
            screen_height,
            global_palette,
            background,
            frames,
        }),
    }
}

/// Paints frames onto the canvas in order, keeping each result.
///
/// @param frame_limit how many frames to go as far as, which is one for a caller that
///        only wants the first picture and has no use for the rest being decoded
fn compose(parsed: &Parsed, frame_limit: usize) -> Result<List, GifError> {
    let Parsed {
        screen_width: w,
        screen_height: h,
        global_palette,
        background,
        frames,
    } = parsed;
    let global_palette = global_palette.as_slice();
    // Sixty-five thousand squared fits 32 bits, and that times four does not.
    let canvas_pixels = w
        .checked_mul(*h)
        .filter(|&pixels| pixels <= MAX_CANVAS_PIXELS)
        .ok_or(GifError::WorkLimit)?;
    let canvas_size = canvas_pixels * 4;

    let mut list = List {
        displayed: Vec::new(),
        differences: Vec::new(),
        timings: Vec::new(),
    };
    let mut canvas = vec![0u8; canvas_size];
    if let Some([r, g, b]) = background {
        for i in 0..(canvas_size / 4) {
            canvas[i * 4] = *r;
            canvas[i * 4 + 1] = *g;
            canvas[i * 4 + 2] = *b;
            canvas[i * 4 + 3] = 255;
        }
    }

    let mut total = 0usize;

    for frame in frames {
        if list.timings.len() >= frame_limit {
            break;
        }
        total += canvas_pixels;
        if total > MAX_COMPOSITED_PIXELS {
            break;
        }
        list.timings.push(Timing {
            delay: frame.delay,
            disposal: frame.disposal,
        });

        let palette = frame.local_palette.as_deref().unwrap_or(global_palette);

        // Keep the pre-frame canvas for disposal 3, and only for disposal 3.
        let saved = (frame.disposal == 3).then(|| canvas.clone());

        // Inside the canvas, as `parse` checked, so inside the canvas budget too.
        let pixels = frame.width * frame.height;
        let indices = lzw(frame.min_code_size, &frame.data, pixels)?;

        let width = *w;
        for row in 0..frame.height {
            let y = if frame.interlaced {
                let mut seen = 0;
                let mut resolved = row;
                for (start, step) in PASSES {
                    let count = frame.height.saturating_sub(start).div_ceil(step);
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
            for x in 0..frame.width {
                let Some(&index) = indices.get(row * frame.width + x) else {
                    continue;
                };
                let out = ((frame.top + y) * width + (frame.left + x)) * 4;
                if out + 4 > canvas.len() {
                    continue;
                }
                if frame.transparent == Some(index) {
                    continue;
                }
                let [r, g, b] = palette.get(index as usize).copied().unwrap_or([0, 0, 0]);
                canvas[out] = r;
                canvas[out + 1] = g;
                canvas[out + 2] = b;
                canvas[out + 3] = 255;
            }
        }

        if let Some(prev) = list.displayed.last() {
            list.differences.push(difference(prev, &canvas));
        }
        list.displayed.push(canvas.clone());

        // Apply disposal for the next frame.
        match frame.disposal {
            2 => {
                if let Some([r, g, b]) = background {
                    let width = *w;
                    for y in frame.top..(frame.top + frame.height).min(*h) {
                        for x in frame.left..(frame.left + frame.width).min(*w) {
                            let at = (y * width + x) * 4;
                            canvas[at] = *r;
                            canvas[at + 1] = *g;
                            canvas[at + 2] = *b;
                            canvas[at + 3] = 255;
                        }
                    }
                }
            }
            3 => {
                if let Some(saved) = saved {
                    canvas = saved;
                }
            }
            _ => {}
        }
    }

    Ok(list)
}

/// Per-channel absolute difference between two composited RGBA frames. Unchanged
/// pixels are exactly zero, and a one-bit change in any channel is a one.
fn difference(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x.abs_diff(*y)).collect()
}

/// What an animation decoded to: the displayed frames, the consecutive
/// differences between them, and the timing of each frame that made it under the
/// budget.
struct List {
    displayed: Vec<Vec<u8>>,
    differences: Vec<Vec<u8>>,
    timings: Vec<Timing>,
}

impl List {
    fn header(&mut self, parsed: &Parsed) -> Header {
        Header {
            width: parsed.screen_width,
            height: parsed.screen_height,
            frames: self.timings.len(),
            declared_frames: parsed.frames.len(),
            interlaced: false,
            palette_entries: parsed.global_palette.len(),
            timings: core::mem::take(&mut self.timings),
        }
    }
}

/// Return type of `decode_frames`, factored to satisfy clippy's type complexity.
type DecodedFrames = (Header, Vec<Vec<u8>>, Vec<Vec<u8>>, bool);

/// Decodes all displayed frames and the consecutive differences between them.
///
/// Returns the header, one RGBA canvas per displayed frame, one difference per
/// pair of consecutive displayed frames, and whether the work budget stopped
/// the walk before the file's frames were exhausted.
pub fn decode_frames(file: &[u8]) -> Result<DecodedFrames, GifError> {
    let parsed = parse(file)?;
    let mut list = compose(&parsed, MAX_FRAMES)?;
    let capped = list.timings.len() < parsed.frames.len();

    let header = list.header(&parsed);
    Ok((header, list.displayed, list.differences, capped))
}

/// Decodes the first composited display frame to non-premultiplied RGBA8, which is
/// all `pixels::decode()` wants. Each pixel tool asks for it afresh, so the rest of
/// the animation stays undecoded here.
pub fn decode(file: &[u8]) -> Result<(Header, Vec<u8>), GifError> {
    let parsed = parse(file)?;
    let mut list = compose(&parsed, 1)?;
    let first = list.displayed.pop().ok_or(GifError::NoImage)?;
    Ok((list.header(&parsed), first))
}

/// Runs the pixel detectors over one frame or difference, as the fields of a source.
fn push_detectors(
    out: &mut String,
    rgba: &[u8],
    header: &Header,
    tags: &[String],
    max_bytes: usize,
    chi_steps: usize,
) {
    use crate::cuttlefish;
    use crate::json::push_string;

    push_string(out, "lsb");
    out.push(':');
    out.push_str(&cuttlefish::sweep_json_naming(
        rgba,
        header.width,
        header.height,
        false,
        max_bytes,
        tags,
    ));
    out.push(',');

    push_string(out, "chi");
    out.push(':');
    out.push_str(&cuttlefish::chi_square_json(rgba, chi_steps));
    out.push(',');

    push_string(out, "rs");
    out.push(':');
    let estimate = cuttlefish::rs::analyse(rgba, header.width, header.height, 3);
    out.push_str(&cuttlefish::rs::json(&estimate));
}

/// Every displayed frame and consecutive difference through the pixel detectors, as
/// JSON. The raw pixels and plane walls stay behind.
///
/// Null for a file that is not a GIF, and an object carrying `error` for one this
/// reader refuses, so a person is told why rather than that it was never a GIF.
pub fn analysis_json(file: &[u8], tags: &[String], max_bytes: usize, chi_steps: usize) -> String {
    use crate::json::{push_bool, push_field, push_number, push_string};

    if !has_signature(file) {
        return "null".to_string();
    }

    let mut out = String::from("{");
    let (header, frames, differences, capped) = match decode_frames(file) {
        Ok(decoded) => decoded,
        Err(error) => {
            push_number(&mut out, "width", u16_at(file, 6).unwrap_or(0));
            out.push(',');
            push_number(&mut out, "height", u16_at(file, 8).unwrap_or(0));
            out.push(',');
            push_number(&mut out, "declaredFrames", 0);
            out.push(',');
            push_number(&mut out, "analysedFrames", 0);
            out.push(',');
            push_bool(&mut out, "capped", false);
            out.push(',');
            push_field(&mut out, "error", &error.to_string());
            out.push(',');
            push_string(&mut out, "sources");
            out.push_str(":[]}");
            return out;
        }
    };

    push_number(&mut out, "width", header.width);
    out.push(',');
    push_number(&mut out, "height", header.height);
    out.push(',');
    push_number(&mut out, "declaredFrames", header.declared_frames);
    out.push(',');
    push_number(&mut out, "analysedFrames", frames.len());
    out.push(',');
    push_bool(&mut out, "capped", capped);
    out.push(',');
    push_string(&mut out, "error");
    out.push_str(":null,");
    push_string(&mut out, "sources");
    out.push_str(":[");

    for (index, frame) in frames.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let timing = header.timings[index];
        out.push('{');
        push_field(&mut out, "kind", "frame");
        out.push(',');
        push_number(&mut out, "from", index + 1);
        out.push(',');
        push_string(&mut out, "to");
        out.push_str(":null,");
        push_number(&mut out, "delay", timing.delay as usize);
        out.push(',');
        push_field(&mut out, "disposal", timing.disposal_name());
        out.push(',');
        push_detectors(&mut out, frame, &header, tags, max_bytes, chi_steps);
        out.push('}');
    }

    for (index, difference) in differences.iter().enumerate() {
        out.push(',');
        out.push('{');
        push_field(&mut out, "kind", "difference");
        out.push(',');
        push_number(&mut out, "from", index + 1);
        out.push(',');
        push_number(&mut out, "to", index + 2);
        out.push(',');
        // A difference between two frames has no timing of its own.
        push_string(&mut out, "delay");
        out.push_str(":null,");
        push_string(&mut out, "disposal");
        out.push_str(":null,");
        push_detectors(&mut out, difference, &header, tags, max_bytes, chi_steps);
        out.push('}');
    }

    out.push_str("]}");
    out
}

/// Bytes after the trailer, which a viewer never reads.
pub fn trailing(file: &[u8]) -> Option<(usize, usize)> {
    if !has_signature(file) {
        return None;
    }

    let packed = *file.get(10)?;
    let global_entries = if packed & 0x80 != 0 {
        2usize << (packed & 0x07)
    } else {
        0
    };
    let mut at = 13 + global_entries * 3;
    loop {
        match *file.get(at)? {
            0x3b => {
                let end = at + 1;
                return (file.len() > end).then(|| (end, file.len() - end));
            }
            0x21 => at = skip_sub_blocks(file, at + 2)?,
            0x2c => {
                let packed = *file.get(at + 9)?;
                let local_entries = if packed & 0x80 != 0 {
                    2usize << (packed & 0x07)
                } else {
                    0
                };
                at = skip_sub_blocks(file, at + 10 + local_entries * 3 + 1)?;
            }
            _ => return None,
        }
    }
}

/// Where a run of sub-blocks ends, without keeping what is in them.
fn skip_sub_blocks(file: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *file.get(at)? as usize;
        at += 1;
        if len == 0 {
            return Some(at);
        }
        at += len;
    }
}

/// Comment blocks, which hold plain text and are a common hiding place.
pub fn comments(file: &[u8]) -> Vec<(usize, String)> {
    comments_only(file).unwrap_or_default()
}

fn comments_only(file: &[u8]) -> Option<Vec<(usize, String)>> {
    let packed = *file.get(10)?;
    let global_entries = if packed & 0x80 != 0 {
        2usize << (packed & 0x07)
    } else {
        0
    };
    let mut at = 13 + global_entries * 3;
    let mut out = Vec::new();
    while let Some(&marker) = file.get(at) {
        match marker {
            0x3b => return Some(out),
            0x21 => {
                let label = *file.get(at + 1)?;
                let (data, next) = sub_blocks(file, at + 2)?;
                if label == 0xfe {
                    out.push((at, crate::json::latin1(&data)));
                }
                at = next;
            }
            0x2c => {
                let packed = file.get(at + 9).copied()?;
                let local_entries = if packed & 0x80 != 0 {
                    2usize << (packed & 0x07)
                } else {
                    0
                };
                let local_bytes = local_entries * 3;
                let code_at = at + 10 + local_bytes;
                let (_, next) = sub_blocks(file, code_at + 1)?;
                at = next;
            }
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests;
