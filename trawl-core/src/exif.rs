//! EXIF, by way of a hand-written TIFF walker.
//!
//! The format is a TIFF header followed by image file directories. Each IFD is a
//! count, then that many 12-byte entries, then the offset of the next IFD. An
//! entry is a tag, a type, a count, and four bytes that hold the value outright
//! when it fits and an offset when it does not.
//!
//! Every offset is relative to the start of the TIFF header, and every one of
//! them is attacker-controlled. Directories can point at each other in a loop,
//! past the end of the buffer, or at themselves. The walker treats all of that
//! as ordinary input.

use crate::bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(&self, b: &[u8]) -> u16 {
        match self {
            Endian::Little => u16::from_le_bytes([b[0], b[1]]),
            Endian::Big => u16::from_be_bytes([b[0], b[1]]),
        }
    }

    fn u32(&self, b: &[u8]) -> u32 {
        match self {
            Endian::Little => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            Endian::Big => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub ifd: &'static str,
    pub tag: u16,
    pub name: &'static str,
    pub value: String,
    /// True when the value is text a person could have written.
    pub textual: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExifError {
    NoHeader,
    BadByteOrder,
    BadMagic,
}

/// Tags worth naming. The rest are reported by number rather than dropped,
/// because an unusual tag is itself interesting.
fn tag_name(tag: u16) -> &'static str {
    match tag {
        0x010e => "ImageDescription",
        0x010f => "Make",
        0x0110 => "Model",
        0x0112 => "Orientation",
        0x011a => "XResolution",
        0x011b => "YResolution",
        0x0131 => "Software",
        0x0132 => "DateTime",
        0x013b => "Artist",
        0x013e => "WhitePoint",
        0x8298 => "Copyright",
        0x8769 => "ExifIFDPointer",
        0x8825 => "GPSInfoIFDPointer",
        0x829a => "ExposureTime",
        0x829d => "FNumber",
        0x8827 => "ISOSpeedRatings",
        0x9003 => "DateTimeOriginal",
        0x9004 => "DateTimeDigitized",
        0x927c => "MakerNote",
        0x9286 => "UserComment",
        0xa000 => "FlashpixVersion",
        0xa002 => "PixelXDimension",
        0xa003 => "PixelYDimension",
        0xa004 => "RelatedSoundFile",
        0xa420 => "ImageUniqueID",
        0xa430 => "CameraOwnerName",
        0xa433 => "LensMake",
        0xa434 => "LensModel",
        _ => "",
    }
}

fn gps_tag_name(tag: u16) -> &'static str {
    match tag {
        0x0000 => "GPSVersionID",
        0x0001 => "GPSLatitudeRef",
        0x0002 => "GPSLatitude",
        0x0003 => "GPSLongitudeRef",
        0x0004 => "GPSLongitude",
        0x0005 => "GPSAltitudeRef",
        0x0006 => "GPSAltitude",
        0x0007 => "GPSTimeStamp",
        0x001d => "GPSDateStamp",
        _ => "",
    }
}

fn type_size(kind: u16) -> usize {
    match kind {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 => 4,
        5 | 10 | 12 => 8,
        _ => 0,
    }
}

/// Renders an entry's value, keeping text as text and numbers readable.
fn render(endian: Endian, kind: u16, count: usize, raw: &[u8]) -> (String, bool) {
    match kind {
        // ASCII and UNDEFINED both carry text in practice; UserComment is UNDEFINED.
        2 | 7 => {
            let trimmed: Vec<u8> = raw
                .iter()
                .copied()
                .take_while(|&b| b != 0)
                .filter(|&b| b != 0)
                .collect();
            let text = bytes::latin1_lossy(&trimmed);
            let printable = !text.is_empty()
                && trimmed
                    .iter()
                    .all(|&b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\t');
            (text, printable)
        }
        1 | 6 => (
            raw.iter()
                .take(count)
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            false,
        ),
        3 | 8 => (
            raw.as_chunks::<2>().0.iter()
                .take(count)
                .map(|c| endian.u16(c).to_string())
                .collect::<Vec<_>>()
                .join(" "),
            false,
        ),
        4 | 9 => (
            raw.as_chunks::<4>().0.iter()
                .take(count)
                .map(|c| endian.u32(c).to_string())
                .collect::<Vec<_>>()
                .join(" "),
            false,
        ),
        5 | 10 => (
            raw.as_chunks::<8>().0.iter()
                .take(count)
                .map(|c| {
                    let n = endian.u32(&c[0..4]);
                    let d = endian.u32(&c[4..8]);
                    if d == 0 { format!("{n}/0") } else { format!("{n}/{d}") }
                })
                .collect::<Vec<_>>()
                .join(" "),
            false,
        ),
        _ => (format!("{count} values of unknown type {kind}"), false),
    }
}

const MAX_ENTRIES: usize = 512;
const MAX_VALUE_BYTES: usize = 4096;

fn walk_ifd(
    tiff: &[u8],
    endian: Endian,
    offset: usize,
    label: &'static str,
    out: &mut Vec<Entry>,
    seen: &mut Vec<usize>,
    pending: &mut Vec<(usize, &'static str)>,
) {
    if seen.contains(&offset) || seen.len() > 8 {
        return;
    }
    seen.push(offset);

    let Some(header) = tiff.get(offset..offset + 2) else {
        return;
    };
    let count = (endian.u16(header) as usize).min(MAX_ENTRIES);

    for i in 0..count {
        let at = offset + 2 + i * 12;
        let Some(entry) = tiff.get(at..at + 12) else {
            return;
        };

        let tag = endian.u16(&entry[0..2]);
        let kind = endian.u16(&entry[2..4]);
        let values = endian.u32(&entry[4..8]) as usize;

        let unit = type_size(kind);
        if unit == 0 {
            continue;
        }
        let size = unit.saturating_mul(values).min(MAX_VALUE_BYTES);

        let raw: &[u8] = if size <= 4 {
            &entry[8..8 + size.min(4)]
        } else {
            let at = endian.u32(&entry[8..12]) as usize;
            match tiff.get(at..at + size) {
                Some(slice) => slice,
                None => continue,
            }
        };

        // Sub-directories are followed after this one finishes, so the ordering
        // in the report matches the ordering in the file.
        if tag == 0x8769 && label == "IFD0" {
            pending.push((endian.u32(&entry[8..12]) as usize, "EXIF"));
            continue;
        }
        if tag == 0x8825 && label == "IFD0" {
            pending.push((endian.u32(&entry[8..12]) as usize, "GPS"));
            continue;
        }

        let (value, textual) = render(endian, kind, values, raw);
        let named = if label == "GPS" { gps_tag_name(tag) } else { tag_name(tag) };

        out.push(Entry {
            ifd: label,
            tag,
            name: named,
            value,
            textual,
        });
    }

    // The next-IFD pointer sits after the entries.
    let next_at = offset + 2 + count * 12;
    if let Some(slice) = tiff.get(next_at..next_at + 4) {
        let next = endian.u32(slice) as usize;
        if next != 0 && label == "IFD0" {
            walk_ifd(tiff, endian, next, "IFD1 thumbnail", out, seen, pending);
        }
    }
}

/// Parses a TIFF block, as found in a JPEG APP1 segment or a PNG eXIf chunk.
pub fn parse(tiff: &[u8]) -> Result<Vec<Entry>, ExifError> {
    let header = tiff.get(0..8).ok_or(ExifError::NoHeader)?;

    let endian = match &header[0..2] {
        b"II" => Endian::Little,
        b"MM" => Endian::Big,
        _ => return Err(ExifError::BadByteOrder),
    };

    if endian.u16(&header[2..4]) != 42 {
        return Err(ExifError::BadMagic);
    }

    let first = endian.u32(&header[4..8]) as usize;
    let mut out = Vec::new();
    let mut seen = Vec::new();
    let mut pending = Vec::new();

    walk_ifd(tiff, endian, first, "IFD0", &mut out, &mut seen, &mut pending);

    while let Some((offset, label)) = pending.pop() {
        walk_ifd(tiff, endian, offset, label, &mut out, &mut seen, &mut pending);
    }

    Ok(out)
}

pub fn json(entries: &[Entry]) -> String {
    use crate::json::{push_bool, push_field, push_number};

    let mut out = String::from("[");
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "ifd", entry.ifd);
        out.push(',');
        push_number(&mut out, "tag", entry.tag as usize);
        out.push(',');
        push_field(&mut out, "name", entry.name);
        out.push(',');
        push_field(&mut out, "value", &entry.value);
        out.push(',');
        push_bool(&mut out, "textual", entry.textual);
        out.push('}');
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests;
