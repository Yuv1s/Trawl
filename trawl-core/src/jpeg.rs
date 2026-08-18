//! JPEG segment walking. Structure only, no decoding.
//!
//! A JPEG is a sequence of marker segments: 0xFF, a marker byte, then for most
//! markers a big-endian length covering itself and the payload. Two things make
//! it messier than PNG. Some markers carry no length at all, and the scan data
//! after SOS is raw entropy-coded bytes that must be skipped by hunting for the
//! next real marker.

pub mod dct;
pub mod stego;

#[cfg(test)]
pub(crate) mod fixture;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub marker: u8,
    pub name: &'static str,
    /// Offset of the 0xFF that begins the marker.
    pub offset: usize,
    /// Payload length, excluding the marker and the length field itself.
    pub length: usize,
    pub data_offset: usize,
}

pub fn has_signature(file: &[u8]) -> bool {
    file.starts_with(&[0xff, 0xd8])
}

fn name_of(marker: u8) -> &'static str {
    match marker {
        0xd8 => "SOI",
        0xd9 => "EOI",
        0xda => "SOS",
        0xc0 => "SOF0 baseline",
        0xc1 => "SOF1 extended",
        0xc2 => "SOF2 progressive",
        0xc3 => "SOF3 lossless",
        0xc4 => "DHT",
        0xc8 => "JPG",
        0xcc => "DAC",
        0xdb => "DQT",
        0xdc => "DNL",
        0xdd => "DRI",
        0xde => "DHP",
        0xdf => "EXP",
        0xfe => "COM",
        0xe0 => "APP0 JFIF",
        0xe1 => "APP1 EXIF or XMP",
        0xe2 => "APP2",
        0xed => "APP13 Photoshop",
        0xee => "APP14 Adobe",
        0xe3..=0xef => "APPn",
        0xd0..=0xd7 => "RST",
        0x01 => "TEM",
        _ => "unknown",
    }
}

/// Markers that stand alone with no length field.
fn is_standalone(marker: u8) -> bool {
    matches!(marker, 0xd8 | 0xd9 | 0x01 | 0xd0..=0xd7)
}

/// From `at`, finds the next 0xFF that starts a real marker.
///
/// Inside scan data a literal 0xFF is stuffed as 0xFF 0x00, and restart markers
/// are sprinkled through legitimately, so both are skipped.
fn next_marker(file: &[u8], at: usize) -> Option<usize> {
    let mut i = at;
    while i + 1 < file.len() {
        if file[i] == 0xff {
            let next = file[i + 1];
            if next != 0x00 && next != 0xff && !matches!(next, 0xd0..=0xd7) {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Walks every marker segment, stopping at the first one that cannot be read.
///
/// Tolerant by design: a length field that overruns the file is a finding, not a
/// reason to abandon the walk.
pub fn segments(file: &[u8]) -> Vec<Segment> {
    let mut out = Vec::new();
    if !has_signature(file) {
        return out;
    }

    let mut at = 0usize;

    while at + 1 < file.len() {
        if file[at] != 0xff {
            match next_marker(file, at) {
                Some(found) => at = found,
                None => break,
            }
        }

        let marker = file[at + 1];
        if marker == 0xff {
            at += 1;
            continue;
        }

        if is_standalone(marker) {
            out.push(Segment {
                marker,
                name: name_of(marker),
                offset: at,
                length: 0,
                data_offset: at + 2,
            });
            if marker == 0xd9 {
                break;
            }
            at += 2;
            continue;
        }

        let Some(field) = file.get(at + 2..at + 4) else {
            break;
        };
        let declared = u16::from_be_bytes([field[0], field[1]]) as usize;
        if declared < 2 {
            break;
        }

        let length = declared - 2;
        let data_offset = at + 4;
        if data_offset + length > file.len() {
            // Record the liar, then stop: nothing after it can be located.
            out.push(Segment {
                marker,
                name: name_of(marker),
                offset: at,
                length,
                data_offset,
            });
            break;
        }

        out.push(Segment {
            marker,
            name: name_of(marker),
            offset: at,
            length,
            data_offset,
        });

        at = data_offset + length;

        // Scan data follows SOS and contains no length information.
        if marker == 0xda {
            match next_marker(file, at) {
                Some(found) => at = found,
                None => break,
            }
        }
    }

    out
}

pub fn segment_data(file: &[u8], segment: Segment) -> &[u8] {
    let end = (segment.data_offset + segment.length).min(file.len());
    file.get(segment.data_offset..end).unwrap_or(&[])
}

/// COM comments, which are plain text and a common hiding place.
pub fn comments(file: &[u8]) -> Vec<(usize, String)> {
    segments(file)
        .into_iter()
        .filter(|s| s.marker == 0xfe)
        .map(|s| (s.offset, crate::json::latin1(segment_data(file, s))))
        .collect()
}

/// The TIFF block inside APP1, which is where EXIF lives.
pub fn exif_payload(file: &[u8]) -> Option<&[u8]> {
    segments(file)
        .into_iter()
        .filter(|s| s.marker == 0xe1)
        .find_map(|s| segment_data(file, s).strip_prefix(b"Exif\0\0"))
}

/// Width and height from whichever start-of-frame marker appears.
pub fn dimensions(file: &[u8]) -> Option<(u16, u16)> {
    segments(file)
        .iter()
        .filter(|s| matches!(s.marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf))
        .find_map(|s| {
            let data = segment_data(file, *s);
            let bytes = data.get(1..5)?;
            Some((
                u16::from_be_bytes([bytes[2], bytes[3]]),
                u16::from_be_bytes([bytes[0], bytes[1]]),
            ))
        })
}

/// Bytes after the end-of-image marker. A JPEG is complete at EOI.
pub fn trailing(file: &[u8]) -> Option<(usize, usize)> {
    let eoi = segments(file).into_iter().find(|s| s.marker == 0xd9)?;
    let end = eoi.offset + 2;
    (file.len() > end).then(|| (end, file.len() - end))
}

#[cfg(test)]
mod tests;
