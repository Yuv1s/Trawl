//! What can be said about any file, whatever its format.
//!
//! Flag shapes, printable strings, embedded signatures and entropy are all
//! properties of bytes. Refusing to report them because the container is not one
//! we can walk would be withholding work already done.

use crate::json::{push_bool, push_field, push_number, push_string};
use crate::{bytes, exif, jpeg, png};

const STRING_MIN: usize = 6;
const STRING_SAMPLE: usize = 300;
const ENTROPY_POINTS: usize = 256;
const FLAG_RADIUS: usize = 512;

/// Judges a flag-shaped match by the neighbourhood it was found in.
///
/// Compressed and encrypted regions are close to uniform, so the shape turns up
/// there by chance across a large enough file. This is the general form of the
/// rule the PNG walker applies structurally, and it works on formats whose
/// structure we cannot read.
fn credible(data: &[u8], offset: usize) -> (String, bool) {
    let entropy = bytes::local_entropy(data, offset, FLAG_RADIUS);

    if entropy > bytes::COMPRESSED_ENTROPY {
        (format!("high-entropy region, {entropy:.1} bits/byte"), false)
    } else {
        (format!("readable region, {entropy:.1} bits/byte"), true)
    }
}

/// The TIFF block, wherever this format keeps it.
///
/// JPEG carries it in an APP1 segment behind an `Exif\0\0` prefix; PNG carries
/// the same block raw in an `eXIf` chunk. One walker reads both.
fn exif_block(data: &[u8]) -> Option<&[u8]> {
    if jpeg::has_signature(data) {
        return jpeg::exif_payload(data);
    }

    if png::has_signature(data) {
        return png::chunk_payload(data, b"eXIf");
    }

    None
}

pub fn json(data: &[u8]) -> String {
    let mut out = String::from("{");

    push_number(&mut out, "size", data.len());

    out.push(',');
    push_string(&mut out, "format");
    out.push(':');
    match bytes::identify(data) {
        Some(label) => push_string(&mut out, label),
        None => out.push_str("null"),
    }

    out.push(',');
    push_string(&mut out, "flags");
    out.push_str(":[");

    let mut first = true;
    let mut emit_flag = |out: &mut String, offset: usize, text: &str, region: &str, ok: bool| {
        if !first {
            out.push(',');
        }
        first = false;
        out.push('{');
        push_number(out, "offset", offset);
        out.push(',');
        push_field(out, "text", text);
        out.push(',');
        push_field(out, "region", region);
        out.push(',');
        push_bool(out, "credible", ok);
        out.push('}');
    };

    for found in bytes::flag_candidates(data) {
        let (region, ok) = credible(data, found.offset);
        emit_flag(&mut out, found.offset, &found.text, &region, ok);
    }

    // A flag written as UTF-16LE has a null between every character, so the
    // byte-level scan walks straight past it. Search the decoded text as well.
    for wide in bytes::utf16le_strings(data, STRING_MIN) {
        for found in bytes::flag_candidates(wide.text.as_bytes()) {
            emit_flag(
                &mut out,
                wide.offset + found.offset * 2,
                &found.text,
                "UTF-16LE text",
                true,
            );
        }
    }

    out.push(']');

    out.push(',');
    push_string(&mut out, "magic");
    out.push_str(":[");
    for (i, hit) in bytes::magic_scan(data).iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_number(&mut out, "offset", hit.offset);
        out.push(',');
        push_field(&mut out, "label", hit.label);
        out.push(',');
        push_number(&mut out, "length", hit.length);
        out.push(',');
        push_bool(&mut out, "bounded", hit.bounded);
        out.push(',');
        push_bool(&mut out, "embedded", hit.offset > 0);
        out.push('}');
    }
    out.push(']');

    // Both encodings, merged in file order. A single-byte scan walks straight past
    // UTF-16LE, which is how Windows tools write text.
    let mut strings = bytes::ascii_strings(data, STRING_MIN);
    let wide_total = {
        let wide = bytes::utf16le_strings(data, STRING_MIN);
        let count = wide.len();
        strings.extend(wide);
        count
    };
    strings.sort_by_key(|f| f.offset);

    out.push(',');
    push_string(&mut out, "strings");
    out.push_str(":{");
    push_number(&mut out, "total", strings.len());
    out.push(',');
    push_number(&mut out, "wide", wide_total);
    out.push(',');
    push_string(&mut out, "sample");
    out.push_str(":[");
    for (i, found) in strings.iter().take(STRING_SAMPLE).enumerate() {
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

    out.push(',');
    push_string(&mut out, "exif");
    out.push(':');
    match exif_block(data).map(exif::parse) {
        Some(Ok(entries)) => out.push_str(&exif::json(&entries)),
        Some(Err(_)) => out.push_str("[]"),
        None => out.push_str("null"),
    }

    out.push(',');
    push_string(&mut out, "jpegSegments");
    out.push_str(":[");
    for (i, segment) in jpeg::segments(data).iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "name", segment.name);
        out.push(',');
        push_number(&mut out, "marker", segment.marker as usize);
        out.push(',');
        push_number(&mut out, "offset", segment.offset);
        out.push(',');
        push_number(&mut out, "length", segment.length);
        out.push('}');
    }
    out.push(']');

    out.push(',');
    push_string(&mut out, "jpegComments");
    out.push_str(":[");
    for (i, (offset, text)) in jpeg::comments(data).iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_number(&mut out, "offset", *offset);
        out.push(',');
        push_field(&mut out, "text", text);
        out.push('}');
    }
    out.push(']');

    out.push(',');
    push_string(&mut out, "jpegTrailing");
    out.push(':');
    match jpeg::trailing(data) {
        Some((offset, length)) => {
            out.push('{');
            push_number(&mut out, "offset", offset);
            out.push(',');
            push_number(&mut out, "length", length);
            out.push('}');
        }
        None => out.push_str("null"),
    }

    let (window, values) = bytes::entropy_profile(data, ENTROPY_POINTS);
    out.push(',');
    push_string(&mut out, "entropy");
    out.push_str(":{");
    push_number(&mut out, "window", window);
    out.push(',');
    push_string(&mut out, "values");
    out.push_str(":[");
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("{value:.3}"));
    }
    out.push_str("]}}");

    out
}

#[cfg(test)]
mod tests;
