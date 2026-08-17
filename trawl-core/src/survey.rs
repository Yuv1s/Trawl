//! What can be said about any file, whatever its format.
//!
//! Flag shapes, printable strings, embedded signatures and entropy are all
//! properties of bytes. Refusing to report them because the container is not one
//! we can walk would be withholding work already done.

use crate::bytes;
use crate::json::{push_bool, push_field, push_number, push_string};

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
    for (i, found) in bytes::flag_candidates(data).iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let (region, ok) = credible(data, found.offset);
        out.push('{');
        push_number(&mut out, "offset", found.offset);
        out.push(',');
        push_field(&mut out, "text", &found.text);
        out.push(',');
        push_field(&mut out, "region", &region);
        out.push(',');
        push_bool(&mut out, "credible", ok);
        out.push('}');
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
        push_bool(&mut out, "embedded", hit.offset > 0);
        out.push('}');
    }
    out.push(']');

    let strings = bytes::ascii_strings(data, STRING_MIN);
    out.push(',');
    push_string(&mut out, "strings");
    out.push_str(":{");
    push_number(&mut out, "total", strings.len());
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
