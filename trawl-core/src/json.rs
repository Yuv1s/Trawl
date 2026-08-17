//! Just enough JSON to get analysis results across the WASM boundary.
//!
//! wasm-bindgen structs are handles into linear memory, so they cannot survive a
//! `postMessage` out of the worker. A string can. serde would do this too, but it
//! is a dependency and this is thirty lines.

pub fn push_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str("\\u");
                for shift in [12, 8, 4, 0] {
                    out.push(char::from_digit((c as u32 >> shift) & 0xf, 16).unwrap());
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn push_field(out: &mut String, key: &str, value: &str) {
    push_string(out, key);
    out.push(':');
    push_string(out, value);
}

pub fn push_number(out: &mut String, key: &str, value: usize) {
    push_string(out, key);
    out.push(':');
    out.push_str(&value.to_string());
}

pub fn push_bool(out: &mut String, key: &str, value: bool) {
    push_string(out, key);
    out.push(':');
    out.push_str(if value { "true" } else { "false" });
}

/// Latin-1, which is what PNG text chunks and most legacy metadata actually hold.
/// Decoding those as UTF-8 turns a valid 0xE9 into a replacement character.
pub fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_the_characters_json_cannot_hold_raw() {
        let mut out = String::new();
        push_string(&mut out, "a\"b\\c\nd\te");
        assert_eq!(out, "\"a\\\"b\\\\c\\nd\\te\"");
    }

    #[test]
    fn escapes_control_bytes_as_four_digit_hex() {
        let mut out = String::new();
        push_string(&mut out, "\u{1}\u{1f}\u{7f}");
        assert_eq!(out, "\"\\u0001\\u001f\\u007f\"");
    }

    #[test]
    fn latin1_maps_high_bytes_without_replacement_characters() {
        assert_eq!(latin1(&[0x41, 0xe9, 0xff]), "A\u{e9}\u{ff}");
        assert_eq!(latin1(&[0x80]).chars().next(), Some('\u{80}'));
    }
}
