//! Reading a flag out of text that was encoded to keep it out of sight.
//!
//! A recon scan fetches a page as text, and a plain flag in it is already found.
//! This is for the ones that are not plain: a variable holding base64, a comment
//! rotated thirteen places, a colour written as CSS escapes, an array of numbers
//! XORed against a byte, an ETag written backwards. Each is a reading the source
//! suggests, and the filter is the one the plain scan already uses: a decoding
//! is kept only when a flag falls out of it. That is what lets every reading be
//! tried on every token and still stay silent on a page that hid nothing.

use trawl_core::bytes;

/// A flag a decoding revealed, and the reading that revealed it.
#[derive(Debug, Clone, PartialEq)]
pub struct Harvested {
    pub value: String,
    pub how: String,
}

fn flags_in(data: &[u8]) -> Vec<String> {
    bytes::flag_candidates(data)
        .into_iter()
        .filter(|found| bytes::tag_is_known(&found.text))
        .map(|found| found.text)
        .collect()
}

fn rot13(data: &[u8]) -> Vec<u8> {
    data.iter()
        .map(|&b| match b {
            b'a'..=b'z' => b'a' + (b - b'a' + 13) % 26,
            b'A'..=b'Z' => b'A' + (b - b'A' + 13) % 26,
            other => other,
        })
        .collect()
}

fn from_hex(text: &[u8]) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let digit = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.chunks(2) {
        out.push((digit(pair[0])? << 4) | digit(pair[1])?);
    }
    Some(out)
}

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn from_base64(text: &[u8], alphabet: &[u8]) -> Option<Vec<u8>> {
    let body: Vec<u8> = text.iter().copied().take_while(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &byte in &body {
        let value = alphabet.iter().position(|&c| c == byte)? as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (acc == 0 && !out.is_empty()).then_some(out)
}

/// CSS escapes: `\` then one to six hex digits, an optional trailing space that
/// the syntax uses to end the run. A colour or a caption written this way reads
/// as bytes once the escapes are turned back.
fn css_unescape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'\\' {
            let start = i + 1;
            let mut end = start;
            while end < data.len() && end - start < 6 && data[end].is_ascii_hexdigit() {
                end += 1;
            }
            if end > start
                && let Ok(text) = core::str::from_utf8(&data[start..end])
                && let Ok(point) = u32::from_str_radix(text, 16)
                && let Some(ch) = char::from_u32(point)
            {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
                i = end + usize::from(end < data.len() && data[end] == b' ');
                continue;
            }
        }
        out.push(data[i]);
        i += 1;
    }
    out
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn is_base64(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_')
}

/// Maximal runs of bytes that all satisfy `keep`, each at least `min` long.
fn runs(data: &[u8], keep: impl Fn(u8) -> bool, min: usize) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, &byte) in data.iter().enumerate() {
        match (keep(byte), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= min {
                    out.push(&data[s..i]);
                }
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start
        && data.len() - s >= min
    {
        out.push(&data[s..]);
    }
    out
}

/// Arrays of small integers, `[75, 65, 76, ...]`, read as bytes. A payload
/// written this way is usually one XOR away from readable.
fn int_arrays(text: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < text.len() && out.len() < MAX_ARRAYS {
        if text[i] != b'[' {
            i += 1;
            continue;
        }
        let mut bytes = Vec::new();
        let mut number: Option<u32> = None;
        let mut j = i + 1;
        let mut ok = true;
        while j < text.len() && text[j] != b']' {
            match text[j] {
                b'0'..=b'9' => {
                    let digit = (text[j] - b'0') as u32;
                    number = Some(number.unwrap_or(0) * 10 + digit);
                    if number.unwrap() > 255 {
                        ok = false;
                        break;
                    }
                }
                b',' | b' ' | b'\n' | b'\r' | b'\t' => {
                    if let Some(value) = number.take() {
                        bytes.push(value as u8);
                    }
                }
                _ => {
                    ok = false;
                    break;
                }
            }
            if bytes.len() > MAX_ARRAY_LEN {
                ok = false;
                break;
            }
            j += 1;
        }
        if ok && j < text.len() {
            if let Some(value) = number {
                bytes.push(value as u8);
            }
            if bytes.len() >= 4 {
                out.push(bytes);
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Ceilings so a large page cannot make the harvest crawl. The flag filter keeps
/// the output honest; these keep the work bounded.
const MAX_TOKENS: usize = 4096;
const MAX_ARRAYS: usize = 64;
const MAX_ARRAY_LEN: usize = 4096;
const MAX_HARVESTED: usize = 64;

fn add(out: &mut Vec<Harvested>, values: Vec<String>, how: &str) {
    for value in values {
        if out.len() >= MAX_HARVESTED {
            return;
        }
        if !out.iter().any(|found| found.value == value) {
            out.push(Harvested {
                value,
                how: how.to_string(),
            });
        }
    }
}

/// Every flag a battery of decodings reads out of a run of text, each tagged
/// with the reading that found it. Empty for text that was hiding nothing.
pub fn harvest(text: &[u8]) -> Vec<Harvested> {
    let mut out: Vec<Harvested> = Vec::new();

    add(&mut out, flags_in(&rot13(text)), "ROT13");

    if text.contains(&b'\\') {
        add(&mut out, flags_in(&css_unescape(text)), "CSS escapes");
    }

    for token in runs(text, is_hex, 16).into_iter().take(MAX_TOKENS) {
        if let Some(decoded) = from_hex(token) {
            add(&mut out, flags_in(&decoded), "hex");
        }
    }

    for token in runs(text, is_base64, 16).into_iter().take(MAX_TOKENS) {
        if let Some(decoded) = from_base64(token, B64).or_else(|| from_base64(token, B64_URL)) {
            add(&mut out, flags_in(&decoded), "base64");
        }
        let reversed: Vec<u8> = token.iter().rev().copied().collect();
        if let Some(decoded) =
            from_base64(&reversed, B64).or_else(|| from_base64(&reversed, B64_URL))
        {
            add(&mut out, flags_in(&decoded), "reversed base64");
        }
    }

    for array in int_arrays(text) {
        for key in 1u8..=255 {
            let xored: Vec<u8> = array.iter().map(|&b| b ^ key).collect();
            add(&mut out, flags_in(&xored), &format!("XOR 0x{key:02x}"));
        }
    }

    out
}

#[cfg(test)]
mod tests;
