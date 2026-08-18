//! The codecs Mantis peels.
//!
//! Each one decodes or declines. There is no separate detection step: a codec
//! that accepts the input is a candidate, and whether the result was an
//! improvement is decided afterwards by comparing how much the output looks like
//! something a person would read.
//!
//! That split matters. Deciding "this is base64" by looking at the input alone
//! is guesswork, because plenty of ordinary words are valid base64. Deciding it
//! by looking at what falls out is not.

/// Line breaks an encoded blob picks up from being wrapped or pasted.
///
/// Only newlines. Base64 gets wrapped across lines, it does not get spaces
/// inserted between groups, and stripping spaces too would turn any English
/// sentence into a candidate: drop the spaces from "the quick brown fox" and
/// what is left is a legal base64 string that decodes to noise.
fn unwrap_lines(data: &[u8]) -> Vec<u8> {
    data.iter()
        .copied()
        .filter(|b| !matches!(b, b'\n' | b'\r'))
        .collect()
}

fn value_in(alphabet: &[u8], byte: u8) -> Option<u32> {
    alphabet.iter().position(|&c| c == byte).map(|i| i as u32)
}

const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Shortest input any codec will touch.
///
/// Below this the odds of a short English word being valid base64 stop being a
/// curiosity and start being the common case.
const MIN_LENGTH: usize = 8;

fn base_n(data: &[u8], alphabet: &[u8], bits: u32) -> Option<Vec<u8>> {
    let clean = unwrap_lines(data);
    let body: &[u8] = match clean.iter().position(|&b| b == b'=') {
        Some(at) => {
            // Padding only ever sits at the end.
            if clean[at..].iter().any(|&b| b != b'=') {
                return None;
            }
            &clean[..at]
        }
        None => &clean,
    };

    if body.len() < MIN_LENGTH {
        return None;
    }

    // A length no encoder could have produced. Base64 leaves 0, 2 or 3
    // characters over, never 1, and base32 has its own set. Checking this is
    // most of what separates real base64 from a word that happens to fit.
    let leftover = match bits {
        6 => body.len() % 4,
        5 => body.len() % 8,
        _ => 0,
    };
    let legal = match bits {
        6 => matches!(leftover, 0 | 2 | 3),
        5 => matches!(leftover, 0 | 2 | 4 | 5 | 7),
        _ => true,
    };
    if !legal {
        return None;
    }

    let mut out = Vec::with_capacity(body.len() * bits as usize / 8);
    let mut acc = 0u32;
    let mut held = 0u32;

    for &byte in body {
        let value = value_in(alphabet, byte)?;
        acc = (acc << bits) | value;
        held += bits;

        if held >= 8 {
            held -= 8;
            out.push((acc >> held) as u8);
            acc &= (1 << held) - 1;
        }
    }

    // Leftover bits are the encoder's padding and must be zero. Anything else
    // means this was never really base64, it just looked like it.
    if acc != 0 || out.is_empty() {
        return None;
    }

    Some(out)
}

/// Long enough that the case mix below stops being luck.
const MIXED_CASE_FROM: usize = 16;

/// True when this looks like something a base64 encoder produced.
///
/// The alphabet spans both cases and the digits, so real output of any length
/// uses all three. A long run of nothing but lowercase letters is words, and
/// words of the right length are legal base64 that decodes to noise.
fn looks_encoded(data: &[u8]) -> bool {
    let body: Vec<u8> = data
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();

    if body.len() < MIXED_CASE_FROM {
        return true;
    }

    let lower = body.iter().any(|b| b.is_ascii_lowercase());
    let upper = body.iter().any(|b| b.is_ascii_uppercase());
    let other = body.iter().any(|b| !b.is_ascii_alphabetic());

    (lower && upper) || other
}

pub fn base64(data: &[u8]) -> Option<Vec<u8>> {
    if !looks_encoded(data) {
        return None;
    }
    base_n(data, BASE64, 6)
}

pub fn base64_url(data: &[u8]) -> Option<Vec<u8>> {
    // Only worth trying when it actually differs from the standard alphabet.
    if !data.iter().any(|&b| b == b'-' || b == b'_') || !looks_encoded(data) {
        return None;
    }
    base_n(data, BASE64_URL, 6)
}

pub fn base32(data: &[u8]) -> Option<Vec<u8>> {
    base_n(data, BASE32, 5)
}

/// Ascii85, in the flavour with the `<~ ~>` wrapper made optional.
pub fn ascii85(data: &[u8]) -> Option<Vec<u8>> {
    let clean = unwrap_lines(data);
    let body = clean
        .strip_prefix(b"<~".as_slice())
        .unwrap_or(&clean)
        .to_vec();
    let body = body.strip_suffix(b"~>".as_slice()).unwrap_or(&body).to_vec();

    if body.len() < MIN_LENGTH {
        return None;
    }

    let mut out = Vec::new();
    let mut group = Vec::with_capacity(5);

    for &byte in &body {
        if byte == b'z' && group.is_empty() {
            // The shorthand for four zero bytes.
            out.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }

        if !(b'!'..=b'u').contains(&byte) {
            return None;
        }

        group.push(byte - b'!');
        if group.len() == 5 {
            let mut value = 0u32;
            for &digit in &group {
                value = value.checked_mul(85)?.checked_add(digit as u32)?;
            }
            out.extend_from_slice(&value.to_be_bytes());
            group.clear();
        }
    }

    if !group.is_empty() {
        if group.len() == 1 {
            return None;
        }
        let kept = group.len() - 1;
        while group.len() < 5 {
            group.push(84);
        }
        let mut value = 0u32;
        for &digit in &group {
            value = value.checked_mul(85)?.checked_add(digit as u32)?;
        }
        out.extend_from_slice(&value.to_be_bytes()[..kept]);
    }

    (!out.is_empty()).then_some(out)
}

/// Hex, tolerating the separators people paste it with.
pub fn hex(data: &[u8]) -> Option<Vec<u8>> {
    let clean: Vec<u8> = data
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace() && *b != b':' && *b != b'-')
        .collect();

    let body = clean
        .strip_prefix(b"0x".as_slice())
        .or_else(|| clean.strip_prefix(b"0X".as_slice()))
        .unwrap_or(&clean);

    if body.len() < MIN_LENGTH || body.len() % 2 != 0 {
        return None;
    }

    let digit = |b: u8| (b as char).to_digit(16).map(|d| d as u8);

    let mut out = Vec::with_capacity(body.len() / 2);
    for pair in body.chunks(2) {
        out.push((digit(pair[0])? << 4) | digit(pair[1])?);
    }

    Some(out)
}

/// Percent-encoding, as seen in a URL.
pub fn percent(data: &[u8]) -> Option<Vec<u8>> {
    if !data.contains(&b'%') {
        return None;
    }

    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;

    while i < data.len() {
        if data[i] == b'%' {
            let pair = data.get(i + 1..i + 3)?;
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            out.push(((hi << 4) | lo) as u8);
            i += 3;
        } else {
            // A plus sign means a space in form encoding, and nowhere else.
            out.push(data[i]);
            i += 1;
        }
    }

    Some(out)
}

/// HTML entities, named and numeric.
pub fn html_entities(data: &[u8]) -> Option<Vec<u8>> {
    if !data.contains(&b'&') {
        return None;
    }

    const NAMED: [(&[u8], u8); 6] = [
        (b"amp", b'&'),
        (b"lt", b'<'),
        (b"gt", b'>'),
        (b"quot", b'"'),
        (b"apos", b'\''),
        (b"nbsp", b' '),
    ];

    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    let mut replaced = 0usize;

    while i < data.len() {
        if data[i] != b'&' {
            out.push(data[i]);
            i += 1;
            continue;
        }

        let Some(end) = data[i..].iter().position(|&b| b == b';').map(|p| i + p) else {
            out.push(data[i]);
            i += 1;
            continue;
        };

        let body = &data[i + 1..end];
        let decoded = if let Some(digits) = body.strip_prefix(b"#x".as_slice()) {
            u32::from_str_radix(core::str::from_utf8(digits).ok()?, 16).ok()
        } else if let Some(digits) = body.strip_prefix(b"#".as_slice()) {
            core::str::from_utf8(digits).ok()?.parse::<u32>().ok()
        } else {
            NAMED
                .iter()
                .find(|(name, _)| *name == body)
                .map(|(_, byte)| *byte as u32)
        };

        match decoded {
            Some(value) if value <= 0x10ffff => {
                let c = char::from_u32(value)?;
                let mut buffer = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
                replaced += 1;
                i = end + 1;
            }
            _ => {
                out.push(data[i]);
                i += 1;
            }
        }
    }

    (replaced > 0).then_some(out)
}

/// Text written as ones and zeroes.
pub fn binary(data: &[u8]) -> Option<Vec<u8>> {
    let clean: Vec<u8> = data
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace() && *b != b',')
        .collect();

    if clean.len() < MIN_LENGTH || !clean.len().is_multiple_of(8) {
        return None;
    }
    if !clean.iter().all(|&b| b == b'0' || b == b'1') {
        return None;
    }

    Some(
        clean
            .chunks(8)
            .map(|byte| byte.iter().fold(0u8, |acc, &b| (acc << 1) | (b - b'0')))
            .collect(),
    )
}

/// Byte values written out as numbers.
pub fn decimal(data: &[u8]) -> Option<Vec<u8>> {
    let text = core::str::from_utf8(data).ok()?;
    let parts: Vec<&str> = text
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|p| !p.is_empty())
        .collect();

    if parts.len() < 4 {
        return None;
    }

    let mut out = Vec::with_capacity(parts.len());
    for part in parts {
        let value: u32 = part.parse().ok()?;
        if value > 255 {
            return None;
        }
        out.push(value as u8);
    }

    Some(out)
}

/// Rotates letters by a fixed amount. Thirteen is its own inverse, which is why
/// it caught on.
pub fn rot_n(data: &[u8], shift: u8) -> Vec<u8> {
    data.iter()
        .map(|&b| match b {
            b'a'..=b'z' => b'a' + (b - b'a' + shift) % 26,
            b'A'..=b'Z' => b'A' + (b - b'A' + shift) % 26,
            other => other,
        })
        .collect()
}

pub fn rot13(data: &[u8]) -> Option<Vec<u8>> {
    data.iter()
        .any(|b| b.is_ascii_alphabetic())
        .then(|| rot_n(data, 13))
}

/// Rotates every printable character rather than only the letters.
pub fn rot47(data: &[u8]) -> Option<Vec<u8>> {
    if !data.iter().all(|&b| (b'!'..=b'~').contains(&b) || b.is_ascii_whitespace()) {
        return None;
    }

    Some(
        data.iter()
            .map(|&b| {
                if (b'!'..=b'~').contains(&b) {
                    b'!' + (b - b'!' + 47) % 94
                } else {
                    b
                }
            })
            .collect(),
    )
}

const MORSE: [(&str, u8); 36] = [
    (".-", b'A'),
    ("-...", b'B'),
    ("-.-.", b'C'),
    ("-..", b'D'),
    (".", b'E'),
    ("..-.", b'F'),
    ("--.", b'G'),
    ("....", b'H'),
    ("..", b'I'),
    (".---", b'J'),
    ("-.-", b'K'),
    (".-..", b'L'),
    ("--", b'M'),
    ("-.", b'N'),
    ("---", b'O'),
    (".--.", b'P'),
    ("--.-", b'Q'),
    (".-.", b'R'),
    ("...", b'S'),
    ("-", b'T'),
    ("..-", b'U'),
    ("...-", b'V'),
    (".--", b'W'),
    ("-..-", b'X'),
    ("-.--", b'Y'),
    ("--..", b'Z'),
    ("-----", b'0'),
    (".----", b'1'),
    ("..---", b'2'),
    ("...--", b'3'),
    ("....-", b'4'),
    (".....", b'5'),
    ("-....", b'6'),
    ("--...", b'7'),
    ("---..", b'8'),
    ("----.", b'9'),
];

/// Morse, with `/` or a double space between words.
pub fn morse(data: &[u8]) -> Option<Vec<u8>> {
    let text = core::str::from_utf8(data).ok()?;

    if !text
        .chars()
        .all(|c| matches!(c, '.' | '-' | '/' | ' ' | '\n' | '\r' | '\t' | '|'))
    {
        return None;
    }
    if !text.contains('.') && !text.contains('-') {
        return None;
    }

    let mut out = Vec::new();
    for word in text.split(['/', '|']) {
        if !out.is_empty() {
            out.push(b' ');
        }
        for letter in word.split_whitespace() {
            let found = MORSE.iter().find(|(code, _)| *code == letter)?;
            out.push(found.1);
        }
    }

    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests;
