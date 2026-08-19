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
    let body = body
        .strip_suffix(b"~>".as_slice())
        .unwrap_or(&body)
        .to_vec();

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
    if !data
        .iter()
        .all(|&b| (b'!'..=b'~').contains(&b) || b.is_ascii_whitespace())
    {
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

/// Bitcoin's base58 alphabet: no zero, capital O, capital I or lowercase l,
/// because those are the pairs people mistype when copying by hand.
const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58, which cannot be done by shifting bits.
///
/// Every other base here divides the byte evenly: base64 takes six bits at a
/// time, base32 five. 58 is not a power of two, so there is no bit boundary to
/// cut on and the whole string has to be treated as one long number in base 58
/// and divided back down into bytes.
///
/// Leading zero bytes are the exception, because a number does not remember how
/// many zeroes preceded it. They are carried separately, as leading `1`s.
pub fn base58(data: &[u8]) -> Option<Vec<u8>> {
    let clean = unwrap_lines(data);
    if clean.len() < MIN_LENGTH || !looks_encoded(&clean) {
        return None;
    }

    let mut out: Vec<u8> = Vec::with_capacity(clean.len());

    for &byte in &clean {
        let mut carry = value_in(BASE58, byte)?;

        for digit in out.iter_mut().rev() {
            carry += *digit as u32 * 58;
            *digit = (carry & 0xff) as u8;
            carry >>= 8;
        }

        while carry > 0 {
            out.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let zeroes = clean.iter().take_while(|&&b| b == b'1').count();
    let mut result = vec![0u8; zeroes];
    result.extend(out.iter().skip_while(|&&b| b == 0));

    (!result.is_empty()).then_some(result)
}

/// Quoted-printable, as email bodies carry text that is almost but not quite
/// ASCII.
///
/// `=` starts an escape: two hex digits for a byte, or an end of line for a
/// break that the encoder inserted and the reader should not see.
pub fn quoted_printable(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < MIN_LENGTH || !data.contains(&b'=') {
        return None;
    }

    let hex = |b: u8| (b as char).to_digit(16);
    let mut out = Vec::with_capacity(data.len());
    let mut at = 0usize;
    let mut escapes = 0usize;

    while at < data.len() {
        if data[at] != b'=' {
            out.push(data[at]);
            at += 1;
            continue;
        }

        escapes += 1;

        match data.get(at + 1) {
            // A soft break: the encoder wrapped the line, so drop it.
            Some(b'\r') if data.get(at + 2) == Some(&b'\n') => at += 3,
            Some(b'\n') => at += 2,
            Some(&high) => {
                let low = *data.get(at + 2)?;
                out.push((hex(high)? * 16 + hex(low)?) as u8);
                at += 3;
            }
            // A trailing `=` with nothing after it is not an encoding.
            None => return None,
        }
    }

    // Text with no escapes in it is not evidence of anything: this codec would
    // otherwise accept any sentence containing an equals sign and hand it back
    // unchanged.
    (escapes > 0).then_some(out)
}

/// uuencode, which predates base64 and still turns up wrapped around mail
/// attachments.
///
/// Each line begins with its own decoded length, offset by 32 so it prints, and
/// then encodes three bytes into four characters six bits at a time, each also
/// offset by 32. A `begin` header and an `end` footer are optional here, since
/// what usually gets pasted is the body alone.
pub fn uuencode(data: &[u8]) -> Option<Vec<u8>> {
    let text = core::str::from_utf8(data).ok()?;
    let mut out = Vec::new();
    let mut lines = 0usize;

    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        let raw = line.as_bytes();

        if line.starts_with("begin ") || line == "end" || raw.is_empty() {
            continue;
        }

        // A backtick and a space both mean nought, which is how a zero-length
        // line survives being trimmed by a mail client.
        let length = match raw[0] {
            b'`' => 0,
            byte @ 0x20..=0x60 => (byte - 0x20) as usize,
            _ => return None,
        };

        if length == 0 {
            continue;
        }

        let quads = length.div_ceil(3);
        if raw.len() < 1 + quads * 4 {
            return None;
        }

        let mut decoded = Vec::with_capacity(quads * 3);
        for quad in raw[1..1 + quads * 4].chunks(4) {
            let mut bits = 0u32;
            for &byte in quad {
                let value = match byte {
                    b'`' => 0,
                    0x20..=0x60 => (byte - 0x20) as u32,
                    _ => return None,
                };
                bits = (bits << 6) | value;
            }
            decoded.extend_from_slice(&[(bits >> 16) as u8, (bits >> 8) as u8, bits as u8]);
        }

        decoded.truncate(length);
        out.extend_from_slice(&decoded);
        lines += 1;
    }

    (lines > 0 && !out.is_empty()).then_some(out)
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

/// Standard base64, for building test material and nothing else.
#[cfg(test)]
pub fn base64_of(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();

    for chunk in data.chunks(3) {
        let mut packed = 0u32;
        for (i, &byte) in chunk.iter().enumerate() {
            packed |= (byte as u32) << (16 - 8 * i);
        }
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                BASE64[((packed >> (18 - 6 * i)) & 63) as usize]
            } else {
                b'='
            });
        }
    }

    out
}

/// The alphabet a rotation runs over when digits are part of the ring.
const BASE36: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Rotation over digits and letters together, thirty-six positions round.
///
/// Encoder sites offer this as a Caesar with a custom alphabet, and it is a
/// different cipher from the twenty-six letter one: shifting `Y` by eleven lands
/// on `9` rather than wrapping straight back into the letters. A text rotated
/// this way and then read with the letter alphabet comes out as nonsense, which
/// is why it needs its own pass rather than a wider ring on the existing one.
///
/// Case survives letters but not digits, because a digit has none to remember.
/// A lowercase letter that rotates onto one comes back uppercase.
pub fn rot_base36(data: &[u8], shift: u8) -> Vec<u8> {
    data.iter()
        .map(|&byte| {
            let upper = byte.to_ascii_uppercase();
            match BASE36.iter().position(|&c| c == upper) {
                Some(at) => {
                    let moved = BASE36[(at + shift as usize) % 36];
                    if byte.is_ascii_lowercase() {
                        moved.to_ascii_lowercase()
                    } else {
                        moved
                    }
                }
                None => byte,
            }
        })
        .collect()
}

/// Atbash: the alphabet read backwards, so A becomes Z.
///
/// Its own inverse, and it has no key, so there is nothing to search. It is here
/// because it is common enough in puzzles that its absence is noticeable.
pub fn atbash(data: &[u8]) -> Vec<u8> {
    data.iter()
        .map(|&byte| match byte {
            b'a'..=b'z' => b'z' - (byte - b'a'),
            b'A'..=b'Z' => b'Z' - (byte - b'A'),
            _ => byte,
        })
        .collect()
}
