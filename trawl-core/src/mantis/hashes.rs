//! What a hash is, from its shape.
//!
//! Two kinds of answer, and the difference matters more than the answer does.
//!
//! Some strings declare themselves. A password hash starting `$2b$` is bcrypt
//! because bcrypt wrote that prefix, and there is nothing to guess. A JSON Web
//! Token carries a header naming its own algorithm, and that header can be read
//! rather than assumed.
//!
//! Everything else is shape alone, and shape does not narrow to one answer.
//! Thirty-two hex digits is MD5. It is also NTLM, MD4 and LM, and no amount of
//! staring at the string will separate them, because there is nothing in it to
//! separate. Tools that print "MD5" and stop are guessing and hiding it.
//!
//! Identifying a hash is also the only way to stop treating it as something to
//! unwrap. Thirty-two hex digits decode perfectly well into sixteen bytes of
//! noise, and without this the peeler did exactly that and presented the noise.

use crate::json::latin1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identified {
    /// Formats this could be. More than one whenever the shape cannot separate
    /// them, which is most of the time.
    pub candidates: Vec<&'static str>,
    /// True when the string declares its own format rather than merely fitting.
    pub certain: bool,
    /// Digest size, where the shape implies one.
    pub bits: Option<usize>,
    /// The shape that was matched, in words.
    pub shape: String,
}

impl Identified {
    fn declared(name: &'static str, shape: impl Into<String>) -> Self {
        Self {
            candidates: vec![name],
            certain: true,
            bits: None,
            shape: shape.into(),
        }
    }
}

/// Password hashes that begin with their own name.
const PREFIXED: [(&str, &str); 14] = [
    ("$2a$", "bcrypt"),
    ("$2b$", "bcrypt"),
    ("$2x$", "bcrypt"),
    ("$2y$", "bcrypt"),
    ("$1$", "md5crypt"),
    ("$5$", "sha256crypt"),
    ("$6$", "sha512crypt"),
    ("$argon2id$", "Argon2id"),
    ("$argon2i$", "Argon2i"),
    ("$argon2d$", "Argon2d"),
    ("$scrypt$", "scrypt"),
    ("$7$", "scrypt"),
    ("$y$", "yescrypt"),
    ("pbkdf2_sha256$", "Django PBKDF2-SHA256"),
];

/// Hex digest lengths, and everything that produces one.
///
/// The lists are the point. A single name here would be a lie of omission.
const BY_LENGTH: [(usize, usize, &[&str]); 8] = [
    (8, 32, &["CRC-32", "Adler-32"]),
    (16, 64, &["MySQL 3.x", "half of an MD5"]),
    (32, 128, &["MD5", "NTLM", "MD4", "LM"]),
    (
        40,
        160,
        &["SHA-1", "RIPEMD-160", "MySQL 4.1+ without its asterisk"],
    ),
    (56, 224, &["SHA-224", "SHA3-224"]),
    (64, 256, &["SHA-256", "SHA3-256", "BLAKE2s", "Keccak-256"]),
    (96, 384, &["SHA-384", "SHA3-384"]),
    (128, 512, &["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"]),
];

fn is_hex(data: &[u8]) -> bool {
    !data.is_empty() && data.iter().all(|b| b.is_ascii_hexdigit())
}

/// The three dot-separated parts of a JSON Web Token, with the header read.
///
/// Readable rather than guessable: the header is base64url of JSON that names
/// its own algorithm, so this reports what the token says about itself.
fn json_web_token(text: &str) -> Option<Identified> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 3 || parts.iter().take(2).any(|p| p.is_empty()) {
        return None;
    }

    let header = super::encodings::base64_url(parts[0].as_bytes())
        .or_else(|| super::encodings::base64(parts[0].as_bytes()))?;
    let header = latin1(&header);

    if !header.contains("\"alg\"") {
        return None;
    }

    // The algorithm the token declares, quoted straight out of its header.
    let algorithm = header
        .split("\"alg\"")
        .nth(1)
        .and_then(|rest| rest.split('"').nth(1))
        .unwrap_or("unstated");

    Some(Identified {
        candidates: vec!["JSON Web Token"],
        certain: true,
        bits: None,
        shape: format!("three base64url parts, header declares alg {algorithm}"),
    })
}

fn uuid(text: &str) -> Option<Identified> {
    let parts: Vec<&str> = text.split('-').collect();
    let lengths = [8usize, 4, 4, 4, 12];

    if parts.len() != 5 || !parts.iter().all(|p| is_hex(p.as_bytes())) {
        return None;
    }
    if !parts.iter().zip(lengths).all(|(p, n)| p.len() == n) {
        return None;
    }

    Some(Identified {
        candidates: vec!["UUID"],
        certain: true,
        // Named so it is not mistaken for a digest, which is what a bare run of
        // hex this length would otherwise look like.
        bits: Some(128),
        shape: "8-4-4-4-12 hex".to_string(),
    })
}

/// What this string is, as far as its shape can say.
pub fn identify(data: &[u8]) -> Option<Identified> {
    let text = core::str::from_utf8(data).ok()?.trim();
    if text.is_empty() {
        return None;
    }

    for (prefix, name) in PREFIXED {
        if text.starts_with(prefix) {
            return Some(Identified::declared(name, format!("prefixed {prefix}")));
        }
    }

    if let Some(found) = json_web_token(text) {
        return Some(found);
    }

    // MySQL 4.1 writes an asterisk in front of its digest, which is a
    // declaration rather than a coincidence of length.
    if text
        .strip_prefix('*')
        .is_some_and(|rest| rest.len() == 40 && is_hex(rest.as_bytes()))
    {
        return Some(Identified {
            candidates: vec!["MySQL 4.1+"],
            certain: true,
            bits: Some(160),
            shape: "asterisk then 40 hex".to_string(),
        });
    }

    if let Some(found) = uuid(text) {
        return Some(found);
    }

    if is_hex(text.as_bytes()) {
        let (_, bits, names) = BY_LENGTH.iter().find(|(len, _, _)| *len == text.len())?;
        return Some(Identified {
            candidates: names.to_vec(),
            // Shape alone, which is exactly why there is a list rather than an
            // answer.
            certain: false,
            bits: Some(*bits),
            shape: format!("{} hex digits", text.len()),
        });
    }

    None
}

/// True when a string is a digest rather than something wrapped up.
///
/// The peeler asks this before unwrapping anything. A hash is the end of the
/// road: hex-decoding one gives bytes that were never text and never will be.
pub fn is_digest(data: &[u8]) -> bool {
    identify(data).is_some()
}

pub fn json(data: &[u8]) -> String {
    use crate::json::{push_bool, push_field, push_number, push_string};

    let Some(found) = identify(data) else {
        return "null".to_string();
    };

    let mut out = String::from("{");
    push_bool(&mut out, "certain", found.certain);
    out.push(',');
    push_field(&mut out, "shape", &found.shape);
    out.push(',');
    match found.bits {
        Some(bits) => push_number(&mut out, "bits", bits),
        None => {
            push_string(&mut out, "bits");
            out.push_str(":null");
        }
    }
    out.push(',');
    push_string(&mut out, "candidates");
    out.push_str(":[");
    for (i, name) in found.candidates.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        push_string(&mut out, name);
    }
    out.push_str("]}");

    out
}

#[cfg(test)]
mod tests;
