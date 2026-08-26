//! AES-CBC, and finding the pieces to run it.
//!
//! A file sometimes carries its own key. A photo's metadata holds the hex for a
//! key and an IV, a text chunk names the cipher, and a base64 blob is the
//! ciphertext, all sitting in plain sight because none of it means anything
//! without the others. A person would copy the three into a decryptor by hand.
//! This does that for them.
//!
//! The cipher is written out rather than pulled in, the same as every other
//! codec here. Only decryption: a tool that reads a file has ciphertext and
//! wants plaintext, never the other way round.
//!
//! The search is what keeps it honest. Wrong keys are the overwhelming majority
//! of what gets tried, and a wrong key turns AES into a random byte generator,
//! so the filter is simply whether the result reads. PKCS7 padding has to check
//! out and the bytes have to be mostly printable before anything is shown, and
//! the chance of a wrong key clearing both is too small to matter. On a file
//! with no key in it, nothing is tried that survives, and the tool says so.

use crate::bytes;

/// The AES substitution box, forward direction, used by the key schedule.
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// The inverse box, derived so there is one table to trust rather than two.
const INV_SBOX: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        table[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Round constants for the key schedule, one per key-expansion round.
const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

/// Multiplication in GF(2^8), the field AES mixes columns over.
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

/// The expanded key: one four-byte word per column, across every round.
///
/// Returns the schedule and the round count, or nothing when the key length is
/// not one AES defines.
fn key_schedule(key: &[u8]) -> Option<(Vec<[u8; 4]>, usize)> {
    let nk = match key.len() {
        16 => 4,
        24 => 6,
        32 => 8,
        _ => return None,
    };
    let nr = nk + 6;
    let total = 4 * (nr + 1);

    let mut words: Vec<[u8; 4]> = Vec::with_capacity(total);
    for i in 0..nk {
        words.push([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }

    for i in nk..total {
        let mut temp = words[i - 1];
        if i % nk == 0 {
            temp = [temp[1], temp[2], temp[3], temp[0]];
            for byte in &mut temp {
                *byte = SBOX[*byte as usize];
            }
            temp[0] ^= RCON[i / nk];
        } else if nk > 6 && i % nk == 4 {
            for byte in &mut temp {
                *byte = SBOX[*byte as usize];
            }
        }
        let prev = words[i - nk];
        words.push([
            prev[0] ^ temp[0],
            prev[1] ^ temp[1],
            prev[2] ^ temp[2],
            prev[3] ^ temp[3],
        ]);
    }

    Some((words, nr))
}

/// The state is column-major: byte `r + 4c` is row `r` of column `c`.
fn add_round_key(state: &mut [u8; 16], words: &[[u8; 4]], round: usize) {
    for c in 0..4 {
        let word = words[round * 4 + c];
        for r in 0..4 {
            state[r + 4 * c] ^= word[r];
        }
    }
}

fn inv_sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = INV_SBOX[*byte as usize];
    }
}

/// Row `r` rotates right by `r`, undoing the encryption's left rotation.
fn inv_shift_rows(state: &mut [u8; 16]) {
    let source = *state;
    for r in 1..4 {
        for c in 0..4 {
            state[r + 4 * c] = source[r + 4 * ((c + 4 - r) % 4)];
        }
    }
}

fn inv_mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let a0 = state[4 * c];
        let a1 = state[4 * c + 1];
        let a2 = state[4 * c + 2];
        let a3 = state[4 * c + 3];
        state[4 * c] = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
        state[4 * c + 1] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
        state[4 * c + 2] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
        state[4 * c + 3] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
    }
}

fn decrypt_block(block: &[u8; 16], words: &[[u8; 4]], nr: usize) -> [u8; 16] {
    let mut state = *block;
    add_round_key(&mut state, words, nr);
    for round in (1..nr).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, words, round);
        inv_mix_columns(&mut state);
    }
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_round_key(&mut state, words, 0);
    state
}

/// AES-CBC decryption. The padding is left on; the caller decides what to trust.
pub fn cbc_decrypt(key: &[u8], iv: &[u8; 16], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return None;
    }
    let (words, nr) = key_schedule(key)?;

    let mut out = Vec::with_capacity(ciphertext.len());
    let mut previous = *iv;
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let decrypted = decrypt_block(&block, &words, nr);
        for i in 0..16 {
            out.push(decrypted[i] ^ previous[i]);
        }
        previous = block;
    }
    Some(out)
}

/// Strips PKCS7 padding, or returns nothing when the trailer is not valid PKCS7.
fn pkcs7_strip(data: &[u8]) -> Option<&[u8]> {
    let pad = *data.last()? as usize;
    if pad == 0 || pad > 16 || pad > data.len() {
        return None;
    }
    if data[data.len() - pad..].iter().all(|&b| b as usize == pad) {
        Some(&data[..data.len() - pad])
    } else {
        None
    }
}

/// Fraction of bytes a person could read, the test a real decryption passes and
/// a wrong key does not.
fn printable_ratio(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let readable = data
        .iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r'))
        .count();
    readable as f32 / data.len() as f32
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
    (acc == 0).then_some(out)
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn is_b64(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_' | b'=')
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

/// Longest ciphertext worth trying, so one enormous base64 blob cannot make the
/// search crawl.
const CIPHERTEXT_CAP: usize = 4096;
/// Ceilings on how many of each kind of candidate to keep, in file order.
const MAX_KEYS: usize = 64;
const MAX_IVS: usize = 64;
const MAX_CIPHERTEXTS: usize = 24;
/// A ceiling on total block decryptions, so a pathological file still returns.
const BUDGET: usize = 4_000_000;
/// Most decryptions to report.
const MAX_SOLVED: usize = 12;

fn push_unique(into: &mut Vec<Vec<u8>>, value: Vec<u8>, cap: usize) {
    if into.len() < cap && !into.contains(&value) {
        into.push(value);
    }
}

/// One decryption that read as text, with where its key and IV came from.
pub struct Solved {
    pub key_hex: String,
    pub iv_hex: String,
    pub bits: usize,
    pub text: String,
    pub flags: Vec<String>,
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0xf) as u32, 16).unwrap());
    }
    out
}

/// Tries the keys, IVs and ciphertexts a file carries against each other, and
/// returns the combinations that decrypted to something readable.
pub fn probe(file: &[u8]) -> Vec<Solved> {
    let mut keys: Vec<Vec<u8>> = Vec::new();
    let mut ivs: Vec<Vec<u8>> = Vec::new();

    for run in runs(file, is_hex, 32) {
        // A run can carry a stray hex digit from the bytes next to it, so read
        // fixed key and IV lengths off the front rather than trusting its edge.
        if let Some(bytes) = from_hex(&run[..32]) {
            push_unique(&mut keys, bytes.clone(), MAX_KEYS);
            push_unique(&mut ivs, bytes, MAX_IVS);
        }
        if run.len() >= 48 && let Some(bytes) = from_hex(&run[..48]) {
            push_unique(&mut keys, bytes, MAX_KEYS);
        }
        if run.len() >= 64 && let Some(bytes) = from_hex(&run[..64]) {
            push_unique(&mut keys, bytes, MAX_KEYS);
        }
    }

    let mut ciphertexts: Vec<Vec<u8>> = Vec::new();
    for run in runs(file, is_b64, 24) {
        let decoded = from_base64(run, B64).or_else(|| from_base64(run, B64_URL));
        if let Some(bytes) = decoded
            && !bytes.is_empty()
            && bytes.len().is_multiple_of(16)
            && bytes.len() <= CIPHERTEXT_CAP
        {
            push_unique(&mut ciphertexts, bytes, MAX_CIPHERTEXTS);
        }
    }

    let mut solved: Vec<Solved> = Vec::new();
    // The stable part of each plaintext, and how good that reading was. In CBC a
    // wrong IV corrupts only the first block, so the right key with the wrong IV
    // still decrypts the rest. Keying on everything past the first block folds
    // those near-misses into the one clean reading rather than listing both.
    let mut tails: Vec<Vec<u8>> = Vec::new();
    let mut grades: Vec<(usize, u32)> = Vec::new();
    let mut spent = 0usize;

    'outer: for ciphertext in &ciphertexts {
        for key in &keys {
            for iv in &ivs {
                spent += ciphertext.len() / 16;
                if spent > BUDGET {
                    break 'outer;
                }

                let mut block = [0u8; 16];
                block.copy_from_slice(&iv[..16]);
                let Some(raw) = cbc_decrypt(key, &block, ciphertext) else {
                    continue;
                };
                let plain = pkcs7_strip(&raw).unwrap_or(&raw);
                if plain.len() < 4 || printable_ratio(plain) < 0.85 {
                    continue;
                }

                let flags: Vec<String> = bytes::flag_candidates(plain)
                    .into_iter()
                    .map(|found| found.text)
                    .collect();
                // A flag outweighs a cleaner read, then the readable fraction
                // separates the correct IV from one that garbled the first block.
                let grade = (flags.len(), (printable_ratio(plain) * 1000.0) as u32);
                // Past the first block for a multi-block message; the whole of a
                // single block, which a wrong IV garbles beyond the readable bar.
                let tail = if plain.len() > 16 {
                    plain[16..].to_vec()
                } else {
                    plain.to_vec()
                };

                let entry = Solved {
                    key_hex: to_hex(key),
                    iv_hex: to_hex(iv),
                    bits: key.len() * 8,
                    text: String::from_utf8_lossy(plain).into_owned(),
                    flags,
                };

                match tails.iter().position(|seen| *seen == tail) {
                    Some(j) => {
                        if grade > grades[j] {
                            solved[j] = entry;
                            grades[j] = grade;
                        }
                    }
                    None => {
                        tails.push(tail);
                        grades.push(grade);
                        solved.push(entry);
                        if solved.len() >= MAX_SOLVED {
                            break 'outer;
                        }
                    }
                }
            }
        }
    }

    // A decryption that yielded a flag is the answer; float those up.
    solved.sort_by_key(|item| std::cmp::Reverse(item.flags.len()));
    solved
}

/// The probe as JSON, an array that is empty when nothing decrypted.
pub fn json(file: &[u8]) -> String {
    use crate::json::{push_field, push_number, push_string};

    let mut out = String::from("[");
    for (i, item) in probe(file).iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "keyHex", &item.key_hex);
        out.push(',');
        push_field(&mut out, "ivHex", &item.iv_hex);
        out.push(',');
        push_number(&mut out, "bits", item.bits);
        out.push(',');
        push_field(&mut out, "text", &item.text);
        out.push(',');
        push_string(&mut out, "flags");
        out.push_str(":[");
        for (j, flag) in item.flags.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            let mut held = String::new();
            push_string(&mut held, flag);
            out.push_str(&held);
        }
        out.push_str("]}");
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests;
