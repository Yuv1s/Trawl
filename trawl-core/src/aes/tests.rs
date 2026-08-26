use super::*;

fn hex(text: &str) -> Vec<u8> {
    from_hex(text.as_bytes()).unwrap()
}

// The forward cipher, kept to the tests, so decryption can be checked against
// material this file encrypted rather than a value pasted in from elsewhere.
fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let source = *state;
    for r in 1..4 {
        for c in 0..4 {
            state[r + 4 * c] = source[r + 4 * ((c + r) % 4)];
        }
    }
}

fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let a0 = state[4 * c];
        let a1 = state[4 * c + 1];
        let a2 = state[4 * c + 2];
        let a3 = state[4 * c + 3];
        state[4 * c] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
        state[4 * c + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
        state[4 * c + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
        state[4 * c + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
    }
}

fn encrypt_block(block: &[u8; 16], words: &[[u8; 4]], nr: usize) -> [u8; 16] {
    let mut state = *block;
    add_round_key(&mut state, words, 0);
    for round in 1..nr {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, words, round);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, words, nr);
    state
}

fn encrypt_cbc(key: &[u8], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let (words, nr) = key_schedule(key).unwrap();

    let pad = 16 - (plaintext.len() % 16);
    let mut padded = plaintext.to_vec();
    padded.extend(std::iter::repeat_n(pad as u8, pad));

    let mut out = Vec::with_capacity(padded.len());
    let mut previous = *iv;
    for chunk in padded.chunks(16) {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ previous[i];
        }
        let encrypted = encrypt_block(&block, &words, nr);
        out.extend_from_slice(&encrypted);
        previous = encrypted;
    }
    out
}

fn base64(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in data.chunks(3) {
        let mut packed = 0u32;
        for (i, &byte) in chunk.iter().enumerate() {
            packed |= (byte as u32) << (16 - 8 * i);
        }
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                B64[((packed >> (18 - 6 * i)) & 63) as usize]
            } else {
                b'='
            });
        }
    }
    out
}

#[test]
fn block_decrypt_matches_the_fips_128_vector() {
    // FIPS-197 appendix, the single-block example for a 128-bit key.
    let key = hex("000102030405060708090a0b0c0d0e0f");
    let (words, nr) = key_schedule(&key).unwrap();
    let mut ciphertext = [0u8; 16];
    ciphertext.copy_from_slice(&hex("69c4e0d86a7b0430d8cdb78070b4c55a"));

    let plain = decrypt_block(&ciphertext, &words, nr);
    assert_eq!(plain.to_vec(), hex("00112233445566778899aabbccddeeff"));
}

#[test]
fn block_decrypt_matches_the_fips_256_vector() {
    let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let (words, nr) = key_schedule(&key).unwrap();
    let mut ciphertext = [0u8; 16];
    ciphertext.copy_from_slice(&hex("8ea2b7ca516745bfeafc49904b496089"));

    let plain = decrypt_block(&ciphertext, &words, nr);
    assert_eq!(plain.to_vec(), hex("00112233445566778899aabbccddeeff"));
}

#[test]
fn cbc_round_trips_across_several_blocks() {
    let key = b"hydrophone-array";
    let iv = *b"nauticorp-atlas!";
    let message = b"the tide comes in twice a day, and twice it goes back out again";

    let ciphertext = encrypt_cbc(key, &iv, message);
    let raw = cbc_decrypt(key, &iv, &ciphertext).unwrap();
    assert_eq!(pkcs7_strip(&raw).unwrap(), message);
}

#[test]
fn rejects_a_ciphertext_that_is_not_a_block_multiple() {
    let key = b"hydrophone-array";
    let iv = [0u8; 16];
    assert!(cbc_decrypt(key, &iv, b"seventeen bytes..").is_none());
}

#[test]
fn probe_reads_a_key_iv_and_payload_out_of_a_file() {
    let key = b"hydrophone-array";
    let iv = *b"nauticorp-atlas!";
    let flag = b"CTF{aes_key_carried_in_plain_sight}";
    let ciphertext = base64(&encrypt_cbc(key, &iv, flag));

    // The three pieces sit apart, the way a photo's metadata carries them: the
    // key in one text chunk, the IV in a comment, the payload in another chunk.
    let mut file = Vec::new();
    file.extend_from_slice(b"\x89PNG\r\n\x1a\n....tEXtCalibrationKeyHex\0");
    file.extend_from_slice(to_hex(key).as_bytes());
    file.extend_from_slice(b"....<!-- AES_CBC_IV_HEX=");
    file.extend_from_slice(to_hex(&iv).as_bytes());
    file.extend_from_slice(b" -->....tEXtPayloadBase64\0");
    file.extend_from_slice(&ciphertext);
    file.extend_from_slice(b"....IEND");

    let solved = probe(&file);
    assert!(
        solved
            .iter()
            .any(|s| s.flags.iter().any(|f| f == "CTF{aes_key_carried_in_plain_sight}")),
        "probe did not recover the flag: {:?}",
        solved.iter().map(|s| &s.text).collect::<Vec<_>>()
    );
}

#[test]
fn probe_survives_a_key_with_a_stray_hex_digit_beside_it() {
    let key = b"hydrophone-array";
    let iv = *b"nauticorp-atlas!";
    let flag = b"CTF{aes_key_carried_in_plain_sight}";
    let ciphertext = base64(&encrypt_cbc(key, &iv, flag));

    // A CRC byte after the key value reads as one more hex digit, making the run
    // 33 long. Reading 32 off the front is what keeps the key recoverable.
    let mut file = Vec::new();
    file.extend_from_slice(to_hex(key).as_bytes());
    file.extend_from_slice(b"a \0 ");
    file.extend_from_slice(to_hex(&iv).as_bytes());
    file.extend_from_slice(b" \0 ");
    file.extend_from_slice(&ciphertext);

    let solved = probe(&file);
    assert!(solved.iter().any(|s| s.flags.iter().any(|f| f.contains("aes_key"))));
}

#[test]
fn probe_folds_the_wrong_iv_near_miss_into_the_clean_reading() {
    // A file whose key and IV are both present gives the probe a decoy: the key
    // used as its own IV decrypts every block but the first, so the tail reads.
    // The clean reading, with a flag, is the only one that should survive.
    let key = b"hydrophone-array";
    let iv = *b"nauticorp-atlas!";
    let flag = b"CTF{aes_key_carried_in_plain_sight}";
    let ciphertext = base64(&encrypt_cbc(key, &iv, flag));

    let mut file = Vec::new();
    file.extend_from_slice(to_hex(key).as_bytes());
    file.extend_from_slice(b" \0 ");
    file.extend_from_slice(to_hex(&iv).as_bytes());
    file.extend_from_slice(b" \0 ");
    file.extend_from_slice(&ciphertext);

    let solved = probe(&file);
    assert_eq!(solved.len(), 1, "the wrong-IV near-miss was not folded in");
    assert_eq!(solved[0].flags, vec!["CTF{aes_key_carried_in_plain_sight}"]);
}

#[test]
fn probe_is_quiet_on_a_file_that_holds_no_key() {
    // Text and numbers, but nothing that forms a key, an IV and a payload that
    // decrypt to anything readable.
    let file = b"the quick brown fox jumps over 13 lazy dogs, 42 times, near the harbour wall";
    assert!(probe(file).is_empty());
}

#[test]
fn json_is_an_empty_array_when_nothing_decrypts() {
    assert_eq!(json(b"nothing to see here at all, just words"), "[]");
}
