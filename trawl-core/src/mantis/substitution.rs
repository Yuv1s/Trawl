//! Simple substitution, solved by climbing rather than counting.
//!
//! Every letter is replaced by another, consistently, and the key is the whole
//! mapping: 26 letters in any of 403 septillion arrangements. Nothing can be
//! tried exhaustively and nothing splits into columns, which is what separates
//! this from every other cipher in Mantis. Caesar has 26 keys. Vigenère breaks
//! into Caesars once the period is known. Substitution offers neither.
//!
//! What it does offer is a smooth landscape. Swapping two letters of a key that
//! is half right usually makes the result more English or less, and rarely
//! leaves it unchanged, so a key can be walked uphill: try every swap, keep the
//! ones that improve it, repeat until none does. That lands on a local peak,
//! which is not always the answer, so the walk restarts from fresh keys and the
//! best peak of the lot wins.
//!
//! Letter frequency alone cannot judge the steps. A wrong key and the right one
//! have the same letter frequencies as each other by construction: the wrong one
//! has simply given the counts different names. Only the order letters arrive in
//! tells them apart, which is why this module is the one that needed the trigram
//! census, and why it arrives after everything that did not.

use super::ngram;

/// Ciphertext letters as numbers, nought for A. Case and punctuation carry no
/// trigram evidence and are put back only at the end.
fn indices(data: &[u8]) -> Vec<u8> {
    data.iter()
        .filter(|b| b.is_ascii_alphabetic())
        .map(|b| b.to_ascii_uppercase() - b'A')
        .collect()
}

/// Trigram weight of the ciphertext read through a key, without decrypting it.
///
/// The hot loop. A solve calls this a few hundred thousand times, so it maps and
/// scores in one pass and allocates nothing.
fn weight_under(cipher: &[u8], key: &[u8; 26]) -> u32 {
    if cipher.len() < 3 {
        return 0;
    }

    let mut cell = key[cipher[0] as usize] as usize * 26 + key[cipher[1] as usize] as usize;
    let mut total = 0u32;

    for &letter in &cipher[2..] {
        cell = (cell % 676) * 26 + key[letter as usize] as usize;
        total += ngram::cell(cell);
    }

    total
}

/// xorshift64*, seeded from the ciphertext.
///
/// Climbing needs somewhere random to start, and a WASM build has no system
/// entropy to draw on. Seeding from the input instead makes every solve
/// reproducible: the same ciphertext always walks the same path, so a result
/// that gets reported can also be re-derived.
struct Rng(u64);

impl Rng {
    fn seeded(data: &[u8]) -> Self {
        let mut hash = 0xcbf29ce484222325u64;
        for &byte in data {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        Self(hash | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545f4914f6cdd1d)
    }

    fn shuffle(&mut self, key: &mut [u8; 26]) {
        for i in (1..26).rev() {
            key.swap(i, (self.next() % (i as u64 + 1)) as usize);
        }
    }
}

/// English letter frequencies, in percent, a through z.
const ENGLISH: [f32; 26] = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406,
    6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074,
];

/// A first key from letter counts: commonest ciphertext letter to E, and so on
/// down.
///
/// Wrong almost everywhere, but wrong in a useful way. It puts the vowels
/// roughly where vowels go, which is a better place to start climbing from than
/// a shuffle, and it costs one pass over the text.
fn by_frequency(cipher: &[u8]) -> [u8; 26] {
    let mut counts = [(0u32, 0u8); 26];
    for (letter, slot) in counts.iter_mut().enumerate() {
        slot.1 = letter as u8;
    }
    for &letter in cipher {
        counts[letter as usize].0 += 1;
    }
    counts.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));

    let mut english: Vec<u8> = (0..26).collect();
    english.sort_by(|&a, &b| ENGLISH[b as usize].total_cmp(&ENGLISH[a as usize]));

    let mut key = [0u8; 26];
    for (rank, &(_, letter)) in counts.iter().enumerate() {
        key[letter as usize] = english[rank];
    }
    key
}

/// Walks one key uphill until no single swap improves it.
fn climb(cipher: &[u8], key: &mut [u8; 26]) -> u32 {
    let mut best = weight_under(cipher, key);

    loop {
        let mut improved = false;

        for a in 0..26 {
            for b in (a + 1)..26 {
                key.swap(a, b);
                let score = weight_under(cipher, key);

                if score > best {
                    best = score;
                    improved = true;
                } else {
                    key.swap(a, b);
                }
            }
        }

        if !improved {
            return best;
        }
    }
}

/// Applies a key, putting case and punctuation back.
pub fn decipher(data: &[u8], key: &[u8; 26]) -> Vec<u8> {
    data.iter()
        .map(|&byte| {
            if !byte.is_ascii_alphabetic() {
                return byte;
            }

            let plain = b'a' + key[(byte.to_ascii_uppercase() - b'A') as usize];
            if byte.is_ascii_uppercase() {
                plain.to_ascii_uppercase()
            } else {
                plain
            }
        })
        .collect()
}

/// Enciphers under a key, for building test material.
pub fn encipher(data: &[u8], key: &[u8; 26]) -> Vec<u8> {
    let mut inverse = [0u8; 26];
    for (cipher, &plain) in key.iter().enumerate() {
        inverse[plain as usize] = cipher as u8;
    }
    decipher(data, &inverse)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    /// Plaintext letter for each ciphertext letter, A through Z.
    pub key: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub score: f32,
}

/// Fresh starts before the best peak is taken as the answer.
///
/// Climbing lands on a local peak, and a peak can be a key that is right about
/// twenty letters and stuck, reading "peecs" where the text said "keeps". More
/// restarts is more chances to land on the real one. Exact recoveries out of 20,
/// from `tests::probe_restarts`:
///
/// ```text
/// letters     25     50    100    200 restarts
///     150      0      1      4      9
///     200     17     18     20     20
///     250     20     20     20     20
///     300     20     20     20     20
/// ```
///
/// A hundred is where 200 letters becomes reliable. Past that it buys nothing
/// any text this length needs, and below 200 letters no budget rescues it: the
/// evidence is not there, and the answer comes back readable with a few letters
/// still swapped.
const RESTARTS: usize = 100;

/// Shortest ciphertext worth attempting.
///
/// A key has 26 free choices in it, and on a short text there is enough freedom
/// to fit those choices to nothing. Climbing 100 letters that have English's
/// composition and no order — what a transposition leaves behind, and the
/// hardest thing to turn down — produces a reading that scores 0.808, which is
/// most of the way to prose. That fades as the text grows.
/// `tests::measure_separation` draws the two curves, worst of forty:
///
/// ```text
/// letters    noise    prose
///     100    0.808    0.926
///     120    0.736    0.914
///     150    0.642    0.905
///     180    0.584    0.922
/// ```
///
/// Prose holds above 0.90 at every length, so the two only need separating at
/// the short end. Cutting at 150 puts the bar 0.16 clear of the noise below it
/// and 0.10 clear of the prose above.
///
/// Clearing this is not a promise of the exact key. Between here and about 200
/// letters the answer comes back readable with a handful of letters still
/// swapped, which [`RESTARTS`] measures and cannot fix.
const MIN_LETTERS: usize = 150;

/// How readable the result has to be before it is reported.
///
/// Some key always wins, so without a bar this reports a solution for any text
/// at all. See [`MIN_LETTERS`] for the other half of this.
///
/// Transposed text is the awkward case: the letters are already the right ones,
/// so a key can push a rearranged sentence to 0.507 without ever being the
/// answer. Readable text is the other one, at 0.916, because the identity is a
/// valid key and a sentence always solves to itself. [`MIN_GAIN`] is what turns
/// that one down.
///
/// ```text
///          input    affine   transposition   substitution
///          plain         -            -             0.916
///     rail fence         -         0.816            0.507
///       columnar         -         0.816            0.491
///         affine     0.816         0.343            0.904
///   substitution     0.315         0.328            0.916
///          noise     0.229         0.231              -
/// ```
///
/// Affine is the row that is not a false positive. An affine cipher genuinely
/// is a substitution, so 0.904 there is a correct answer that `read` sets aside
/// in favour of the smaller key.
const MIN_SCORE: f32 = 0.80;

/// How much more readable the result has to be than the text it came from.
///
/// The identity is a valid key, so without this a readable sentence solves to
/// itself and gets reported as a break.
const MIN_GAIN: f32 = 0.1;

pub fn solve(data: &[u8]) -> Option<Candidate> {
    let cipher = indices(data);
    if cipher.len() < MIN_LETTERS {
        return None;
    }

    let before = ngram::fitness(data);
    let mut rng = Rng::seeded(&cipher);
    let mut key = by_frequency(&cipher);

    let mut top = climb(&cipher, &mut key);
    let mut best = key;

    for _ in 1..RESTARTS {
        rng.shuffle(&mut key);
        let score = climb(&cipher, &mut key);

        if score > top {
            top = score;
            best = key;
        }
    }

    let plaintext = decipher(data, &best);
    let score = ngram::fitness(&plaintext);

    (score >= MIN_SCORE && score >= before + MIN_GAIN).then(|| Candidate {
        key: best.iter().map(|&letter| b'a' + letter).collect(),
        plaintext,
        score,
    })
}

#[cfg(test)]
mod tests;
