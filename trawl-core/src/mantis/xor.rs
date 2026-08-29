//! XOR key recovery.
//!
//! XOR is the cipher people reach for when they want something that looks
//! encrypted and takes ten lines to write. It is also the one that falls
//! apart fastest, because the key is short and the plaintext is English.
//!
//! Two cases. A single-byte key has 256 possibilities, so every one is tried and
//! the readable result wins. A repeating key is the same attack once you know
//! how long the key is, and you can work that out without knowing the key:
//! bytes encrypted under the same key byte differ only as English differs from
//! itself, which is far less than two random bytes differ. Measuring that across
//! candidate lengths makes the right one stand out.
//!
//! Neither of these is guesswork about the input. As everywhere else in Mantis,
//! a result is reported because of what it says, not because of how it looked
//! going in.

use crate::bytes;

use super::plainness;

/// How common each character is in ordinary English, including the space.
///
/// A column of a repeating-key cipher has no words and no sentence shape, so the
/// scorer used elsewhere has nothing to grip. What a column does keep is the
/// character mix, and space is the giveaway: it is the single most common
/// character in English text and appears in no other position of the table.
fn character_score(byte: u8) -> f32 {
    match byte.to_ascii_lowercase() {
        b' ' => 18.0,
        b'e' => 10.2,
        b't' => 7.5,
        b'a' => 6.5,
        b'o' => 6.1,
        b'i' => 5.7,
        b'n' => 5.5,
        b's' => 5.1,
        b'h' => 5.0,
        b'r' => 4.9,
        b'd' => 3.5,
        b'l' => 3.3,
        b'u' => 2.3,
        b'c' => 2.3,
        b'm' => 2.0,
        b'f' => 1.8,
        b'w' => 1.7,
        b'g' => 1.7,
        b'y' => 1.7,
        b'p' => 1.5,
        b'b' => 1.3,
        b'v' => 0.8,
        b'k' => 0.6,
        b'x' => 0.2,
        b'j' => 0.1,
        b'q' => 0.1,
        b'z' => 0.1,
        b'\n' | b'\r' | b'\t' => 0.5,
        b'0'..=b'9' => 0.6,
        b'.' | b',' | b'\'' | b'"' | b'!' | b'?' | b';' | b':' | b'-' => 0.5,
        b'{' | b'}' | b'_' => 0.4,
        other if (0x20..0x7f).contains(&other) => 0.2,
        // Control bytes are the strongest evidence a key is wrong.
        _ => -12.0,
    }
}

fn score_run(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().map(|&b| character_score(b)).sum::<f32>() / data.len() as f32
}

/// The key byte that makes a run read most like English.
fn best_byte(data: &[u8]) -> (u8, f32) {
    (0..=255u8)
        .map(|key| {
            let decoded: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
            (key, score_run(&decoded))
        })
        .fold(
            (0, f32::MIN),
            |best, next| if next.1 > best.1 { next } else { best },
        )
}

pub fn apply(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// Bits that differ between two runs of equal length.
fn hamming(a: &[u8], b: &[u8]) -> u32 {
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

/// Key lengths worth trying, best first.
///
/// Two blocks a key-length apart were encrypted under the same key bytes, so
/// their difference is the difference between two pieces of English, which is
/// small. At a wrong length the comparison is effectively between random bytes,
/// which is large. Averaging over several block pairs keeps one unlucky pair
/// from deciding it.
pub fn key_lengths(data: &[u8], max: usize) -> Vec<usize> {
    let max = max.min(data.len() / 4).max(1);
    let mut scored: Vec<(usize, f32)> = Vec::new();

    for length in 1..=max {
        let blocks: Vec<&[u8]> = data.chunks_exact(length).take(8).collect();
        if blocks.len() < 2 {
            continue;
        }

        let mut total = 0f32;
        let mut pairs = 0f32;
        for i in 0..blocks.len() {
            for j in i + 1..blocks.len() {
                total += hamming(blocks[i], blocks[j]) as f32 / length as f32;
                pairs += 1.0;
            }
        }

        scored.push((length, total / pairs));
    }

    scored.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(core::cmp::Ordering::Equal));
    scored.into_iter().map(|(length, _)| length).collect()
}

/// The shortest run the key repeats.
///
/// Any multiple of the real key length decrypts perfectly, so the search often
/// lands on one. Reporting "KEYKEY" when the key was "KEY" is not wrong, but it
/// is not the answer either.
fn shortest_period(key: &[u8]) -> Vec<u8> {
    for period in 1..=key.len() / 2 {
        if !key.len().is_multiple_of(period) {
            continue;
        }
        if key.chunks(period).all(|chunk| chunk == &key[..period]) {
            return key[..period].to_vec();
        }
    }
    key.to_vec()
}

/// Recovers the key of a given length by solving each column on its own.
pub fn key_of_length(data: &[u8], length: usize) -> Vec<u8> {
    let key: Vec<u8> = (0..length)
        .map(|offset| {
            let column: Vec<u8> = data.iter().skip(offset).step_by(length).copied().collect();
            best_byte(&column).0
        })
        .collect();

    shortest_period(&key)
}

/// What each extra key byte costs when weighing two candidates.
///
/// Any multiple of the real key deciphers exactly as well, so "KEY" and
/// "KEYKEYKEY" come out within a thousandth of each other and the longer one
/// wins about half the time on noise alone. Worse, a multiple splits the text
/// into more columns than the key needs, and the last of those columns can be
/// short enough that its byte is recovered wrongly: the answer comes back as
/// nine bytes of which one is rubbish, which `shortest_period` cannot then
/// collapse. A multiple is never the answer, so length has to cost something.
const LENGTH_COST: f32 = 0.002;

#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub key: Vec<u8>,
    pub plaintext: Vec<u8>,
    /// How much the result reads like ordinary text.
    pub score: f32,
    pub flags: Vec<String>,
    convincing: bool,
}

impl Candidate {
    /// What this candidate is worth, for ordering.
    ///
    /// A flag outranks any readability score. Readability is a guess about
    /// English; a flag is the answer, and on a short string the guess is noisy
    /// enough to rank real finds below nonsense without this.
    fn rank(&self) -> (bool, f32) {
        (
            self.convincing,
            self.score - self.key.len() as f32 * LENGTH_COST,
        )
    }

    /// Strictly better than another candidate, flags first then readability.
    fn beats(&self, other: &Self) -> bool {
        let (mine, theirs) = (self.rank(), other.rank());
        mine.0.cmp(&theirs.0).then(
            mine.1
                .partial_cmp(&theirs.1)
                .unwrap_or(core::cmp::Ordering::Equal),
        ) == core::cmp::Ordering::Greater
    }

    /// The key as something a person can read, quoted when it is text.
    pub fn key_text(&self) -> String {
        if self.key.iter().all(|&b| (0x20..0x7f).contains(&b)) {
            format!("\"{}\"", String::from_utf8_lossy(&self.key))
        } else {
            self.key
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        }
    }
}

/// How readable a result has to be before it is worth reporting.
///
/// XOR always produces something. Without a bar, every input yields 256 answers
/// and the tool becomes a random text generator with a confident tone. Ordinary
/// prose scores around 0.6, and the wrong keys were clearing 0.42 on the
/// strength of having spaces and lowercase letters in them.
const MIN_SCORE: f32 = 0.5;

/// Tags that a flag shape has to carry before it outranks a readability score.
///
/// Not a filter: an unrecognised tag is still reported. But XOR output is
/// printable noise with braces scattered through it, so `ssb6{s6wb6b~s6ryu}`
/// turns up constantly and would otherwise be promoted above the real answer.
/// Longest repeating key worth hunting for.
const MAX_KEY: usize = 32;

fn assess(key: Vec<u8>, plaintext: Vec<u8>, tags: &[String]) -> Option<Candidate> {
    let flags: Vec<String> = bytes::flag_candidates_for_tags(&plaintext, tags)
        .into_iter()
        .map(|f| f.text)
        .collect();

    let score = plainness(&plaintext);
    let convincing = flags
        .iter()
        .any(|flag| bytes::tag_is_known_for(flag, tags));
    if score < MIN_SCORE && !convincing {
        return None;
    }

    Some(Candidate {
        key,
        plaintext,
        score,
        flags,
        convincing,
    })
}

/// Every single-byte key that produced something readable, best first.
pub fn single_byte(data: &[u8], tags: &[String]) -> Vec<Candidate> {
    let mut found: Vec<Candidate> = (1..=255u8)
        .filter_map(|key| assess(vec![key], apply(data, &[key]), tags))
        .collect();

    found.sort_by(|a, b| {
        let (a_flag, a_score) = a.rank();
        let (b_flag, b_score) = b.rank();
        b_flag.cmp(&a_flag).then(
            b_score
                .partial_cmp(&a_score)
                .unwrap_or(core::cmp::Ordering::Equal),
        )
    });
    found.truncate(3);
    found
}

/// The best repeating key, if one produces something readable.
pub fn repeating(data: &[u8], tags: &[String]) -> Option<Candidate> {
    if data.len() < 16 {
        return None;
    }

    key_lengths(data, MAX_KEY)
        .into_iter()
        .take(4)
        .filter(|&length| length > 1)
        .filter_map(|length| {
            let key = key_of_length(data, length);
            assess(key.clone(), apply(data, &key), tags)
        })
        // Strictly better, so a tie keeps the earlier candidate. Key lengths
        // arrive shortest first and a multiple decrypts just as well.
        .fold(None::<Candidate>, |best, next| match best {
            Some(current) if !next.beats(&current) => Some(current),
            _ => Some(next),
        })
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Recovery {
    pub single: Vec<Candidate>,
    pub repeating: Option<Candidate>,
}

impl Recovery {
    pub fn found(&self) -> bool {
        !self.single.is_empty() || self.repeating.is_some()
    }

    /// Every candidate, best first, whatever kind it is.
    ///
    /// A repeating key is often the right answer while a couple of single-byte
    /// keys scrape past the bar, and listing by kind would bury the answer under
    /// them.
    pub fn best_first(&self) -> Vec<(&'static str, &Candidate)> {
        let mut all: Vec<(&'static str, &Candidate)> = self
            .single
            .iter()
            .map(|c| ("single byte", c))
            .chain(self.repeating.iter().map(|c| ("repeating key", c)))
            .collect();

        all.sort_by(|a, b| {
            let (a_flag, a_score) = a.1.rank();
            let (b_flag, b_score) = b.1.rank();
            b_flag.cmp(&a_flag).then(
                b_score
                    .partial_cmp(&a_score)
                    .unwrap_or(core::cmp::Ordering::Equal),
            )
        });
        all.truncate(3);
        all
    }
}

pub fn recover(data: &[u8], tags: &[String]) -> Recovery {
    Recovery {
        single: single_byte(data, tags),
        repeating: repeating(data, tags),
    }
}

#[cfg(test)]
mod tests;
