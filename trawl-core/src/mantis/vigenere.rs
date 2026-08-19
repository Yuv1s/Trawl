//! Vigenère, solved without being told the key or its length.
//!
//! The cipher shifts each letter by a different amount, cycling through a
//! keyword, which is what defeats plain letter counting: the most common letter
//! of the ciphertext is not the most common letter of English, because every
//! position was shifted differently.
//!
//! It falls to one observation. Take every k-th letter, where k is the key
//! length, and all of them were shifted by the same key letter. That column is
//! an ordinary Caesar shift, and Caesar shifts fall to letter counting.
//!
//! So the work is finding k. English letters repeat in a lumpy way, and that
//! lumpiness survives a single fixed shift but not a cycling one. Measuring it
//! at each candidate length makes the real key length stand out.
//!
//! No quadgram table is needed for any of this, which is why this arrives before
//! simple substitution does. Substitution has no columns to split into.

use super::{ngram, plainness};

/// English letter frequencies, in percent, a through z.
const ENGLISH: [f32; 26] = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406,
    6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074,
];

/// Above this, a set of columns is lumpy enough to be English rather than a mix
/// of differently shifted letters.
///
/// English runs about 0.067 and a Vigenère ciphertext about 0.045, so the gap is
/// wide and this sits in it.
const LUMPY: f32 = 0.06;

/// Letters a column needs before its counts mean anything.
///
/// Six letters produce an index of coincidence that is pure luck, and long key
/// lengths make short columns, so without this the longest candidates win by
/// being noisiest.
const MIN_COLUMN: usize = 8;

/// How lumpy the letter counts are.
///
/// The chance that two letters picked at random from a run are the same. English
/// runs about 0.067 because some letters are far more common than others.
/// Uniformly random letters run about 0.038. A Vigenère ciphertext sits near the
/// random figure, and each of its columns sits near the English one.
pub fn index_of_coincidence(letters: &[u8]) -> f32 {
    let total = letters.len();
    if total < 2 {
        return 0.0;
    }

    let mut counts = [0usize; 26];
    for &letter in letters {
        counts[(letter - b'a') as usize] += 1;
    }

    let sum: usize = counts.iter().map(|&n| n * n.saturating_sub(1)).sum();
    sum as f32 / (total * (total - 1)) as f32
}

/// Lowercase letters only, which is all the cipher touches.
fn letters_of(data: &[u8]) -> Vec<u8> {
    data.iter()
        .filter(|b| b.is_ascii_alphabetic())
        .map(|b| b.to_ascii_lowercase())
        .collect()
}

/// Key lengths worth trying, most likely first.
///
/// Scored by how close each length brings its columns to English lumpiness. A
/// wrong length mixes letters that were shifted differently, which flattens the
/// counts toward random.
pub fn key_lengths(data: &[u8], max: usize) -> Vec<usize> {
    let letters = letters_of(data);
    let max = max.min(letters.len() / MIN_COLUMN).max(1);

    let scored: Vec<(usize, f32)> = (1..=max)
        .map(|length| {
            let average: f32 = (0..length)
                .map(|offset| {
                    let column: Vec<u8> = letters
                        .iter()
                        .skip(offset)
                        .step_by(length)
                        .copied()
                        .collect();
                    index_of_coincidence(&column)
                })
                .sum::<f32>()
                / length as f32;

            (length, average)
        })
        .collect();

    let best = scored.iter().map(|(_, ic)| *ic).fold(0.0f32, f32::max);

    // The real key length pushes the columns toward English, and so does every
    // multiple of it: at twice the length the columns are half as long but still
    // uniformly shifted. Ranking by score alone therefore picks a multiple about
    // as often as the answer, so among the lengths that clear the bar the
    // shortest wins.
    let bar = LUMPY.max(best * 0.9);

    let mut strong: Vec<usize> = scored
        .iter()
        .filter(|(_, ic)| *ic >= bar)
        .map(|(length, _)| *length)
        .collect();
    strong.sort_unstable();

    let mut rest: Vec<(usize, f32)> = scored
        .into_iter()
        .filter(|(length, _)| !strong.contains(length))
        .collect();
    rest.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(core::cmp::Ordering::Equal));

    strong
        .into_iter()
        .chain(rest.into_iter().map(|(l, _)| l))
        .collect()
}

/// The shift that best turns one column back into English.
///
/// Chi-squared against the expected letter counts. Every column of a Vigenère is
/// a Caesar shift, so this is the whole of solving one.
fn best_shift(column: &[u8]) -> u8 {
    let total = column.len() as f32;
    if total == 0.0 {
        return 0;
    }

    let mut counts = [0f32; 26];
    for &letter in column {
        counts[(letter - b'a') as usize] += 1.0;
    }

    (0..26u8)
        .map(|shift| {
            let error: f32 = (0..26)
                .map(|i| {
                    let observed = counts[(i + shift as usize) % 26];
                    let expected = total * ENGLISH[i] / 100.0;
                    (observed - expected).powi(2) / expected.max(0.01)
                })
                .sum();
            (shift, error)
        })
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(core::cmp::Ordering::Equal))
        .map(|(shift, _)| shift)
        .unwrap_or(0)
}

/// The key of a given length.
pub fn key_of_length(data: &[u8], length: usize) -> Vec<u8> {
    let letters = letters_of(data);

    (0..length)
        .map(|offset| {
            let column: Vec<u8> = letters
                .iter()
                .skip(offset)
                .step_by(length)
                .copied()
                .collect();
            b'a' + best_shift(&column)
        })
        .collect()
}

/// Undoes the cipher, leaving everything that is not a letter where it was.
///
/// The key advances only on letters. Counting spaces and punctuation as key
/// positions is the classic way to get a decryption that is right for the first
/// few words and wrong after that.
pub fn decipher(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }

    let mut out = Vec::with_capacity(data.len());
    let mut at = 0usize;

    for &byte in data {
        if !byte.is_ascii_alphabetic() {
            out.push(byte);
            continue;
        }

        let shift = key[at % key.len()] - b'a';
        at += 1;

        let base = if byte.is_ascii_uppercase() {
            b'A'
        } else {
            b'a'
        };
        out.push(base + (byte - base + 26 - shift) % 26);
    }

    out
}

pub fn encipher(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }

    let inverse: Vec<u8> = key.iter().map(|&k| b'a' + (26 - (k - b'a')) % 26).collect();

    decipher(data, &inverse)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub key: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub score: f32,
}

/// Shortest run the key repeats, since any multiple of it also deciphers.
fn shortest_period(key: &[u8]) -> Vec<u8> {
    for period in 1..=key.len() / 2 {
        if key.len().is_multiple_of(period) && key.chunks(period).all(|c| c == &key[..period]) {
            return key[..period].to_vec();
        }
    }
    key.to_vec()
}

/// Longest keyword worth hunting for.
///
/// Stacking Vigenère does not make a new cipher: enciphering with keys of five,
/// seven and two letters is one Vigenère whose key is their lowest common
/// multiple, seventy letters long. So the question of how many layers can be
/// undone is really the question of how long a key can be found, and that has a
/// harder ceiling than it looks.
///
/// A key of seventy is seventy columns that must *all* come out right at once.
/// Twenty letters per column gets each one right most of the time, and most of
/// the time to the power of seventy is never. Raising this to eighty was
/// measured: it did not recover a seventy letter key from fourteen hundred
/// letters, and it made every other solve eighteen times slower.
///
/// Forty is what the text a person actually pastes can support. What that means
/// in practice, measured in `tests::probe_stacked_status`:
///
/// ```text
/// keys              effective   solved from
/// cat + dog                 3   200 letters
/// ab + cat + lion          12   200 letters
/// lemon + cat              15   500 letters
/// key + lemon + ab         30   900 letters
/// lemon + kwunkzl + ab     70   out of range
/// ```
const MAX_KEY: usize = 40;

/// How readable the result has to be before it is reported.
///
/// Every key length produces some decryption, so without a bar this reports one
/// for any text at all, including text that was never enciphered.
///
/// Measured in `tests::probe_solve_score_separation`. Keys the climb gets right
/// come back at 0.755 and above; the one wrong key it reported at all scored
/// 0.516, on columns too thin to have found anything:
///
/// ```text
/// key             per column    score
/// cat                   11.3    0.894   correct
/// lemon                  8.6    0.798   correct
/// kwunkzl                5.3    0.755   correct
/// security               5.1    0.764   correct
/// cryptography           3.6    0.516   wrong
/// ```
const MIN_SCORE: f32 = 0.65;

/// What each extra key letter costs, when weighing two candidates.
///
/// Every multiple of the real key length deciphers just as well, so "cipher" and
/// "ciphercipher" come out scoring within a thousandth of each other and the
/// longer one wins about half the time on noise alone. A multiple is never the
/// answer, so length has to cost something.
const LENGTH_COST: f32 = 0.002;

/// Shortest ciphertext worth attempting.
///
/// Was sixty when a key had to be counted out of its columns. Climbing needs
/// about a fifth as much per position, and `tests::probe_solve_floor` measures
/// the difference: keys of three, five and seven letters all come back exactly
/// from texts of 34 to 45 letters, which the old floor refused outright.
///
/// Thirty rather than lower because the bar has to hold against text nobody
/// enciphered. At this length noise is still turned down at every size tried,
/// and the identity key, which would otherwise let any readable text "solve" to
/// itself, is skipped in [`derive`].
const MIN_LETTERS: usize = 30;

/// Letters as numbers, nought for A, which is what the climbing loop works in.
fn indices(data: &[u8]) -> Vec<u8> {
    data.iter()
        .filter(|b| b.is_ascii_alphabetic())
        .map(|b| b.to_ascii_uppercase() - b'A')
        .collect()
}

/// Trigram weight of the whole text read through a key, without deciphering it.
///
/// The hot loop of the climb, so it maps and scores in one pass and allocates
/// nothing.
fn weight_under(letters: &[u8], key: &[u8]) -> u32 {
    if letters.len() < 3 {
        return 0;
    }

    let plain = |at: usize| (letters[at] + 26 - key[at % key.len()]) % 26;

    let mut cell = plain(0) as usize * 26 + plain(1) as usize;
    let mut total = 0u32;

    for at in 2..letters.len() {
        cell = (cell % 676) * 26 + plain(at) as usize;
        total += ngram::cell(cell);
    }

    total
}

/// xorshift64*, seeded from the text so a solve can be re-derived.
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
}

/// Walks one key uphill, one position at a time, until nothing improves it.
///
/// The whole reason this exists. Counting letters in a column judges each key
/// letter by that column alone, and a column of two letters has no distribution
/// to count: at that length the counted key is a coin toss per position, which
/// is why [`solve`] declines short text rather than guessing.
///
/// Climbing judges the key by what the whole text spells. A key letter at
/// position three sets the letters at three, ten and seventeen, and each of
/// those sits inside three trigrams that reach across into positions belonging
/// to other key letters. So the evidence for one key letter is not its own two
/// letters, it is every trigram those letters touch, and the positions
/// constrain each other rather than being solved apart.
fn climb(start: &[u8], score: impl Fn(&[u8]) -> f64) -> (Vec<u8>, f64) {
    let mut key = start.to_vec();
    let mut best = score(&key);

    loop {
        let mut improved = false;

        for at in 0..key.len() {
            let mut chosen = key[at];

            for shift in 0..26u8 {
                key[at] = shift;
                let here = score(&key);
                if here > best {
                    best = here;
                    chosen = shift;
                    improved = true;
                }
            }

            key[at] = chosen;
        }

        if !improved {
            return (key, best);
        }
    }
}

/// Column depth below which counting stops being enough and climbing earns its
/// cost.
///
/// Twelve is where counting was measured to become reliable, in
/// `mantis::tests::probe_letters_per_column`. Above it the counted key is already right and a climb can only reach the
/// same answer more slowly. Below it the count degrades, and the climb, which
/// judges a key letter by every trigram its letters touch rather than by its
/// own column alone, starts being worth the work.
const CLIMB_BELOW: usize = 12;

/// Column depth below which even trigrams are not enough.
///
/// With seventeen letters and a seven letter key the real key scores 2970 in
/// trigrams and a wrong key scores 3042. The search is not failing there, it is
/// succeeding at the wrong question, and no amount of it helps. What breaks the
/// tie is what a letters-only view throws away: the spaces. Word lengths and the
/// words themselves are evidence, and under a score that reads them the same
/// pair goes 0.685 against 0.395.
///
/// Reading words costs far more than summing trigrams, so it is spent only
/// where nothing else can work: on thin columns, and only in a text short
/// enough that a key this size could be the answer. Thirty thin columns of a
/// thousand letter text are not a candidate key, they are an overfit, and the
/// ranking discounts them anyway.
const WORDS_BELOW: usize = 5;

/// Longest text on which a thin-column key is still worth reading words for.
const WORDS_TEXT: usize = 120;

/// Tags and tag fragments a flag is usually wrapped in.
///
/// Two jobs in one list. A whole tag that matches the whole run settles every
/// key position it touches at once and leaves nothing to search: `testCTF`
/// against seven enciphered letters pins all six positions of a six letter key,
/// exactly, by subtraction. That is worth listing the common ones for.
///
/// A fragment catches the rest. Tags are endless, every competition invents its
/// own, but almost all of them end in CTF, so sliding `ctf` along the run finds
/// three positions of a tag nobody listed. Fewer positions, and then a search.
///
/// Longest first, because a longer match pins more and searches less.
const CRIB_TAGS: [&str; 10] = [
    "picoctf", "testctf", "crypto", "flag", "pico", "ctf", "htb", "thm", "key", "the",
];

/// How many of the best tails to keep once a crib has settled the rest.
///
/// More than one because the last position is where the evidence runs out. With
/// eighteen letters "flag{nello_haman}" scores 0.2926 and "flag{hello_human}"
/// scores 0.2884, so the wrong key wins by four thousandths: nothing here can
/// tell them apart, and pretending otherwise means discarding the answer. Both
/// go in the list, next to each other, where the difference is obvious to anyone
/// reading them.
const NEAR_TIES: usize = 3;

/// Free key positions a crib may leave before the search stops being exhaustive.
///
/// Three is 17,576 keys, which is the whole remaining keyspace once a crib has
/// settled the rest, and nothing against a short text.
const EXHAUSTIVE_FREE: usize = 3;

/// Candidates carried from the fast sweep into the slow ranking.
///
/// The sweep scores with trigrams, which is an integer sum over a slice and
/// cheap enough to run seventeen thousand times per crib. Reading words is not,
/// and it is also the only thing that can pick the winner, so a shortlist
/// crosses from one to the other.
///
/// Generous, because trigrams are close to blind on the short text a crib is
/// for. Twelve letters of `testCTF{hello}` left the right key outside the top
/// twenty-four, and a shortlist that drops the answer is worse than no shortlist
/// at all. Two hundred is still a rounding error against the sweep itself.
const SWEEP_KEEP: usize = 200;

/// Where a flag shape sits, as (first letter, how many letters) in the
/// letters-only stream.
///
/// Punctuation is not enciphered by anything here, so a brace in the ciphertext
/// is a brace in the plaintext, at the same place. That is what makes this
/// possible at all.
fn crib_sites(data: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut letters = 0usize;
    let mut run = 0usize;

    for &byte in data {
        if byte.is_ascii_alphabetic() {
            letters += 1;
            run += 1;
        } else {
            if byte == b'{' && run > 0 {
                out.push((letters - run, run));
            }
            run = 0;
        }
    }

    out
}

/// Walks a key uphill, leaving the positions a crib already determined alone.
fn climb_free(start: &[u8], fixed: &[bool], score: impl Fn(&[u8]) -> f64) -> (Vec<u8>, f64) {
    let mut key = start.to_vec();
    let mut best = score(&key);

    loop {
        let mut improved = false;

        for at in 0..key.len() {
            if fixed[at] {
                continue;
            }

            let mut chosen = key[at];
            for shift in 0..26u8 {
                key[at] = shift;
                let here = score(&key);
                if here > best {
                    best = here;
                    chosen = shift;
                    improved = true;
                }
            }
            key[at] = chosen;
        }

        if !improved {
            return (key, best);
        }
    }
}

/// Keys implied by assuming a flag shape wraps a tag anyone would recognise.
///
/// The strongest evidence a short ciphertext ever offers, and it comes from the
/// punctuation rather than the letters. No cipher here touches a brace, so
/// `zobm{ojfop_nbruq}` says four enciphered letters sit directly before a brace,
/// and if those four spell "flag" then four key positions are settled outright
/// by subtraction. What is left is a handful of positions to search rather than
/// a whole key.
///
/// It costs nothing when it is wrong, because a wrong crib produces a key like
/// any other and is judged like any other.
pub fn from_crib(data: &[u8]) -> Vec<(Vec<u8>, usize, usize)> {
    let letters = indices(data);
    if letters.len() < COUNTABLE * 2 {
        return Vec::new();
    }

    let sites = crib_sites(data);
    if sites.is_empty() {
        return Vec::new();
    }

    let longest = MAX_KEY.min(letters.len() / COUNTABLE);
    let mut out: Vec<(Vec<u8>, usize, usize)> = Vec::new();

    for (start, run) in sites {
        for tag in CRIB_TAGS {
            if tag.len() > run {
                continue;
            }

            // Every place the fragment could sit inside the run. A tag ending in
            // CTF is the common case and lands on the last offset; one that is
            // the whole run, like `flag`, lands on the only offset there is.
            for offset in 0..=(run - tag.len()) {
                for length in 1..=longest {
                    let mut key = vec![0u8; length];
                    let mut fixed = vec![false; length];
                    let mut clash = false;

                    for (step, plain) in tag.bytes().enumerate() {
                        let at = (start + offset + step) % length;
                        let implied = (letters[start + offset + step] + 26 - (plain - b'a')) % 26;

                        // The same key position can be reached twice by a crib
                        // longer than the key. If the two disagree, this length is
                        // not the one.
                        if fixed[at] && key[at] != implied {
                            clash = true;
                            break;
                        }

                        key[at] = implied;
                        fixed[at] = true;
                    }

                    if clash {
                        continue;
                    }

                    let by_words = |candidate: &[u8]| -> f64 {
                        let text: Vec<u8> = candidate.iter().map(|shift| b'a' + shift).collect();
                        plainness(&decipher(data, &text)) as f64
                    };

                    let free: Vec<usize> = (0..length).filter(|&at| !fixed[at]).collect();

                    // Few enough positions left that they can simply all be tried.
                    // A climb can stop on a peak that is one letter out, and one
                    // letter out of a key is three or four letters out of the
                    // answer; exhaustive removes that failure entirely.
                    let mut found: Vec<Vec<u8>> = if free.len() <= EXHAUSTIVE_FREE {
                        // Swept with trigrams, decided by words. The sweep has to
                        // visit every remaining key and only integers are cheap
                        // enough for that; the decision has to read the text and
                        // only words can make it. A shortlist crosses between them.
                        let mut swept: Vec<(u32, Vec<u8>)> = Vec::new();
                        let mut trial = key.clone();

                        for combination in 0..26usize.pow(free.len() as u32) {
                            let mut rest = combination;
                            for &at in &free {
                                trial[at] = (rest % 26) as u8;
                                rest /= 26;
                            }
                            swept.push((weight_under(&letters, &trial), trial.clone()));
                        }

                        swept.sort_by_key(|(weight, _)| core::cmp::Reverse(*weight));
                        swept.truncate(SWEEP_KEEP);

                        let mut ranked: Vec<(f64, Vec<u8>)> = swept
                            .into_iter()
                            .map(|(_, candidate)| (by_words(&candidate), candidate))
                            .collect();

                        ranked.sort_by(|a, b| b.0.total_cmp(&a.0));
                        ranked.truncate(NEAR_TIES);
                        ranked.into_iter().map(|(_, key)| key).collect()
                    } else {
                        vec![climb_free(&key, &fixed, by_words).0]
                    };

                    let pinned = fixed.iter().filter(|&&at| at).count();

                    for candidate in found.drain(..) {
                        let spelled: Vec<u8> = candidate.iter().map(|shift| b'a' + shift).collect();

                        // Keep the strongest derivation of a key, since the same key
                        // can fall out of several cribs with different amounts of it
                        // actually deduced.
                        match out.iter_mut().find(|(seen, _, _)| *seen == spelled) {
                            Some((_, best, assumed)) if tag.len() > *assumed => {
                                *best = pinned;
                                *assumed = tag.len();
                            }
                            Some(_) => {}
                            None => out.push((spelled, pinned, tag.len())),
                        }
                    }
                }
            }
        }
    }

    out
}

/// Fresh starts before the best peak is taken as the key.
///
/// A climb lands on a local peak, and from a bad start the peak can be a key
/// that is right about half its letters. Restarting costs almost nothing here
/// because a key has only as many positions as it is long.
const CLIMB_RESTARTS: usize = 24;

/// The best key of one length, by counting and by climbing.
///
/// Counting comes first because it is free and, given a long enough column, it
/// is exact. Climbing then starts from that answer and from fresh guesses, and
/// whichever ends up spelling the most English wins. On a long text they agree.
/// On a short one only the climb has anything to go on.
fn best_of_length(data: &[u8], letters: &[u8], length: usize, rng: &mut Rng) -> Vec<u8> {
    let counted: Vec<u8> = key_of_length(data, length)
        .iter()
        .map(|b| b - b'a')
        .collect();

    // key_of_length folds multiples down, so it can come back shorter.
    let counted = if counted.len() == length {
        counted
    } else {
        vec![0u8; length]
    };

    // Trigrams drive the climb at every length. They are an integer sum over a
    // slice, so restarts are affordable, and on anything but the shortest text
    // they land on the same key a fuller score would.
    let by_trigram = |key: &[u8]| weight_under(letters, key) as f64;

    // Words decide where trigrams provably cannot: see [`WORDS_BELOW`]. Reading
    // them costs far more than an integer sum, so this runs only on the lengths
    // that need it, and only ever against keys of one length, where the bias
    // towards longer keys has nothing to act on.
    let by_words = |key: &[u8]| -> f64 {
        let letters: Vec<u8> = key.iter().map(|shift| b'a' + shift).collect();
        plainness(&decipher(data, &letters)) as f64
    };

    let per_column = letters.len() / length.max(1);

    // A column this deep names its own shift. Counting it is exact and instant,
    // and a climb can only reach the same answer more slowly.
    if per_column >= CLIMB_BELOW {
        return counted.iter().map(|shift| b'a' + shift).collect();
    }

    let (mut best, mut top) = climb(&counted, by_trigram);
    let mut seen = vec![best.clone()];

    for _ in 0..CLIMB_RESTARTS {
        let start: Vec<u8> = (0..length).map(|_| (rng.next() % 26) as u8).collect();
        let (key, here) = climb(&start, by_trigram);

        if !seen.contains(&key) {
            seen.push(key.clone());
        }
        if here > top {
            top = here;
            best = key;
        }
    }

    // Where the columns are thinnest the trigram peak is often not the answer,
    // and re-ranking the peaks it reached cannot help when the right key was
    // never among them. So the climb runs again under the fuller score, which
    // is affordable precisely because so few lengths qualify.
    if per_column < WORDS_BELOW && letters.len() <= WORDS_TEXT {
        let mut peaks = seen;

        for _ in 0..CLIMB_RESTARTS {
            let start: Vec<u8> = (0..length).map(|_| (rng.next() % 26) as u8).collect();
            peaks.push(climb(&start, by_words).0);
        }
        peaks.push(climb(&counted, by_words).0);

        if let Some(better) = peaks
            .into_iter()
            .max_by(|a, b| by_words(a).total_cmp(&by_words(b)))
        {
            best = better;
        }
    }

    best.iter().map(|shift| b'a' + shift).collect()
}

/// A key worked out of the text at one assumed key length.
#[derive(Debug, Clone, PartialEq)]
pub struct Derived {
    pub key: Vec<u8>,
    /// Key positions a crib settled by subtraction rather than by search.
    ///
    /// Equal to the key length when a tag matched the whole run in front of the
    /// brace, which leaves nothing to search at all. Nought when the key was
    /// climbed out of the letters like any other.
    pub deduced: usize,
    /// Letters of plaintext the crib assumed to get there.
    ///
    /// The size of the guess being made. Assuming seven letters spell `testCTF`
    /// and finding that they settle a whole key consistently is a far larger
    /// claim, and a far better checked one, than assuming three spell `htb`.
    pub assumed: usize,
    /// Letters available to each key position, which is the whole story about
    /// how much this key is worth. Around twelve it becomes reliable; at two it
    /// is a shape the text suggested rather than a key.
    pub per_column: usize,
    pub plaintext: Vec<u8>,
    pub score: f32,
}

/// Fewest letters a column can have and still be counted at all.
///
/// Not enough to be right, only enough to compute. Below this a column has no
/// distribution, and the "key" letter it yields is whichever one the first
/// letter happens to suggest.
const COUNTABLE: usize = 2;

/// Every key the text itself gives up, one per assumed length, best first.
///
/// [`solve`] does this and then picks, which is right when it can tell: it will
/// not report a key it cannot stand behind, and on a short text that means it
/// reports nothing at all. This reports the working instead.
///
/// Each length is a separate attack. Split the letters into that many columns,
/// and every column is a plain Caesar shift because the same key letter enciphered
/// all of it, so counting letters in the column gives that key letter back. Do
/// that for each position and the key falls out. Nothing here is guessed at or
/// looked up; a key that appears in this list appeared because the ciphertext
/// produced it, and a different ciphertext produces different keys.
///
/// What varies is how much the columns had to say. Twenty letters in a column
/// name their shift confidently and two letters name it by coin toss, which is
/// why [`Derived::per_column`] is reported alongside and why this is a list to
/// read rather than an answer to take.
pub fn derive(data: &[u8]) -> Vec<Derived> {
    let letters = letters_of(data);
    if letters.len() < COUNTABLE * 2 {
        return Vec::new();
    }

    let longest = MAX_KEY.min(letters.len() / COUNTABLE);
    let numbered = indices(data);
    let mut rng = Rng::seeded(&numbered);
    let mut out: Vec<Derived> = Vec::new();

    // Keys a flag shape settles outright come first, because they were not
    // guessed at: four letters of a crib subtract four key positions straight
    // out of the ciphertext, and only what is left has to be searched for.
    let mut candidates: Vec<(Vec<u8>, usize, usize)> = from_crib(data);

    for length in 1..=longest {
        candidates.push((best_of_length(data, &numbered, length, &mut rng), 0, 0));
    }

    for (key, deduced, assumed) in candidates {
        // Folded down first. A ten letter search on a five letter key recovers
        // "lemonlemon", which deciphers identically and is the same answer said
        // twice, so it collapses to what it repeats before anything compares it.
        let key = shortest_period(&key);

        // A key of nothing but A deciphers to the input. It is a valid key and
        // it is never the answer, so offering it means offering the text back
        // and calling it a reading.
        if key.iter().all(|&letter| letter == b'a') {
            continue;
        }

        if out.iter().any(|seen| seen.key == key) {
            continue;
        }

        let plaintext = decipher(data, &key);
        out.push(Derived {
            deduced,
            assumed,
            per_column: letters.len() / key.len().max(1),
            score: plainness(&plaintext),
            key,
            plaintext,
        });
    }

    // Ranked with a cost per key letter. A longer key has more positions to
    // bend and fits any text better given the chance, so without this the list
    // is led by the longest key tried, every time, on every input.
    out.sort_by(|a, b| worth(b).total_cmp(&worth(a)));
    out
}

/// What each extra key letter costs when ranking keys of different lengths.
///
/// Ten times what [`LENGTH_COST`] charges a solve, because a solve is choosing
/// between a key and a multiple of itself, which decipher identically. This is
/// choosing between keys that decipher to different text, where the longer one
/// had more freedom to arrive at something readable and the readability is
/// worth correspondingly less.
const KEY_COST: f32 = 0.02;

/// What one passed consistency check is worth, per letter of crib behind it.
///
/// Set so that a seven letter tag agreeing with itself cannot be overtaken by
/// readability, and a three letter one can be.
const CHECK_WEIGHT: f32 = 0.3;

fn worth(derived: &Derived) -> f32 {
    // How many times the crib had to agree with itself.
    //
    // This is the only part of a crib that could have failed, and so the only
    // part that is evidence. A four letter tag settling a four letter key pins
    // each position exactly once: any four letters would have done that, and it
    // proves nothing. Seven letters spelling `testCTF` against a six letter key
    // reach one position twice and have to give the same answer both times, and
    // a wrong guess almost never does.
    //
    // It outranks readability because the two disagree exactly where it matters
    // most: `testCTF{W3lc0me2DaD@sh}` is the right answer and reads like
    // nothing at all.
    // Weighted by how much the crib claimed, because a check is only as strong
    // as the assumption it tested. Three letters agreeing once is a coincidence
    // that happens; seven letters spelling a whole tag and agreeing is not.
    let checks = derived.assumed.saturating_sub(derived.deduced) as f32
        * derived.assumed as f32
        * CHECK_WEIGHT;

    // Weaker than it looks once a crib is involved, since a crib pins the tag
    // and every key it produces therefore ends in one. Kept for the keys that
    // were climbed rather than deduced, where producing a flag is a surprise.
    let flagged = crate::bytes::flag_candidates(&derived.plaintext)
        .iter()
        .any(|found| crate::bytes::tag_is_known(&found.text));

    let base = derived.score - derived.key.len() as f32 * KEY_COST;
    base + checks + if flagged { 0.25 } else { 0.0 }
}

/// How much of each deciphering to show in the list.
///
/// Enough to recognise English, or to see that a key is one letter out, which is
/// the common case on a short text and the reason this list exists.
const PREVIEW: usize = 120;

pub fn derived_json(found: &[Derived]) -> String {
    use crate::json::{push_field, push_number, push_string};

    let mut out = String::from("[");

    for (i, derived) in found.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "key", &String::from_utf8_lossy(&derived.key));
        out.push(',');
        push_number(&mut out, "perColumn", derived.per_column);
        out.push(',');
        push_string(&mut out, "score");
        out.push_str(&format!(":{:.3},", derived.score));
        push_field(
            &mut out,
            "preview",
            &crate::json::latin1(&derived.plaintext[..PREVIEW.min(derived.plaintext.len())]),
        );
        out.push('}');
    }

    out.push(']');
    out
}

/// How much more readable a decryption has to be than the text it came from.
///
/// Skipping the all-A key is not enough on its own: a key that is A everywhere
/// but one position leaves the text almost untouched and almost as readable,
/// and on English that clears any fixed bar. Making the answer beat its own
/// input is what turns those down, and it is the rule the rest of Mantis
/// already works by.
const MIN_GAIN: f32 = 0.1;

/// Letters a key position needs before a solve will stand behind the key.
///
/// [`derive`] deliberately offers keys thinner than this, because a list is
/// something to read and a person can see for themselves that two letters of
/// evidence is nothing. A reported answer is different, and this is the line.
///
/// Five, because that is where climbing was measured to work.
/// `tests::probe_hard_short_keys` recovers a seven letter key exactly from 5.3
/// letters per position and gets six of its seven letters at 2.4. Counting
/// columns needed twelve for the same job, which is what this used to be.
const SOLVE_BELOW: usize = 5;

/// The key this text gives up, when it gives one up at all.
///
/// Built on [`derive`], which works a key out at every plausible length and
/// climbs each one, rather than counting columns and hoping. Counting alone
/// needed about twelve letters per key position; climbing gets there on five,
/// because it judges a key letter by every trigram its letters touch instead of
/// by its own column in isolation.
///
/// What has not changed is the refusal to guess. A key is reported only when
/// the text it produces reads, and on a short ciphertext nothing will.
pub fn solve(data: &[u8]) -> Option<Candidate> {
    let letters = letters_of(data);
    if letters.len() < MIN_LETTERS {
        return None;
    }

    let before = plainness(data);

    derive(data)
        .into_iter()
        .filter(|found| {
            found.per_column >= SOLVE_BELOW
                && found.score >= MIN_SCORE
                && found.score >= before + MIN_GAIN
        })
        .map(|found| Candidate {
            key: found.key,
            plaintext: found.plaintext,
            score: found.score,
        })
        .fold(None::<Candidate>, |best, next| match best {
            Some(current) if weighed(&current) >= weighed(&next) => Some(current),
            _ => Some(next),
        })
}

/// A candidate's score once its key length is paid for.
fn weighed(found: &Candidate) -> f32 {
    found.score - found.key.len() as f32 * LENGTH_COST
}

#[cfg(test)]
mod tests;
