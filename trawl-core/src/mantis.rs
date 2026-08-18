//! Mantis — cryptography.
//!
//! Named for the mantis shrimp, which cracks armoured shells with the fastest
//! strike in the animal kingdom and sees a range of colour we are blind to.
//! Force and perception, which is the whole of cryptanalysis.
//!
//! This module starts with the most common task in the category: someone hands
//! you a string that has been through base64, then hex, then ROT13, and wants
//! you to work back to the message. Mantis peels those layers automatically.
//!
//! The hard part is not decoding. It is knowing when to stop. Plenty of English
//! words are valid base64, and a decoder that always succeeds will happily turn
//! a readable answer into noise and report it as progress. So every peel has to
//! justify itself: the result is kept only when it looks more like something a
//! person would read than what went into it.

pub mod encodings;
pub mod xor;

use crate::bytes;

/// English letter frequencies, in percent, a through z.
const ENGLISH: [f32; 26] = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406,
    6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074,
];

/// Words common enough that finding them is strong evidence of English.
///
/// Letter frequency alone is too blunt on a short string. "The quick brown fox"
/// and its ROT13 have nearly the same letter spread, because a pangram is flat
/// by design, so frequency can barely tell them apart. Only one of them contains
/// the word "the".
const COMMON: [&str; 40] = [
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "it", "for", "not", "on", "with",
    "he", "as", "you", "do", "at", "this", "but", "his", "by", "from", "they", "we", "say", "her",
    "she", "or", "an", "will", "my", "one", "all", "would", "there", "their", "is", "are",
];

/// Fraction of words that are recognisably English, scaled so that a sentence
/// with a couple of them counts as convincing.
fn word_fit(data: &[u8]) -> f32 {
    let Ok(text) = core::str::from_utf8(data) else {
        return 0.0;
    };

    let mut total = 0f32;
    let mut known = 0f32;

    for token in text.split_whitespace() {
        let word: String = token
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .flat_map(|c| c.to_lowercase())
            .collect();

        if word.is_empty() {
            continue;
        }
        total += 1.0;
        if COMMON.contains(&word.as_str()) {
            known += 1.0;
        }
    }

    if total == 0.0 {
        return 0.0;
    }

    // Roughly a third of ordinary prose is these words, so treat that as a full
    // match rather than demanding every word be on the list.
    ((known / total) * 2.5).clamp(0.0, 1.0)
}

fn printable(byte: u8) -> bool {
    (0x20..0x7f).contains(&byte) || matches!(byte, b'\n' | b'\r' | b'\t')
}

/// How much a run of bytes looks like something a person would read.
///
/// Zero is binary noise and one is ordinary English prose. The number itself
/// carries no meaning beyond ordering; it exists so a peel can be compared
/// against what it started from.
///
/// Printability alone will not do. Base64 is entirely printable, and so is its
/// decoded output, so a printable ratio cannot tell the two apart. What does is
/// the shape of the letters: English leans hard on e, t, a and o and puts a
/// space every five or six characters, and an encoded blob does neither.
pub fn plainness(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let readable = data.iter().filter(|&&b| printable(b)).count() as f32 / data.len() as f32;

    // Anything with a real proportion of control bytes is not text, and no
    // amount of letter frequency should argue otherwise.
    if readable < 0.85 {
        return readable * 0.3;
    }

    let mut counts = [0f32; 26];
    let mut letters = 0f32;
    let mut spaces = 0f32;

    for &byte in data {
        if byte.is_ascii_alphabetic() {
            counts[(byte.to_ascii_lowercase() - b'a') as usize] += 1.0;
            letters += 1.0;
        } else if byte == b' ' {
            spaces += 1.0;
        }
    }

    if letters < 4.0 {
        // Too few letters to say anything about their distribution. A run of
        // dots and dashes, or of ones and zeroes, is printable and is not text.
        return readable * 0.25;
    }

    // How far the letter mix sits from English. Identical gives zero, and a
    // uniform spread across the alphabet gives roughly 0.5.
    let divergence: f32 = (0..26)
        .map(|i| (counts[i] / letters - ENGLISH[i] / 100.0).abs())
        .sum::<f32>()
        / 2.0;

    let letter_fit = (1.0 - divergence).clamp(0.0, 1.0);

    // English runs about one space every six characters. Encoded blobs have
    // none, and a wall of unbroken characters is the clearest tell there is.
    let space_ratio = spaces / data.len() as f32;
    let spacing = if space_ratio == 0.0 {
        0.0
    } else {
        (1.0 - (space_ratio - 0.17).abs() / 0.17).clamp(0.0, 1.0)
    };

    readable * (0.35 * letter_fit + 0.2 * spacing + 0.35 * word_fit(data) + 0.1)
}

/// One layer removed.
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    pub encoding: &'static str,
    /// What it produced, which is the input to the next step.
    pub output: Vec<u8>,
    /// How much more readable this made things.
    pub gain: f32,
    /// Why it was kept, in words.
    pub reason: String,
    /// True when the input's own form justified this, rather than the result.
    ///
    /// A long even-length run of nothing but hex digits is hex, whatever it
    /// decodes to. A rotation is never like that: every shift applies, so only
    /// the result can argue for it.
    pub structural: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Peel {
    pub steps: Vec<Step>,
    pub result: Vec<u8>,
    /// Plainness of the final result, for the caller to report honestly.
    pub score: f32,
}

/// Name, decoder, and whether the input's own form justifies the peel.
type Codec = (&'static str, fn(&[u8]) -> Option<Vec<u8>>, bool);

/// Everything Mantis will try, in the order it tries them.
///
/// Order matters only for tie-breaking: the peel takes whichever candidate
/// improves things most, and this decides a draw. Narrower codecs come first so
/// a blob that is unambiguously one thing is not claimed by a looser one.
/// Ordered narrowest alphabet first, so when several accept the same input the
/// most specific reading wins. A run of hex digits is legal base64 too, and hex
/// is the honest answer.
///
/// ROT13 sits here for convenience but is not structural: it accepts any text at
/// all, so it can only ever be justified by its result.
pub const CODECS: [Codec; 11] = [
    ("morse", encodings::morse, true),
    ("binary", encodings::binary, true),
    ("decimal bytes", encodings::decimal, true),
    ("hex", encodings::hex, true),
    ("base32", encodings::base32, true),
    ("base64", encodings::base64, true),
    ("base64url", encodings::base64_url, true),
    ("ascii85", encodings::ascii85, true),
    ("percent-encoding", encodings::percent, true),
    ("HTML entities", encodings::html_entities, true),
    ("ROT13", encodings::rot13, false),
];

/// A chain has to end up this much more readable than it started.
///
/// Set too low, the peeler chases noise and turns a readable answer into
/// garbage. Set too high, it stops one layer short of the message.
const MIN_GAIN: f32 = 0.08;

/// How deep a chain will be followed. Real ones are two or three layers.
const MAX_DEPTH: usize = 6;

/// Beats any plainness score, so a flag always wins.
const CONCLUSIVE: f32 = 2.0;

/// What each extra layer costs the chain it belongs to.
///
/// Without this the search wanders. Plainness is a rough measure, so somewhere
/// down a chain of four wrong turns there is usually a string that scores a
/// fraction above the right answer, and a search that only maximises the score
/// will take it. Charging for every step means a longer chain has to be clearly
/// better rather than accidentally better.
const STEP_COST: f32 = 0.06;

/// How readable a rotation has to leave things before it is taken.
///
/// An absolute bar rather than a relative one, because a rotation is a cipher
/// being solved and a solved cipher reads. Asking only for an improvement lets
/// the search wander over encrypted bytes, where some shift always scores a
/// fraction higher than the last, and report the wandering as progress.
const ROTATION_BAR: f32 = 0.45;

/// Longest run of bytes worth searching. Beyond this it is a file, not a pasted
/// string, and the byte-level tools are the right place for it.
const MAX_INPUT: usize = 1 << 18;

/// True when a result is worth keeping whatever the score says.
///
/// A flag or a file signature is the answer, and letting a frequency heuristic
/// veto it would be absurd.
fn conclusive(data: &[u8]) -> Option<String> {
    if let Some(format) = bytes::identify(data) {
        return Some(format!("{format} signature"));
    }

    bytes::flag_candidates(data)
        .first()
        .map(|found| format!("flag shape, {}", found.text))
}

fn rate(data: &[u8]) -> f32 {
    if conclusive(data).is_some() {
        CONCLUSIVE
    } else {
        plainness(data)
    }
}

/// Everything worth trying from here.
///
/// Structural codecs can sit in the middle of a chain, so they are always
/// explored. Rotations are only taken when they improve things on the spot,
/// because a rotation applied to an encoded blob breaks the blob rather than
/// setting up the next layer, so it is never a useful middle step.
fn candidates(data: &[u8]) -> Vec<(&'static str, Vec<u8>, bool)> {
    let mut out = Vec::new();

    for (name, decode, structural) in CODECS {
        if let Some(decoded) = decode(data).filter(|d| !d.is_empty() && d != data) {
            out.push((name, decoded, structural));
        }
    }

    // Scored with plainness alone rather than `rate`, because `rate` runs a flag
    // scan and this runs twenty-six times per node.
    let here = plainness(data);
    let mut rotation = |name: &'static str, rotated: Vec<u8>| {
        if rotated == data {
            return;
        }
        let score = plainness(&rotated);
        if (score >= ROTATION_BAR && score >= here + MIN_GAIN) || conclusive(&rotated).is_some() {
            out.push((name, rotated, false));
        }
    };

    if let Some(rotated) = encodings::rot47(data) {
        rotation("ROT47", rotated);
    }
    for shift in 1..26u8 {
        if shift != 13 {
            // Thirteen is already in the table, and naming it reads better.
            rotation("ROT", encodings::rot_n(data, shift));
        }
    }

    out
}

/// The best chain reachable from here, and what it ends up scoring.
///
/// Searching rather than stepping is the whole point. A middle layer usually
/// looks no better than the one above it: base64 wrapped around hex decodes to a
/// wall of hex digits, which reads no more like English than the base64 did. A
/// peeler that demands an improvement at every step stops there and never
/// reaches the sentence underneath.
fn explore(data: &[u8], seen: &mut Vec<Vec<u8>>, depth: usize) -> (f32, Vec<Step>) {
    let here = rate(data);
    if depth >= MAX_DEPTH || here == CONCLUSIVE || data.len() > MAX_INPUT {
        return (here, Vec::new());
    }

    let mut best = (here, Vec::new());

    for (encoding, output, structural) in candidates(data) {
        if seen.contains(&output) {
            continue;
        }

        seen.push(output.clone());
        let (reachable, rest) = explore(&output, seen, depth + 1);
        seen.pop();

        // What this branch is worth, once its own step is paid for.
        let score = reachable - STEP_COST;
        if score <= best.0 {
            continue;
        }

        let gain = rate(&output) - here;
        let reason = match conclusive(&output) {
            Some(why) => why,
            None if gain >= MIN_GAIN => format!("reads {:.0}% more like text", gain * 100.0),
            None => "a layer on the way down".to_string(),
        };

        let mut steps = vec![Step {
            encoding,
            output,
            gain,
            reason,
            structural,
        }];
        steps.extend(rest);
        best = (score, steps);
    }

    best
}

/// Unwraps layers that only one codec will accept at all.
///
/// A separate pass, because it answers a different question. The search asks
/// "does this get me somewhere readable"; this asks "is this unambiguously an
/// encoding". A hundred characters of nothing but hex digits, at an even length,
/// is hex whatever it decodes to, and when what it decodes to is a cipher the
/// search will never take the step because the ciphertext reads no better than
/// the hex did. Refusing to unwrap it would leave the cipher invisible.
fn unwrap_structural(data: &[u8]) -> Vec<Step> {
    let mut steps = Vec::new();
    let mut current = data.to_vec();

    while steps.len() < MAX_DEPTH {
        // Already readable, so this is the answer rather than a wrapper. Pure
        // hex reads as hex, and "deadbeefdeadbeef" should be left as it is.
        if plainness(&current) >= ROTATION_BAR {
            break;
        }

        let found = CODECS.iter().filter(|(_, _, structural)| *structural).find_map(
            |(name, decode, _)| {
                decode(&current)
                    .filter(|d| !d.is_empty() && *d != current)
                    .map(|d| (*name, d))
            },
        );

        let Some((encoding, output)) = found else {
            break;
        };
        let gain = rate(&output) - rate(&current);

        current = output.clone();
        steps.push(Step {
            encoding,
            output,
            gain,
            reason: "the only thing this could be".to_string(),
            structural: true,
        });

        if conclusive(&current).is_some() {
            break;
        }
    }

    steps
}

/// Peels layer after layer until nothing improves.
pub fn peel(data: &[u8]) -> Peel {
    let mut seen = vec![data.to_vec()];
    let (score, steps) = explore(data, &mut seen, 0);

    // The whole chain has to be worth it, not just the last step of it.
    //
    // A chain of purely structural peels counts even when it ends somewhere
    // unreadable. That is the shape of a cipher wrapped for transport: the hex
    // comes off cleanly and what is underneath is still encrypted. Demanding a
    // readability gain there would refuse to unwrap it and leave the cipher
    // invisible.
    let structural_only = steps.iter().all(|step| step.structural);
    let worth_it = score == CONCLUSIVE || score >= plainness(data) + MIN_GAIN || structural_only;

    let steps = if worth_it && !steps.is_empty() {
        steps
    } else {
        // Nothing scored its way through, so fall back to what the form alone
        // justifies. Usually that is nothing at all.
        unwrap_structural(data)
    };

    if steps.is_empty() {
        return Peel {
            steps,
            score: plainness(data),
            result: data.to_vec(),
        };
    }

    let result = steps.last().map(|s| s.output.clone()).unwrap_or_default();
    Peel {
        score: plainness(&result),
        steps,
        result,
    }
}

/// Everything Mantis makes of a pasted string.
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    pub peel: Peel,
    /// XOR run against whatever the peel ended with.
    pub xor: xor::Recovery,
}

/// Peels the encodings, then attacks what is left with XOR.
///
/// In that order, because that is the order challenges are built in. Bytes get
/// XORed and the result is unreadable, so it gets hex or base64 wrapped to
/// survive being pasted around. Unwrapping first is what makes the cipher
/// visible at all.
pub fn read(data: &[u8]) -> Reading {
    let peel = peel(data);
    let inner = if peel.steps.is_empty() {
        data
    } else {
        &peel.result
    };

    Reading {
        // Nothing to recover if the peel already arrived somewhere readable.
        xor: if conclusive(inner).is_some() || plainness(inner) >= 0.5 {
            xor::Recovery::default()
        } else {
            xor::recover(inner)
        },
        peel,
    }
}

/// The reading as JSON, ready to leave the worker.
pub fn json(data: &[u8]) -> String {
    use crate::json::{push_field, push_number, push_string};

    let reading = read(data);
    let peeled = &reading.peel;
    let mut out = String::from("{");

    push_number(&mut out, "depth", peeled.steps.len());
    out.push(',');
    push_string(&mut out, "score");
    out.push_str(&format!(":{:.3}", peeled.score));
    out.push(',');
    push_field(&mut out, "result", &crate::json::latin1(&peeled.result));
    out.push(',');

    push_string(&mut out, "steps");
    out.push_str(":[");
    for (i, step) in peeled.steps.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "encoding", step.encoding);
        out.push(',');
        push_field(&mut out, "reason", &step.reason);
        out.push(',');
        push_field(&mut out, "output", &crate::json::latin1(&step.output));
        out.push('}');
    }
    out.push_str("],");

    let candidate = |out: &mut String, kind: &str, c: &xor::Candidate| {
        out.push('{');
        push_field(out, "kind", kind);
        out.push(',');
        push_field(out, "key", &c.key_text());
        out.push(',');
        push_number(out, "keyLength", c.key.len());
        out.push(',');
        push_string(out, "score");
        out.push_str(&format!(":{:.3}", c.score));
        out.push(',');
        push_field(out, "plaintext", &crate::json::latin1(&c.plaintext));
        out.push(',');
        push_string(out, "flags");
        out.push_str(":[");
        for (j, flag) in c.flags.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            push_string(out, flag);
        }
        out.push_str("]}");
    };

    push_string(&mut out, "xor");
    out.push_str(":[");
    for (i, (kind, found)) in reading.xor.best_first().iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        candidate(&mut out, kind, found);
    }
    out.push_str("]}");

    out
}

#[cfg(test)]
mod tests;
