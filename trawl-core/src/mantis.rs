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

pub mod affine;
pub mod encodings;
pub mod frequency;
pub mod hashes;
pub mod hill;
pub mod keyed;
pub mod ngram;
pub mod playfair;
pub mod shortlist;
pub mod substitution;
pub mod transposition;
pub mod vigenere;
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

/// How much of a run is spelled out of words Mantis recognises, scaled so that
/// an ordinary sentence counts as a full match.
///
/// Measured by letter rather than by word, which matters more than it sounds.
/// Counting words, a string with four tokens in it and the word "a" among them
/// scores 0.25, and so does a real sentence where one word in four is common.
/// They are not comparable, and the short one was being read as half English:
///
/// ```text
/// sample              by token   by letter
/// english prose          0.484       0.345
/// english short          0.222       0.171
/// a lucky "a" in noise   0.250       0.040
/// ```
///
/// `tests::probe_word_fit_by_length` redraws that. Matching "a" is worth one
/// letter of evidence, matching "the" is worth three, and noise stops being able
/// to buy a good score with a single stray article.
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

        total += word.len() as f32;
        if COMMON.contains(&word.as_str()) {
            known += word.len() as f32;
        }
    }

    if total == 0.0 {
        return 0.0;
    }

    // Prose spends 0.345 of its letters on these words, measured above, so that
    // is what a full match means. Counting by word the same threshold sat at
    // 2.5, and carrying it over unchanged would have quietly marked all English
    // down: the multiplier has to follow the thing being counted.
    ((known / total) * 2.9).clamp(0.0, 1.0)
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

    // Letter counts and spacing describe the shape of a text. Words and trigrams
    // are the two that read it, and they carry most of the weight because the
    // other two can be perfect while the text says nothing: rearranging English
    // leaves the letter mix exactly English and the spacing untouched. Scrambled
    // prose has to land well clear of 0.5, because that is where the rest of
    // Mantis stops looking.
    readable
        * (0.15 * letter_fit
            + 0.1 * spacing
            + 0.35 * word_fit(data)
            + 0.3 * ngram::fitness(data)
            + 0.1)
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
///
/// Base58 is not structural either, for the same reason and less obviously. Its
/// alphabet is 58 of the 62 alphanumerics, so very nearly every alphanumeric
/// string is valid base58 and decodes to something. Treating that as evidence
/// lets it fire on an answer that was already correct and hand back noise.
pub const CODECS: [Codec; 14] = [
    ("morse", encodings::morse, true),
    ("binary", encodings::binary, true),
    ("decimal bytes", encodings::decimal, true),
    ("hex", encodings::hex, true),
    ("base32", encodings::base32, true),
    ("base58", encodings::base58, false),
    ("base64", encodings::base64, true),
    ("base64url", encodings::base64_url, true),
    ("ascii85", encodings::ascii85, true),
    ("uuencode", encodings::uuencode, true),
    ("percent-encoding", encodings::percent, true),
    ("quoted-printable", encodings::quoted_printable, true),
    ("HTML entities", encodings::html_entities, true),
    ("ROT13", encodings::rot13, false),
];

/// A chain has to end up this much more readable than it started.
///
/// Set too low, the peeler chases noise and turns a readable answer into
/// garbage. Set too high, it stops one layer short of the message.
const MIN_GAIN: f32 = 0.08;

/// How deep a chain will be followed. Real ones are two or three layers.
pub const MAX_DEPTH: usize = 6;

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
/// veto it would be absurd. A configured tag turns a flag shape conclusive too:
/// it was named, not merely recognised, so it outweighs a readability guess.
fn conclusive(data: &[u8], tags: &[String]) -> Option<String> {
    if let Some(format) = bytes::identify(data) {
        return Some(format!("{format} signature"));
    }

    let flags = bytes::flag_candidates(data);
    // A configured tag is the strongest claim: it was named, not merely guessed,
    // so it outweighs the brace shape alone. Falls back to the plain shape, which
    // is what recognised flags always were.
    flags
        .iter()
        .find(|found| bytes::tag_is_known_for(&found.text, tags))
        .or(flags.first())
        .map(|found| format!("flag shape, {}", found.text))
}

fn rate(data: &[u8], tags: &[String]) -> f32 {
    if conclusive(data, tags).is_some() {
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
/// How much of a run has to be letters before a letter rotation is worth trying.
///
/// Halfway between ciphertext and prose, which are not close together. See
/// [`candidates`] for the measurements.
const ROTATABLE: f32 = 0.5;

/// Whether a base-N reading is justified by the input's own shape, or merely
/// possible.
///
/// Base64 packs three bytes into four characters, so real output arrives in
/// whole groups: a length that is a multiple of four, or padding saying where
/// the last group stopped. Anything else still decodes, dropping the leftover
/// bits, but its length vouches for nothing. That distinction only starts to
/// matter when the answer is not English. An eleven-character token is valid
/// base64, and a peel that treats "valid" as "justified" will unwrap the right
/// answer into noise and report it as a layer.
fn grouped(name: &str, data: &[u8]) -> bool {
    let group = match name {
        "base64" | "base64url" => 4,
        "base32" => 8,
        // Ascii85 takes 85 of the 95 printable characters and allows a short
        // final group, so neither its alphabet nor its length rules anything
        // out: very nearly every printable run "is" ascii85 and decodes to
        // bytes. Only the wrapper it is normally shipped inside is evidence.
        "ascii85" => return data.windows(2).any(|pair| pair == b"<~"),
        _ => return true,
    };

    // Padding counts towards the length rather than excusing it: real output
    // divides by the group whether it was padded or not.
    data.iter().filter(|b| !b.is_ascii_whitespace()).count() % group == 0
}

fn candidates(data: &[u8], tags: &[String]) -> Vec<(&'static str, Vec<u8>, bool)> {
    let mut out = Vec::new();

    for (name, decode, structural) in CODECS {
        if let Some(decoded) = decode(data).filter(|d| !d.is_empty() && d != data) {
            out.push((name, decoded, structural && grouped(name, data)));
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
        if (score >= ROTATION_BAR && score >= here + MIN_GAIN) || conclusive(&rotated, tags).is_some() {
            out.push((name, rotated, false));
        }
    };

    // ROT47 works across the whole printable range, so it is judged on its
    // result alone. A letter rotation is different: it only touches letters, so
    // on data that is mostly not letters it cannot decipher anything and can
    // only corrupt. Wrapped ciphertext is exactly that, and a rotation applied
    // to it destroys the key before XOR recovery ever sees it.
    //
    // Letters as a share of printable bytes, measured in
    // `tests::probe_letter_density`:
    //
    // ```text
    //   english 0.81   base64 blob 0.88   random token 0.91
    //   xor ciphertext 0.19   hex 0.06
    // ```
    if let Some(rotated) = encodings::rot47(data) {
        rotation("ROT47", rotated);
    }

    let printable = data.iter().filter(|&&b| (0x20..0x7f).contains(&b)).count();
    let letters = data.iter().filter(|b| b.is_ascii_alphabetic()).count();

    if printable > 0 && letters as f32 / printable as f32 >= ROTATABLE {
        for shift in 1..26u8 {
            if shift != 13 {
                // Thirteen is already in the table, and naming it reads better.
                rotation("ROT", encodings::rot_n(data, shift));
            }
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
fn explore(data: &[u8], seen: &mut Vec<Vec<u8>>, tags: &[String], depth: usize, depth_budget: usize) -> (f32, Vec<Step>) {
    let here = rate(data, tags);
    if depth >= depth_budget || here == CONCLUSIVE || data.len() > MAX_INPUT {
        return (here, Vec::new());
    }

    let mut best = (here, Vec::new());

    for (encoding, output, structural) in candidates(data, tags) {
        if seen.contains(&output) {
            continue;
        }

        seen.push(output.clone());
        let (reachable, rest) = explore(&output, seen, tags, depth + 1, depth_budget);
        seen.pop();

        let score = reachable - STEP_COST;
        if score <= best.0 {
            continue;
        }

        let gain = rate(&output, tags) - here;
        let reason = match conclusive(&output, tags) {
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
pub fn unwrap_structural(data: &[u8], tags: &[String], depth_budget: usize) -> Vec<Step> {
    let mut steps = Vec::new();
    let mut current = data.to_vec();

    while steps.len() < depth_budget {
        if plainness(&current) >= ROTATION_BAR {
            break;
        }

        if hashes::is_digest(&current) {
            break;
        }

        let found = CODECS
            .iter()
            .filter(|(name, _, structural)| *structural && grouped(name, &current))
            .find_map(|(name, decode, _)| {
                decode(&current)
                    .filter(|d| !d.is_empty() && *d != current)
                    .map(|d| (*name, d))
            });

        let Some((encoding, output)) = found else {
            break;
        };
        let gain = rate(&output, tags) - rate(&current, tags);

        current = output.clone();
        steps.push(Step {
            encoding,
            output,
            gain,
            reason: "the only thing this could be".to_string(),
            structural: true,
        });

        if conclusive(&current, tags).is_some() {
            break;
        }
    }

    steps
}

/// Peels layer after layer until nothing improves.
fn peel_with(data: &[u8], tags: &[String]) -> Peel {
    peel_with_depth(data, tags, MAX_DEPTH)
}

/// Internal peeler that accepts a remaining depth budget.
/// Used by the worker to share one six-layer budget across Rust and platform layers.
pub fn peel_with_depth(data: &[u8], tags: &[String], depth_budget: usize) -> Peel {
    let mut seen = vec![data.to_vec()];
    let (score, steps) = explore(data, &mut seen, tags, 0, depth_budget);

    let structural_only = steps.iter().all(|step| step.structural);
    let worth_it = score == CONCLUSIVE || score >= plainness(data) + MIN_GAIN || structural_only;

    let steps = if worth_it && !steps.is_empty() {
        steps
    } else {
        unwrap_structural(data, tags, depth_budget)
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

/// Serialises a Peel (steps + final result) into the JSON shape the worker expects.
/// Does not re-run attacks — used when the worker has already combined layers.
pub fn json_from_peel(peel: &Peel) -> String {
    use crate::json::{push_field, push_number, push_string};

    let mut out = String::from("{");

    push_number(&mut out, "depth", peel.steps.len());
    out.push(',');
    push_string(&mut out, "score");
    out.push_str(&format!(":{:.3}", peel.score));
    out.push(',');
    push_field(&mut out, "result", &crate::json::latin1(&peel.result));
    out.push(',');

    push_string(&mut out, "steps");
    out.push_str(":[");
    for (i, step) in peel.steps.iter().enumerate() {
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

    // Empty/null placeholders for attack fields — the worker fills these
    // after the final pass on the exact tail bytes.
    push_string(&mut out, "xor");
    out.push_str(":[],");
    push_string(&mut out, "vigenere");
    out.push_str(":null,");
    push_string(&mut out, "affine");
    out.push_str(":null,");
    push_string(&mut out, "hill");
    out.push_str(":null,");
    push_string(&mut out, "transposition");
    out.push_str(":null,");
    push_string(&mut out, "substitution");
    out.push_str(":null,");
    push_string(&mut out, "derivedKeys");
    out.push_str(":[],");
    push_string(&mut out, "dictionary");
    out.push_str(":null,");
    push_string(&mut out, "shortlist");
    out.push_str(":[],");
    push_string(&mut out, "frequency");
    out.push(':');
    out.push_str(&frequency::json(&peel.result));
    out.push(',');
    push_string(&mut out, "hash");
    out.push_str(":null}");
    out
}

/// Peels layer after layer until nothing improves, with no configured tags.
pub fn peel(data: &[u8]) -> Peel {
    peel_with(data, &[])
}

/// Everything Mantis makes of a pasted string.
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    pub peel: Peel,
    /// XOR run against whatever the peel ended with.
    pub xor: xor::Recovery,
    /// Set when the string is a digest rather than something to unwrap.
    pub hash: Option<hashes::Identified>,
    /// Set when the text turned out to be Vigenère.
    pub vigenere: Option<vigenere::Candidate>,
    /// Set when the text turned out to be affine, which includes Caesar.
    pub affine: Option<affine::Candidate>,
    /// Set when the text turned out to be a 2x2 Hill cipher.
    pub hill: Option<hill::Candidate>,
    /// Set when the letters were the right ones in the wrong order.
    pub transposition: Option<transposition::Candidate>,
    /// Set when the alphabet was replaced wholesale.
    pub substitution: Option<substitution::Candidate>,
    /// Set when a key from the wordlist read the text.
    pub dictionary: Option<keyed::Attempt>,
    /// Keys worked out of this text, one per assumed key length, best first.
    pub derived: Vec<vigenere::Derived>,
    /// Every rotation laid out, best first.
    ///
    /// Only filled when nothing else read the text. A great many answers are
    /// not English — a token, a key, a flag with no marker — and against those
    /// every scorer here is blind rather than wrong. Twenty-five letter
    /// rotations and thirty-five wider ones are few enough to hand over whole.
    pub shortlist: Vec<shortlist::Reading>,
}

/// Peels the encodings, then attacks what is left with XOR.
///
/// In that order, because that is the order challenges are built in. Bytes get
/// XORed and the result is unreadable, so it gets hex or base64 wrapped to
/// survive being pasted around. Unwrapping first is what makes the cipher
/// visible at all.
pub fn read_for_tags(data: &[u8], tags: &[String]) -> Reading {
    let nothing = |peel: Peel| Reading {
        peel,
        xor: xor::Recovery::default(),
        hash: None,
        vigenere: None,
        affine: None,
        hill: None,
        transposition: None,
        substitution: None,
        dictionary: None,
        derived: Vec::new(),
        shortlist: Vec::new(),
    };

    // Asked first. A hash is not a wrapper, and nothing below should try to
    // open it or attack it.
    if let Some(hash) = hashes::identify(data) {
        return Reading {
            hash: Some(hash),
            ..nothing(Peel {
                steps: Vec::new(),
                result: data.to_vec(),
                score: plainness(data),
            })
        };
    }

    let peel = peel_with(data, tags);
    let inner = if peel.steps.is_empty() {
        data
    } else {
        &peel.result
    };

    // Already readable, so there is nothing left to break.
    //
    // A flag shape only counts as an answer when a peel produced it. Every
    // cipher here leaves punctuation alone, so the braces of `flag{...}` come
    // through enciphering untouched: `zobm{ojfop_nbruq}` is flag-shaped and is
    // pure ciphertext. Taken as conclusive on text nothing was peeled off, that
    // shape stops the attacks before they start, on exactly the input most
    // likely to be an enciphered flag.
    let produced = !peel.steps.is_empty();
    if (produced && conclusive(inner, tags).is_some()) || plainness(inner) >= 0.5 {
        return nothing(peel);
    }

    let xor = xor::recover(inner, tags);

    // Vigenère only ever produces letters, so a run of bytes that is not
    // mostly letters was never enciphered with it.
    let vigenere = vigenere::solve(inner, tags);

    // Each of these answers on its own evidence, against a bar measured in
    // `tests::probe_bars`, rather than on whether another attack came up empty.
    let affine = affine::solve(inner);
    let hill = hill::solve(inner);
    let transposition = transposition::solve(inner);

    // Affine is a substitution with a rule to it, so a text this reads will also
    // solve as a free-form substitution. Both answers are right and only one is
    // worth showing: the smaller key is the better explanation.
    let substitution = affine
        .is_none()
        .then(|| substitution::solve(inner))
        .flatten();

    // Last resort, and only a resort. Everything above reports a conclusion; if
    // none of them reached one, the honest thing is to stop pretending and hand
    // over the readings themselves.
    let settled = xor.found()
        || vigenere.is_some()
        || affine.is_some()
        || hill.is_some()
        || transposition.is_some()
        || substitution.is_some();

    // Rotated from whichever form is still text. A peel can take a wrong turn
    // and leave bytes behind, and rotating bytes asks a question with no answer
    // in it; the string that came in is the better starting point then.
    let readable = |run: &[u8]| {
        !run.is_empty()
            && run.iter().filter(|&&b| printable(b)).count() as f32 / run.len() as f32 >= 0.9
    };

    // A short wordlist, tried only when nothing was recovered from the text
    // itself. Guessing before the evidence has been exhausted is how a tool
    // starts preferring a lucky guess to a real recovery.
    let dictionary = if settled {
        None
    } else {
        keyed::dictionary(inner)
    };

    let settled = settled || dictionary.is_some();

    // The working, shown whether or not an attack landed above. Text that
    // already reads never gets this far, which is right: forty ways of
    // rearranging a readable sentence is not evidence, it is clutter.
    let derived = vigenere::derive(inner, tags);

    let shortlist = if settled {
        Vec::new()
    } else if readable(inner) {
        shortlist::every(inner)
    } else {
        shortlist::every(data)
    };

    Reading {
        peel,
        xor,
        hash: None,
        vigenere,
        affine,
        hill,
        transposition,
        substitution,
        dictionary,
        derived,
        shortlist,
    }
}

/// Reads a string the way Mantis would by default, with no configured tags.
pub fn read(data: &[u8]) -> Reading {
    read_for_tags(data, &[])
}

pub fn json(data: &[u8]) -> String {
    json_for_tags(data, &[])
}

/// The peel, attacks, and working, for a caller that has configured flag tags.
pub fn json_for_tags(data: &[u8], tags: &[String]) -> String {
    use crate::json::{push_field, push_number, push_string};

    let reading = read_for_tags(data, tags);
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

    push_string(&mut out, "vigenere");
    match &reading.vigenere {
        Some(found) => {
            out.push_str(":{");
            push_field(&mut out, "key", &crate::json::latin1(&found.key));
            out.push(',');
            push_string(&mut out, "score");
            out.push_str(&format!(":{:.3}", found.score));
            out.push(',');
            push_field(
                &mut out,
                "plaintext",
                &crate::json::latin1(&found.plaintext),
            );
            out.push('}');
        }
        None => out.push_str(":null"),
    }
    out.push(',');

    push_string(&mut out, "affine");
    match &reading.affine {
        Some(found) => {
            out.push_str(":{");
            push_number(&mut out, "a", found.a as usize);
            out.push(',');
            push_number(&mut out, "b", found.b as usize);
            out.push(',');
            push_string(&mut out, "score");
            out.push_str(&format!(":{:.3}", found.score));
            out.push(',');
            push_field(
                &mut out,
                "plaintext",
                &crate::json::latin1(&found.plaintext),
            );
            out.push('}');
        }
        None => out.push_str(":null"),
    }
    out.push(',');

    push_string(&mut out, "hill");
    match &reading.hill {
        Some(found) => {
            out.push_str(":{");
            push_string(&mut out, "matrix");
            out.push_str(":[");
            for (i, &value) in found.key.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&value.to_string());
            }
            out.push(']');
            out.push(',');
            push_string(&mut out, "score");
            out.push_str(&format!(":{:.3}", found.score));
            out.push(',');
            push_field(
                &mut out,
                "plaintext",
                &crate::json::latin1(&found.plaintext),
            );
            out.push('}');
        }
        None => out.push_str(":null"),
    }
    out.push(',');

    push_string(&mut out, "transposition");
    match &reading.transposition {
        Some(found) => {
            out.push_str(":{");
            match &found.shape {
                transposition::Shape::RailFence { rails } => {
                    push_field(&mut out, "kind", "rail fence");
                    out.push(',');
                    push_number(&mut out, "rails", *rails);
                }
                transposition::Shape::Columnar { order } => {
                    push_field(&mut out, "kind", "columnar");
                    out.push(',');
                    push_number(&mut out, "width", order.len());
                    out.push(',');
                    push_string(&mut out, "order");
                    out.push_str(":[");
                    for (i, column) in order.iter().enumerate() {
                        if i > 0 {
                            out.push(',');
                        }
                        out.push_str(&column.to_string());
                    }
                    out.push(']');
                }
            }
            out.push(',');
            push_string(&mut out, "score");
            out.push_str(&format!(":{:.3}", found.score));
            out.push(',');
            push_field(
                &mut out,
                "plaintext",
                &crate::json::latin1(&found.plaintext),
            );
            out.push('}');
        }
        None => out.push_str(":null"),
    }
    out.push(',');

    push_string(&mut out, "substitution");
    match &reading.substitution {
        Some(found) => {
            out.push_str(":{");
            push_field(&mut out, "key", &crate::json::latin1(&found.key));
            out.push(',');
            push_string(&mut out, "score");
            out.push_str(&format!(":{:.3}", found.score));
            out.push(',');
            push_field(
                &mut out,
                "plaintext",
                &crate::json::latin1(&found.plaintext),
            );
            out.push('}');
        }
        None => out.push_str(":null"),
    }
    out.push(',');

    push_string(&mut out, "derivedKeys");
    out.push(':');
    out.push_str(&vigenere::derived_json(&reading.derived));
    out.push(',');

    push_string(&mut out, "dictionary");
    match &reading.dictionary {
        Some(found) => {
            out.push(':');
            out.push_str(keyed::json(core::slice::from_ref(found)).trim_matches(['[', ']']));
        }
        None => out.push_str(":null"),
    }
    out.push(',');

    push_string(&mut out, "shortlist");
    out.push(':');
    out.push_str(&shortlist::json(&reading.shortlist));
    out.push(',');

    push_string(&mut out, "frequency");
    out.push(':');
    out.push_str(&frequency::json(data));
    out.push(',');

    push_string(&mut out, "hash");
    match &reading.hash {
        Some(_) => {
            out.push(':');
            out.push_str(&hashes::json(data));
        }
        None => out.push_str(":null"),
    }
    out.push(',');

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
