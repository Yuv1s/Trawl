//! Every reading worth looking at, for when nothing can be decided.
//!
//! The rest of Mantis reports an answer or reports nothing, and reporting
//! nothing is correct far more often than it looks: a wrong answer stated
//! confidently is worse than no answer. But "nothing" is a poor thing to hand
//! someone who can see perfectly well that their text is a rotation of
//! something, and who would recognise the right one in a second.
//!
//! That gap has a shape. Every attack here decides by asking whether the result
//! reads like English, and a great many answers are not English: a token, a key,
//! a flag with no marker on it. Against those the scorer is blind, not wrong.
//! The keyspaces involved are also tiny — twenty-five letter rotations,
//! thirty-five over digits and letters, one Atbash — small enough to lay out in
//! full and let a person finish the job.
//!
//! So this module does not decide. It rotates every way it knows, works out
//! which of the results would go on to decode into something, and puts those
//! first.

use super::{conclusive, encodings, plainness, unwrap_structural};

/// One way of reading the input, and where that reading leads.
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    /// What was done, in the words a person would use: "ROT 13", "base36 +21".
    pub how: String,
    pub text: Vec<u8>,
    /// How much the result reads like ordinary text, nought to one.
    pub score: f32,
    /// What a further peel makes of it, when the shape alone justifies one.
    ///
    /// This is what makes the list worth reading. A rotation is only one layer
    /// of most chains, and the right rotation is usually the one that turns into
    /// clean base64 rather than the one that scores best on its own.
    pub then: Option<Continuation>,
    /// Set when the reading contains a flag shape or a file signature, which is
    /// the one case where no judgement is needed.
    pub found: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Continuation {
    /// The encodings that came off, in order.
    pub through: Vec<String>,
    pub result: Vec<u8>,
    pub score: f32,
}

/// Longest run this will lay out candidates for.
///
/// Rotating a large file every possible way and peeling each one is a great deal
/// of work for a list nobody would scroll. Anything this size is a document, and
/// a document that needed a rotation would have been read by the scorer.
const MAX_INPUT: usize = 4096;

/// Shortest run worth rotating.
///
/// Below this every rotation looks as plausible as every other and the list is
/// noise with a scrollbar.
const MIN_INPUT: usize = 4;

fn judge(how: String, text: Vec<u8>) -> Reading {
    let steps = unwrap_structural(&text, &[]);

    let then = (!steps.is_empty()).then(|| {
        let result = steps.last().map(|s| s.output.clone()).unwrap_or_default();
        Continuation {
            through: steps.iter().map(|s| s.encoding.to_string()).collect(),
            score: plainness(&result),
            result,
        }
    });

    // A flag anywhere in the chain settles it, whether it turned up in the
    // rotation itself or in what the rotation decoded to.
    let found = conclusive(&text, &[]).or_else(|| then.as_ref().and_then(|c| conclusive(&c.result, &[])));

    Reading {
        score: plainness(&text),
        how,
        text,
        then,
        found,
    }
}

/// Share of a run that is ordinary printable ASCII.
///
/// The sharpest thing available when the answer is not English. A real decode of
/// a token comes out entirely printable; a rotation that merely happened to be
/// the right length for base64 comes out as bytes, and the difference is stark
/// where plainness barely moves.
fn printable(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let clean = data
        .iter()
        .filter(|&&b| (0x20..0x7f).contains(&b) || matches!(b, b'\n' | b'\r' | b'\t'))
        .count();

    clean as f32 / data.len() as f32
}

/// What a reading is worth to someone scanning the list.
///
/// A flag settles it outright. Otherwise a reading is worth whatever its best
/// end point offers, its own text or whatever that text decodes to, because
/// either could be the answer.
///
/// Decoding onward is weaker evidence than it looks. Base64 accepts almost any
/// run whose length divides by four, so on a two dozen character input most
/// rotations "decode" and only a few decode into anything. What separates them
/// is what came out, weighed equally on being clean and on reading well, since
/// with a token neither is decisive alone.
fn worth(reading: &Reading) -> f32 {
    if reading.found.is_some() {
        // Braces survive a rotation, so every rotation of a flag still looks
        // flag-shaped. Which one actually reads decides between them.
        return 100.0 + reading.score;
    }

    match &reading.then {
        Some(chain) => reading
            .score
            .max(0.5 * printable(&chain.result) + 0.5 * chain.score),
        None => reading.score,
    }
}

/// Every rotation of the input, best first.
///
/// Deliberately not filtered. The whole point is that the caller could not
/// decide, so trimming the list to what this module finds promising would put
/// the same failed judgement back in the way.
pub fn every(data: &[u8]) -> Vec<Reading> {
    if !(MIN_INPUT..=MAX_INPUT).contains(&data.len()) {
        return Vec::new();
    }

    let mut out = Vec::new();

    for shift in 1..26u8 {
        out.push(judge(format!("ROT {shift}"), encodings::rot_n(data, shift)));
    }

    for shift in 1..36u8 {
        let text = encodings::rot_base36(data, shift);
        // A run with no digits in it rotates identically either way for the
        // shifts that stay inside the letters, and a duplicate helps nobody.
        if out.iter().any(|seen| seen.text == text) {
            continue;
        }
        out.push(judge(format!("base36 +{shift}"), text));
    }

    if let Some(text) = encodings::rot47(data) {
        out.push(judge("ROT47".to_string(), text));
    }

    out.push(judge("Atbash".to_string(), encodings::atbash(data)));

    let mut reversed = data.to_vec();
    reversed.reverse();
    out.push(judge("reversed".to_string(), reversed));

    out.retain(|reading| reading.text != data);
    out.sort_by(|a, b| worth(b).total_cmp(&worth(a)));
    out
}

pub fn json(readings: &[Reading]) -> String {
    use crate::json::{push_field, push_string};

    let mut out = String::from("[");

    for (i, reading) in readings.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('{');
        push_field(&mut out, "how", &reading.how);
        out.push(',');
        push_field(&mut out, "text", &crate::json::latin1(&reading.text));
        out.push(',');
        push_string(&mut out, "score");
        out.push_str(&format!(":{:.3},", reading.score));

        push_string(&mut out, "found");
        match &reading.found {
            Some(why) => {
                out.push(':');
                let mut held = String::new();
                push_string(&mut held, why);
                out.push_str(&held);
            }
            None => out.push_str(":null"),
        }
        out.push(',');

        push_string(&mut out, "then");
        match &reading.then {
            Some(chain) => {
                out.push_str(":{");
                push_string(&mut out, "through");
                out.push_str(":[");
                for (j, step) in chain.through.iter().enumerate() {
                    if j > 0 {
                        out.push(',');
                    }
                    push_string(&mut out, step);
                }
                out.push_str("],");
                push_string(&mut out, "score");
                out.push_str(&format!(":{:.3},", chain.score));
                push_field(&mut out, "result", &crate::json::latin1(&chain.result));
                out.push('}');
            }
            None => out.push_str(":null"),
        }
        out.push('}');
    }

    out.push(']');
    out
}

#[cfg(test)]
mod tests;
