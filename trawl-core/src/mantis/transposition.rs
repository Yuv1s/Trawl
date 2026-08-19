//! Rail fence and columnar transposition, which move letters without changing
//! them.
//!
//! Every other cipher in Mantis substitutes: the letters that come out are not
//! the letters that went in, so counting them says something. Transposition
//! keeps every letter and only rearranges the order, which means letter
//! frequency is *exactly* English before and after and says nothing at all. A
//! frequency profile that matches English perfectly while the text reads as
//! gibberish is itself the tell.
//!
//! What is left to score with is order, which is what the trigram census
//! measures. Both ciphers here have few enough arrangements to try all of them
//! and let the reading decide.
//!
//! Rail fence writes in a zigzag down and up a fixed number of rails and reads
//! off a rail at a time. Only the rail count is secret, and there are not many
//! sensible ones.
//!
//! Columnar writes in rows of fixed width and reads off a column at a time, in
//! an order set by a keyword. Both the width and the order are secret, so the
//! work is a factorial in the width rather than a handful of tries.

use super::{ngram, plainness};

/// Which rail each position of a zigzag falls on.
fn zigzag(length: usize, rails: usize) -> Vec<usize> {
    let mut rail = 0usize;
    let mut down = true;

    (0..length)
        .map(|_| {
            let here = rail;

            if rails > 1 {
                if down {
                    rail += 1;
                    if rail == rails - 1 {
                        down = false;
                    }
                } else {
                    rail -= 1;
                    if rail == 0 {
                        down = true;
                    }
                }
            }

            here
        })
        .collect()
}

pub fn rail_encipher(data: &[u8], rails: usize) -> Vec<u8> {
    let pattern = zigzag(data.len(), rails);
    let mut out = Vec::with_capacity(data.len());

    for rail in 0..rails {
        for (&byte, &at) in data.iter().zip(&pattern) {
            if at == rail {
                out.push(byte);
            }
        }
    }

    out
}

pub fn rail_decipher(data: &[u8], rails: usize) -> Vec<u8> {
    let pattern = zigzag(data.len(), rails);

    // How much of the ciphertext belongs to each rail, and so where each rail's
    // run begins.
    let mut at = 0usize;
    let mut cursor: Vec<usize> = (0..rails)
        .map(|rail| {
            let starts = at;
            at += pattern.iter().filter(|&&r| r == rail).count();
            starts
        })
        .collect();

    pattern
        .iter()
        .map(|&rail| {
            let byte = data[cursor[rail]];
            cursor[rail] += 1;
            byte
        })
        .collect()
}

/// Column lengths for a grid filled row-wise, which is what makes a partial
/// last row work.
///
/// With 23 letters in 5 columns the last row is short, so the first three
/// columns hold five letters and the last two hold four. That is decided by
/// where a column sits in the grid, not by when the key reads it.
fn column_lengths(length: usize, width: usize) -> Vec<usize> {
    let short = length / width;
    let long = length % width;

    (0..width)
        .map(|column| if column < long { short + 1 } else { short })
        .collect()
}

/// Reads columns back in the given order, where `order[n]` is the grid column
/// the key reads nth.
pub fn columnar_decipher(data: &[u8], order: &[usize]) -> Vec<u8> {
    let width = order.len();
    let lengths = column_lengths(data.len(), width);

    let mut columns = vec![Vec::new(); width];
    let mut cursor = 0usize;

    for &column in order {
        let take = lengths[column];
        columns[column] = data[cursor..cursor + take].to_vec();
        cursor += take;
    }

    let rows = data.len().div_ceil(width);
    let mut out = Vec::with_capacity(data.len());

    for row in 0..rows {
        for (column, held) in columns.iter().enumerate() {
            if row < lengths[column] {
                out.push(held[row]);
            }
        }
    }

    out
}

pub fn columnar_encipher(data: &[u8], order: &[usize]) -> Vec<u8> {
    let width = order.len();
    let lengths = column_lengths(data.len(), width);

    let mut columns: Vec<Vec<u8>> = vec![Vec::new(); width];
    for (index, &byte) in data.iter().enumerate() {
        columns[index % width].push(byte);
    }

    debug_assert!(columns.iter().zip(&lengths).all(|(c, &n)| c.len() == n));

    order
        .iter()
        .flat_map(|&column| columns[column].clone())
        .collect()
}

/// Every arrangement of `width` columns, in lexicographic order.
fn permutations(width: usize) -> Vec<Vec<usize>> {
    let mut order: Vec<usize> = (0..width).collect();
    let mut all = vec![order.clone()];

    // Plain next-permutation, which avoids holding a recursion stack and stops
    // exactly when the last arrangement has been seen.
    loop {
        let Some(pivot) = (0..width - 1).rev().find(|&i| order[i] < order[i + 1]) else {
            return all;
        };
        let next = (pivot + 1..width)
            .rev()
            .find(|&i| order[i] > order[pivot])
            .unwrap();

        order.swap(pivot, next);
        order[pivot + 1..].reverse();
        all.push(order.clone());
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Shape {
    /// The number of rails the zigzag ran across.
    RailFence { rails: usize },
    /// The grid width, and the order the columns were read in.
    Columnar { order: Vec<usize> },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub shape: Shape,
    pub plaintext: Vec<u8>,
    pub score: f32,
}

/// Most rails worth trying.
///
/// Past this the zigzag is longer than the message and every rail holds a letter
/// or two, at which point the cipher stops rearranging much and every rail count
/// deciphers to something similar.
const MAX_RAILS: usize = 12;

/// Widest column grid worth trying.
///
/// The cost is the factorial: eight columns is 40,320 arrangements, nine is
/// 362,880. Eight covers the keyword lengths these are set with and keeps a
/// solve inside a frame.
const MAX_WIDTH: usize = 8;

/// How readable a rearrangement has to be before it is reported.
///
/// Measured rather than chosen. `mantis::tests::probe_bars` runs every solver
/// over every cipher with the bars taken off. This one reads a real rail fence
/// or columnar at 0.816 and tops out at 0.343 on anything else:
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
const MIN_SCORE: f32 = 0.7;

/// Shortest text worth attempting.
///
/// Below a couple of rows there is not enough text for the order to be evidence
/// of anything.
const MIN_LETTERS: usize = 24;

/// How much more readable a rearrangement has to be than the text it came from.
///
/// No arrangement here is the identity, so a solver that only asks "does this
/// read?" will happily shuffle text that already read and hand back the shuffle.
/// The rest of Mantis makes every peel justify itself against its own input, and
/// this is that rule: a rearrangement is evidence of a cipher only when the text
/// was not readable to begin with.
const MIN_GAIN: f32 = 0.1;

fn judge(plaintext: Vec<u8>, shape: Shape) -> Candidate {
    let score = plainness(&plaintext);
    Candidate {
        shape,
        plaintext,
        score,
    }
}

/// Tries every rail count and every column arrangement, and reports the best
/// reading if any of them reads.
pub fn solve(data: &[u8]) -> Option<Candidate> {
    if ngram::letters(data).len() < MIN_LETTERS {
        return None;
    }

    let before = plainness(data);

    let rails = (2..=MAX_RAILS.min(data.len() - 1))
        .map(|rails| judge(rail_decipher(data, rails), Shape::RailFence { rails }));

    let columns = (2..=MAX_WIDTH.min(data.len() - 1)).flat_map(|width| {
        permutations(width)
            .into_iter()
            .map(|order| judge(columnar_decipher(data, &order), Shape::Columnar { order }))
    });

    rails
        .chain(columns)
        .filter(|found| found.score >= MIN_SCORE && found.score >= before + MIN_GAIN)
        .fold(None::<Candidate>, |best, next| match best {
            Some(current) if current.score >= next.score => Some(current),
            _ => Some(next),
        })
}

#[cfg(test)]
mod tests;
