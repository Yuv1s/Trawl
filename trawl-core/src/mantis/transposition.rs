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
//! work is a factorial in the width rather than a handful of tries — up to
//! eight columns, past which every arrangement is too many and the order is
//! built up one column at a time instead. [`build_wide_order`] covers how.

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

/// Widest column grid tried exhaustively.
///
/// The cost is the factorial: eight columns is 40,320 arrangements, nine is
/// 362,880. Past here [`build_wide_order`] takes over instead of trying more
/// of them.
const MAX_WIDTH: usize = 8;

/// Widest column grid the constructive search reaches for at all.
///
/// [`MIN_ROWS`] already turns away a width whose columns are too short to
/// judge, which does most of the real work of keeping this bounded. This
/// caps it besides, since a realistic keyword has usually run out well
/// before here regardless of how much text there is to spend on it.
const WIDE_MAX: usize = 20;

/// Trigram weight of the row directly under `prev2`, `prev1` and `next`
/// placed side by side, summed over every row.
///
/// This is what a natural-order neighbour is judged on: two grid columns
/// that truly sit next to each other read as ordinary trigrams row by row,
/// and two that do not read as noise almost everywhere, the same separation
/// [`super::substitution`] climbs on. Rows with a non-letter anywhere in the
/// three contribute nothing, since the trigram table has nothing to say
/// about them either way.
fn continuation_weight(chunks: &[&[u8]], prev2: usize, prev1: usize, next: usize) -> u32 {
    let (a, b, c) = (chunks[prev2], chunks[prev1], chunks[next]);

    (0..a.len())
        .map(|row| {
            let (a, b, c) = (a[row], b[row], c[row]);
            if !(a.is_ascii_alphabetic() && b.is_ascii_alphabetic() && c.is_ascii_alphabetic()) {
                return 0;
            }

            let index = |byte: u8| (byte.to_ascii_uppercase() - b'A') as usize;
            ngram::cell((index(a) * 26 + index(b)) * 26 + index(c))
        })
        .sum()
}

/// How many partial arrangements [`build_wide_order`] carries from one step
/// to the next.
///
/// A plain greedy build, keeping only the single best choice at every step,
/// has no way back from one wrong pick: once a column has gone in on weak
/// evidence, every step after it is scored against a false neighbour and
/// compounds the mistake, and this cipher gives that away often enough on a
/// realistic message that a single path is not enough — measured directly in
/// `tests::probes_wide_columnar_recovery`. Carrying more than one arrangement
/// forward is what gives a stronger but later-arriving choice somewhere to
/// land instead of being shut out by an early guess.
const BEAM_WIDTH: usize = 200;

/// Fewest rows a column needs before the constructive search is worth
/// running on it at all.
///
/// Measured, not guessed, in `tests::measures_hit_rate_by_width`: at 113
/// rows every one of fifteen shuffled orders came back exact, at 85 rows
/// none of them cleared [`MIN_SCORE`] at all, and the rows in between were a
/// coin flip rather than a rule. A hundred sits on the near side of where
/// this search stops being worth the compute, the same way [`super::substitution`]
/// will not climb a key from under 150 letters: below the floor, an
/// arrangement that happens to clear the bar would be luck wearing the shape
/// of evidence.
const MIN_ROWS: usize = 100;

/// Builds a reading order for a grid `width` columns wide by finding which
/// chunk of ciphertext holds each grid column in turn, rather than trying
/// every arrangement of them.
///
/// Only reaches for messages whose length divides evenly by `width`, since
/// then every column holds exactly the same number of rows and the raw
/// ciphertext splits into `width` equal chunks without needing to know the
/// order first — a shorter or longer column changes where its neighbours'
/// chunks start in a way that depends on the very order being searched for,
/// and this does not chase that in its first pass.
///
/// Every ordered triple of chunks is scored as the trigrams its own three
/// rows form and tried as the first three grid columns, since with nothing
/// placed yet a pair has no third row to judge a trigram from at all. The
/// [`BEAM_WIDTH`] best of those carry forward; at every remaining step, each
/// surviving arrangement is extended by every unplaced chunk, scored by how
/// well it continues the trigrams after the two columns already at that
/// arrangement's end — [`continuation_weight`] is that judgement — and only
/// the best [`BEAM_WIDTH`] extensions survive into the next step. What
/// decides between the finished arrangements at the end is the same
/// plainness score [`solve`] judges everything else on, not the running
/// trigram total that built them: the total is a guide for which branches
/// are worth carrying forward, not the answer.
///
/// Reliability past here still falls off with width even above [`MIN_ROWS`]:
/// the same measurement found every shuffle exact at nine columns and 113
/// rows, and only a fifth of them exact one column wider with ten rows
/// fewer. A width this finds nothing on is not proof of nothing there,
/// only of not enough text to say so — the honest answer [`solve`] gives is
/// silence rather than a guess.
fn build_wide_order(data: &[u8], width: usize) -> Option<Candidate> {
    if width < 3 || !data.len().is_multiple_of(width) {
        return None;
    }

    let chunk_len = data.len() / width;
    if chunk_len < MIN_ROWS {
        return None;
    }

    let chunks: Vec<&[u8]> = data.chunks_exact(chunk_len).collect();

    let mut beam: Vec<(Vec<usize>, u32)> = Vec::new();
    for first in 0..width {
        for second in 0..width {
            if second == first {
                continue;
            }
            for third in 0..width {
                if third == first || third == second {
                    continue;
                }
                let weight = continuation_weight(&chunks, first, second, third);
                beam.push((vec![first, second, third], weight));
            }
        }
    }
    beam.sort_unstable_by_key(|a| std::cmp::Reverse(a.1));
    beam.truncate(BEAM_WIDTH);

    for _ in 3..width {
        let mut next_beam: Vec<(Vec<usize>, u32)> = Vec::new();

        for (placed, score) in &beam {
            let prev2 = placed[placed.len() - 2];
            let prev1 = placed[placed.len() - 1];

            for candidate in 0..width {
                if placed.contains(&candidate) {
                    continue;
                }
                let mut extended = placed.clone();
                extended.push(candidate);
                next_beam.push((extended, score + continuation_weight(&chunks, prev2, prev1, candidate)));
            }
        }

        next_beam.sort_unstable_by_key(|a| std::cmp::Reverse(a.1));
        next_beam.truncate(BEAM_WIDTH);
        beam = next_beam;
    }

    beam.truncate(REFINE_TOP);
    beam.into_iter()
        .map(|(placed, _)| {
            // `placed[column]` is which raw chunk that grid column's data
            // sits in, the inverse of what `columnar_decipher` wants: it
            // reads chunk by chunk and asks which grid column each one
            // belongs to.
            let mut order = vec![0usize; width];
            for (column, &chunk) in placed.iter().enumerate() {
                order[chunk] = column;
            }
            refine(data, order)
        })
        .fold(None::<Candidate>, |best, next| match best {
            Some(current) if current.score >= next.score => Some(current),
            _ => Some(next),
        })
}

/// How many of the beam's surviving arrangements are handed to [`refine`].
///
/// The beam's own running trigram total is a guide, not a verdict, so the
/// arrangement with the strongest total is not always the one closest to
/// correct. Trying a handful of the survivors costs little next to the beam
/// search itself.
const REFINE_TOP: usize = 20;

/// Polishes an arrangement by swapping two grid columns at a time and
/// keeping the swap when the fully deciphered text reads better.
///
/// The beam search built this arrangement from local trigram evidence at each
/// step, which is enough to land close to the right one but not always land
/// on it exactly — the same three-column trigram that favoured a swap of two
/// grid columns has nothing to say about the fourth column two steps later
/// that the swap also disturbed. A full swap climb judges the whole text at
/// once instead, which is what actually matters, and `solve`'s own [`MIN_SCORE`]
/// already asks each of the ciphers here to clear a bar measured on plainness
/// alone, so refining on the same measure keeps every cipher answering to the
/// same standard.
fn refine(data: &[u8], mut order: Vec<usize>) -> Candidate {
    let width = order.len();

    // Trigram fitness rather than the full plainness score while climbing:
    // plainness also tokenises the text on whitespace and allocates a String
    // per word to check it against the common-word list, which a hot loop
    // trying every pair of columns cannot afford to do thousands of times.
    // Trigram fitness is the term that carries most of plainness's own
    // weight in the first place, so it steers the climb the same way at a
    // fraction of the cost; the full score is only computed once, on the
    // arrangement climbing settled on.
    let mut best_score = ngram::fitness(&columnar_decipher(data, &order));

    loop {
        let mut improved = false;

        for a in 0..width {
            for b in (a + 1)..width {
                order.swap(a, b);
                let found = ngram::fitness(&columnar_decipher(data, &order));

                if found > best_score {
                    best_score = found;
                    improved = true;
                } else {
                    order.swap(a, b);
                }
            }
        }

        if !improved {
            return judge(columnar_decipher(data, &order), Shape::Columnar { order });
        }
    }
}

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

/// How readable a wide-columnar hit has to be before the search stops trying
/// still wider grids.
///
/// Comfortably above [`MIN_SCORE`] and below the roughly 0.83 a genuine
/// recovery measures at in `tests::measures_hit_rate_by_width`, so a real hit
/// stops the search without a merely-clears-the-bar near miss doing the same
/// and hiding the width that was actually right.
const CONFIDENT_SCORE: f32 = 0.8;

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

    // A real message has exactly one width, so a strong hit at a narrower
    // grid makes every wider one increasingly unlikely to also be it —
    // continuing to try them is spending [`BEAM_WIDTH`] and [`REFINE_TOP`]
    // worth of search on widths that are, by construction, wrong. Stopping
    // once one is clearly right keeps a genuine hit from paying for every
    // width past it.
    let mut wide_columns = Vec::new();
    for width in (MAX_WIDTH + 1)..=WIDE_MAX.min(data.len() - 1) {
        let Some(found) = build_wide_order(data, width) else {
            continue;
        };
        let confident = found.score >= CONFIDENT_SCORE;
        wide_columns.push(found);
        if confident {
            break;
        }
    }

    rails
        .chain(columns)
        .chain(wide_columns)
        .filter(|found| found.score >= MIN_SCORE && found.score >= before + MIN_GAIN)
        .fold(None::<Candidate>, |best, next| match best {
            Some(current) if current.score >= next.score => Some(current),
            _ => Some(next),
        })
}

#[cfg(test)]
mod tests;
