use super::*;

const PROSE: &[u8] =
    b"the treasure is buried under the old oak tree at the north end of the field \
and the map that shows it is folded inside the cover of the green book on the second shelf";

#[test]
fn zigzag_runs_down_and_back() {
    assert_eq!(zigzag(9, 3), vec![0, 1, 2, 1, 0, 1, 2, 1, 0]);
    assert_eq!(zigzag(5, 2), vec![0, 1, 0, 1, 0]);
}

#[test]
fn rail_fence_round_trips() {
    for rails in 2..=8 {
        assert_eq!(
            rail_decipher(&rail_encipher(PROSE, rails), rails),
            PROSE,
            "{rails} rails"
        );
    }
}

#[test]
fn rail_fence_matches_a_worked_example() {
    // WEAREDISCOVEREDFLEEATONCE on three rails is the textbook one.
    assert_eq!(
        rail_encipher(b"WEAREDISCOVEREDFLEEATONCE", 3),
        b"WECRLTEERDSOEEFEAOCAIVDEN".to_vec()
    );
}

#[test]
fn columnar_round_trips_on_a_ragged_grid() {
    // 84 letters over 5 columns leaves a partial last row, which is where an
    // off-by-one lives if there is one.
    for width in 2..=8 {
        let order: Vec<usize> = (0..width).rev().collect();
        assert_eq!(
            columnar_decipher(&columnar_encipher(PROSE, &order), &order),
            PROSE,
            "width {width}"
        );
    }
}

#[test]
fn permutations_are_complete_and_distinct() {
    for width in 2..=6 {
        let all = permutations(width);
        let expected: usize = (1..=width).product();

        assert_eq!(all.len(), expected, "width {width}");

        let mut sorted = all.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), expected, "width {width} had repeats");
    }
}

#[test]
fn solves_a_rail_fence() {
    let found = solve(&rail_encipher(PROSE, 4)).expect("nothing came back");

    assert_eq!(found.shape, Shape::RailFence { rails: 4 });
    assert_eq!(found.plaintext, PROSE);
}

#[test]
fn solves_a_columnar() {
    let order = vec![2, 0, 4, 1, 3];
    let found = solve(&columnar_encipher(PROSE, &order)).expect("nothing came back");

    assert_eq!(found.plaintext, PROSE);
    assert_eq!(found.shape, Shape::Columnar { order });
}

#[test]
fn declines_text_that_was_never_transposed() {
    // Rearranging English gives back something that is not English, so the best
    // arrangement of a random string should still fail to read.
    let mut state = 0x9e3779b97f4a7c15u64;
    let noise: Vec<u8> = (0..200)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            b'a' + (state.wrapping_mul(0x2545f4914f6cdd1d) % 26) as u8
        })
        .collect();

    assert_eq!(solve(&noise), None);
}

#[test]
fn declines_text_too_short_to_judge() {
    assert_eq!(solve(b"short"), None);
    assert_eq!(solve(b""), None);
}

#[test]
fn leaves_plain_english_alone() {
    // Already readable. Any rearrangement is a step backwards, and reporting one
    // would be worse than reporting nothing.
    let found = solve(PROSE);

    assert!(
        found.is_none_or(|c| c.plaintext == PROSE),
        "rearranged text that already read"
    );
}


/// A longer passage than `PROSE`, for the wide-columnar tests: a grid twelve
/// or more columns wide needs proportionally more rows of evidence than the
/// eight-column exhaustive search ever had to work with.
const AMPLE_PROSE: &[u8] = b"the museum keeps its oldest maps in a locked room beneath the reading hall, \
where the air is kept dry and the light is kept low. visitors are welcome on the first thursday of \
every month, though the archivist asks that nobody bring a pen. the quiet is the point, she says, \
because a map only gives up its detail to somebody willing to sit with it for an hour. and yet the \
maps themselves are unremarkable, drawn in plain ink on paper that has gone soft with handling, \
which is exactly why nobody has thought to steal one. every so often a student asks why the museum \
bothers keeping so many nearly identical charts of the same stretch of coastline, and the answer is \
always the same: each one disagrees with the others in some small and telling way, and the disagreement \
is the whole point of keeping them. a chart that matches its neighbour exactly has nothing left to \
teach anyone, while one that drifts a little at the edges is still quietly recording an argument \
someone once had about where the water actually was.";

/// `AMPLE_PROSE`, padded with `x` to a clean multiple of `width`.
///
/// [`build_wide_order`] only ever reaches for a message whose length divides
/// evenly by the width being tried — see its own doc comment for why — so a
/// fixture that skips this padding silently tests nothing at all: every call
/// bails out on the length check before the search runs.
fn padded_for(width: usize) -> Vec<u8> {
    let mut padded = AMPLE_PROSE.to_vec();
    while !padded.len().is_multiple_of(width) {
        padded.push(b'x');
    }
    padded
}

/// Deterministic shuffle for building test fixtures, independent of the
/// solver's own seeding so a test failure can't be masked by a lucky draw.
fn shuffled_order(width: usize, seed: u64) -> Vec<usize> {
    let mut order: Vec<usize> = (0..width).collect();
    let mut state = 0x2545f4914f6cdd1du64 ^ seed;
    for i in (1..width).rev() {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let j = (state.wrapping_mul(0x2545f4914f6cdd1d) % (i as u64 + 1)) as usize;
        order.swap(i, j);
    }
    order
}

#[test]
fn finds_a_wide_columnar_order_end_to_end() {
    let width = 9;
    let order = shuffled_order(width, width as u64 * 7 + 1);
    let cipher = columnar_encipher(&padded_for(width), &order);

    let found = solve(&cipher).expect("nothing came back past the exhaustive width");
    assert_eq!(found.shape, Shape::Columnar { order });
}

#[test]
fn wide_search_declines_a_width_that_does_not_divide_evenly() {
    let data = b"this message is not a clean multiple of nine letters long";
    assert_ne!(data.len() % 9, 0, "fixture needs to not divide evenly");
    assert_eq!(build_wide_order(data, 9), None);
}

#[test]
fn wide_search_declines_grids_narrower_than_three() {
    assert_eq!(build_wide_order(b"aaaaaaaaaa", 2), None);
    assert_eq!(build_wide_order(b"aaaaaaaaaa", 1), None);
}

/// Why a plain greedy build is not what runs past the exhaustive width: run
/// with `-- --ignored --nocapture` to print it again.
///
/// Decrypts a real wide-columnar ciphertext under grids that agree with the
/// true order everywhere but a handful of swaps, the same measurement
/// `super::playfair::tests::measures_the_landscape` runs for its own cipher.
/// Unlike Playfair's, this landscape has real slope in it — score keeps
/// falling as the arrangement gets less correct rather than collapsing to
/// noise after two swaps — which is what makes [`refine`]'s swap climb worth
/// running at all once [`build_wide_order`]'s beam search has landed close.
#[test]
#[ignore]
fn measures_the_landscape() {
    let width = 12;
    let order = shuffled_order(width, width as u64);
    let cipher = columnar_encipher(&padded_for(width), &order);

    let mut rng_state = 0x9e3779b97f4a7c15u64;
    for swaps in [0usize, 1, 2, 3, 5, 8, 12] {
        let mut near = order.clone();
        for _ in 0..swaps {
            rng_state ^= rng_state >> 12;
            rng_state ^= rng_state << 25;
            rng_state ^= rng_state >> 27;
            let scrambled = rng_state.wrapping_mul(0x2545f4914f6cdd1d);
            let a = (scrambled % width as u64) as usize;
            let b = ((scrambled >> 32) % width as u64) as usize;
            near.swap(a, b);
        }
        println!("{swaps} swaps from the order: {:.3}", plainness(&columnar_decipher(&cipher, &near)));
    }
}

/// How often the wide search actually lands on the exact order, across a
/// spread of widths and shuffles: run with `-- --ignored --nocapture` to
/// print it again. This is what [`MIN_ROWS`]'s own doc comment cites.
///
/// Widths this size sometimes settle for a reading that is close rather than
/// exact — readable by eye, short of `MIN_SCORE` — which is why they report
/// nothing rather than a wrong answer: nobody has vouched for a guess here
/// the way a supplied key lets [`super::keyed`] show one unjudged.
#[test]
#[ignore]
fn measures_hit_rate_by_width() {
    const SEEDS: u64 = 8;

    for width in [9usize, 10, 11, 12] {
        let mut hits = 0;
        let mut cleared_bar = 0;
        for seed in 0..SEEDS {
            let order = shuffled_order(width, seed);
            let cipher = columnar_encipher(&padded_for(width), &order);
            if let Some(found) = solve(&cipher) {
                cleared_bar += 1;
                if found.shape == (Shape::Columnar { order }) {
                    hits += 1;
                }
            }
        }
        println!("width {width}: {hits}/{SEEDS} exact, {cleared_bar}/{SEEDS} cleared the bar at all");
    }
}
