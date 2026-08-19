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
