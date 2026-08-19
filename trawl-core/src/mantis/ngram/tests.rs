use super::*;

const PROSE: &[u8] = b"the treasure is buried under the old oak tree at the north end of the field";

#[test]
fn folds_to_letters_only() {
    assert_eq!(letters(b"Ab3 c-D!"), b"ABCD");
}

#[test]
fn too_short_to_judge() {
    assert_eq!(weight(b"AB"), 0);
    assert_eq!(fitness(b"ab"), 0.0);
    assert_eq!(fitness(b""), 0.0);
}

#[test]
fn common_trigrams_outweigh_impossible_ones() {
    assert!(weight(b"THE") > weight(b"QKZ"));
    assert!(weight(b"ING") > weight(b"JXV"));
}

#[test]
fn prose_beats_its_own_letters_reversed() {
    let forward = letters(PROSE);
    let mut backward = forward.clone();
    backward.reverse();

    // Same letters, same length, same frequencies. Only the order differs, which
    // is the whole reason this table exists.
    assert!(weight(&forward) > weight(&backward));
}

#[test]
fn prose_beats_a_wrong_caesar_shift() {
    let shifted: Vec<u8> = letters(PROSE)
        .iter()
        .map(|b| (b - b'A' + 7) % 26 + b'A')
        .collect();

    assert!(weight(&letters(PROSE)) > weight(&shifted));
}

#[test]
fn fitness_separates_prose_from_noise() {
    let prose = fitness(PROSE);
    let noise = fitness(b"qxzjvkwqxzjvkwqxzjvkwqxzjvkwqxzjvkw");

    assert!(prose > 0.5, "prose scored {prose}, expected over 0.5");
    assert!(noise < 0.2, "noise scored {noise}, expected under 0.2");
}

#[test]
fn thin_evidence_is_discounted() {
    // A dozen letters can hit a common trigram by luck. Whatever it scores, it
    // must not score like a paragraph.
    let lucky = fitness(b"thexingxthex");
    let paragraph = fitness(PROSE);

    assert!(lucky < paragraph, "{lucky} should not rival {paragraph}");
}

#[test]
fn fitness_stays_in_range() {
    for sample in [
        PROSE,
        b"THETHETHETHETHETHETHE",
        b"aaaaaaaaaaaaaaaaaaaaa",
        b"!!!!!!!",
    ] {
        let score = fitness(sample);
        assert!((0.0..=1.0).contains(&score), "{score} out of range");
    }
}

#[test]
fn table_is_the_size_it_claims() {
    assert_eq!(TABLE.len(), CELLS);
    const { assert!(ENGLISH > NOISE, "English must outscore uniform noise") };
}

/// Where [`EVIDENCE`] comes from.
///
/// Ignored because it asserts nothing. Run it with
/// `cargo test --release probe_noise_band -- --ignored --nocapture` to redraw
/// the table in that constant's doc comment rather than trusting it.
#[test]
#[ignore]
fn probe_noise_band() {
    // Letters drawn with English's own frequencies but in no order, which is
    // the null this table is scored against and the hardest case for it: a
    // transposition cipher produces exactly this.
    let mut ladder = [0f32; 26];
    let mut running = 0.0;
    for (i, share) in ENGLISH_SHARE.iter().enumerate() {
        running += share;
        ladder[i] = running;
    }

    let mut state = 0x243f6a8885a308d3u64;
    let mut next = || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545f4914f6cdd1d)
    };

    println!("letters   mean   worst of 300");
    for length in [8usize, 12, 20, 30, 45, 60, 90, 140] {
        let mut sum = 0f32;
        let mut worst = 0f32;
        for _ in 0..300 {
            let sample: Vec<u8> = (0..length)
                .map(|_| {
                    let pick = (next() % 100_000) as f32 / 100_000.0;
                    let at = ladder.iter().position(|&edge| pick < edge).unwrap_or(25);
                    b'A' + at as u8
                })
                .collect();
            let f = fitness(&sample);
            sum += f;
            worst = worst.max(f);
        }
        println!("{length:7}   {:.3}   {worst:.3}", sum / 300.0);
    }
}

/// English letter shares as fractions, for drawing letters that have English's
/// composition and none of its order.
const ENGLISH_SHARE: [f32; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
    0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
    0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
];
