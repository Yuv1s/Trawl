use super::*;

/// Long enough to solve and varied enough to be worth solving. Substitution
/// needs real text: a sentence or two is not evidence, it is a coincidence
/// waiting to happen.
const PROSE: &[u8] =
    b"the museum keeps its oldest maps in a locked room beneath the reading hall, \
where the air is kept dry and the light is kept low. visitors are welcome on the first thursday of \
every month, though the archivist asks that nobody bring a pen. the quiet is the point, she says, \
because a map only gives up its detail to somebody willing to sit with it for an hour.";

/// An arbitrary scramble of the alphabet, as letter numbers.
const KEY: [u8; 26] = [
    7, 22, 4, 19, 0, 25, 11, 14, 8, 23, 17, 3, 20, 9, 15, 5, 24, 1, 12, 18, 6, 21, 16, 2, 13, 10,
];

/// Letters with English's composition and none of its order.
///
/// The right adversary for this module. Uniformly random letters are easy to
/// turn down because their letter mix is wrong as well as their order; text
/// that keeps English's letter mix and loses only the order is what a
/// transposition cipher produces, and it is what a substitution solver has to
/// avoid claiming.
fn noise(length: usize, seed: u64) -> Vec<u8> {
    const SHARE: [f32; 26] = [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
        0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
        0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
    ];

    let mut ladder = [0f32; 26];
    let mut running = 0.0;
    for (i, share) in SHARE.iter().enumerate() {
        running += share;
        ladder[i] = running;
    }

    let mut state = 0x243f6a8885a308d3u64 ^ seed.wrapping_mul(0x9e3779b97f4a7c15);

    (0..length)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let pick = (state.wrapping_mul(0x2545f4914f6cdd1d) % 100_000) as f32 / 100_000.0;
            b'a' + ladder.iter().position(|&edge| pick < edge).unwrap_or(25) as u8
        })
        .collect()
}

#[test]
fn enciphering_round_trips() {
    assert_eq!(decipher(&encipher(PROSE, &KEY), &KEY), PROSE);
}

#[test]
fn keeps_case_and_punctuation() {
    let out = encipher(b"Hello, World!", &KEY);

    assert_eq!(out[5], b',');
    assert_eq!(out[12], b'!');
    assert!(out[0].is_ascii_uppercase());
    assert!(out[1].is_ascii_lowercase());
}

#[test]
fn recovers_the_plaintext() {
    let found = solve(&encipher(PROSE, &KEY)).expect("nothing came back");

    assert_eq!(
        String::from_utf8_lossy(&found.plaintext),
        String::from_utf8_lossy(PROSE)
    );
    assert!(
        found.score > 0.9,
        "recovered but scored only {}",
        found.score
    );
}

#[test]
fn reports_a_key_that_reproduces_its_own_answer() {
    let cipher = encipher(PROSE, &KEY);
    let found = solve(&cipher).expect("nothing came back");

    let key: [u8; 26] = core::array::from_fn(|i| found.key[i] - b'a');
    assert_eq!(decipher(&cipher, &key), found.plaintext);
}

#[test]
fn declines_text_too_short_to_judge() {
    assert_eq!(solve(b"attack at dawn"), None);
    assert_eq!(solve(b""), None);
}

#[test]
fn declines_random_letters() {
    // The failure that matters. Some key always wins, so a solver without a bar
    // reports a confident reading of nothing at all.
    for seed in 0..8 {
        assert_eq!(solve(&noise(400, seed)), None, "seed {seed} got a reading");
    }
}

#[test]
fn declines_noise_at_the_shortest_length_it_accepts() {
    for seed in 0..8 {
        assert_eq!(solve(&noise(MIN_LETTERS, seed)), None, "seed {seed}");
    }
}

#[test]
fn is_reproducible() {
    let cipher = encipher(PROSE, &KEY);

    assert_eq!(solve(&cipher), solve(&cipher));
}

/// Where [`MIN_LETTERS`] and [`MIN_SCORE`] come from.
///
/// Ignored because it takes seconds and asserts nothing. Run it with
/// `cargo test --release measure_separation -- --ignored --nocapture` to
/// re-derive the table in those doc comments rather than trusting it.
#[test]
#[ignore]
fn measure_separation() {
    fn climbed(text: &[u8]) -> f32 {
        let cipher = indices(text);
        let mut key = by_frequency(&cipher);
        let mut top = climb(&cipher, &mut key);
        let mut best = key;
        let mut rng = Rng::seeded(&cipher);

        for _ in 1..RESTARTS {
            rng.shuffle(&mut key);
            let score = climb(&cipher, &mut key);
            if score > top {
                top = score;
                best = key;
            }
        }

        ngram::fitness(&decipher(text, &best))
    }

    fn prefix(text: &[u8], letters: usize) -> Vec<u8> {
        let mut seen = 0;
        text.iter()
            .take_while(|b| {
                if b.is_ascii_alphabetic() {
                    seen += 1;
                }
                seen <= letters
            })
            .copied()
            .collect()
    }

    println!("letters    noise    prose");
    for length in [100usize, 120, 150, 180] {
        let worst = (0..40)
            .map(|seed| climbed(&noise(length, seed)))
            .fold(0f32, f32::max);
        let prose = climbed(&encipher(&prefix(PROSE, length), &KEY));

        println!("{length:7}    {worst:.3}    {prose:.3}");
    }
}

#[test]
#[ignore]
fn probe_restarts() {
    fn prefix(text: &[u8], letters: usize) -> Vec<u8> {
        let mut seen = 0;
        text.iter()
            .take_while(|b| {
                if b.is_ascii_alphabetic() {
                    seen += 1;
                }
                seen <= letters
            })
            .copied()
            .collect()
    }

    // Recover with a given restart budget, reporting whether it landed exactly.
    fn exact(clean: &[u8], key: &[u8; 26], restarts: usize, salt: u64) -> bool {
        let cipher = indices(&encipher(clean, key));
        let mut work = by_frequency(&cipher);
        let mut top = climb(&cipher, &mut work);
        let mut best = work;
        let mut rng = Rng(0x9e3779b97f4a7c15 ^ salt.wrapping_mul(0x100000001b3) | 1);

        for _ in 1..restarts {
            rng.shuffle(&mut work);
            let score = climb(&cipher, &mut work);
            if score > top {
                top = score;
                best = work;
            }
        }

        decipher(&encipher(clean, key), &best) == clean
    }

    println!("letters   restarts   exact recoveries of 20");
    for length in [150usize, 200, 250, 300] {
        let clean = prefix(PROSE, length);
        for restarts in [25usize, 50, 100, 200] {
            let hits = (0..20u64)
                .filter(|&salt| {
                    let mut key = [0u8; 26];
                    for (i, slot) in key.iter_mut().enumerate() {
                        *slot = i as u8;
                    }
                    Rng(salt.wrapping_mul(0x2545f4914f6cdd1d) | 1).shuffle(&mut key);
                    exact(&clean, &key, restarts, salt)
                })
                .count();
            println!("{length:7}   {restarts:8}   {hits:2}");
        }
    }
}
