use super::*;
use crate::jpeg::dct::{coefficients, Block};
use crate::jpeg::fixture::{build, Spec};

/// A cover that behaves like a photograph's coefficients: DC wanders, AC falls
/// away steeply from zero, and the counts either side of zero are close but not
/// equal. A flat or symmetric cover would pass the chi-square test by accident
/// and prove nothing about the detector.
fn cover(count: usize, seed: u32) -> Vec<Block> {
    let mut state = seed | 1;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state
    };

    let mut dc = 0i32;

    (0..count)
        .map(|_| {
            let mut block = [0i32; 64];
            dc += (next() % 21) as i32 - 10;
            block[0] = dc.clamp(-500, 500);

            // Energy concentrated in the low frequencies, thinning out fast.
            for (k, slot) in block.iter_mut().enumerate().take(40).skip(1) {
                let reach = 40 - k as u32;
                if next() % 64 >= reach {
                    continue;
                }

                // Geometric, not uniform. This is the whole point of the
                // fixture: a uniform magnitude makes the counts of 2 and 3
                // equal, and equal pair counts are precisely what the
                // chi-square test reads as an embedded payload. A cover drawn
                // that way tests nothing, because it already looks embedded.
                // A decay around 0.6 is what published JPEG coefficient
                // statistics show at ordinary quality settings. Steeper than
                // that models a heavily quantized image, where so few value
                // bins clear the test's minimum-count filter that there are
                // barely any pairs left to measure.
                let mut magnitude = 1i32;
                while magnitude < 40 && next() % 100 < 60 {
                    magnitude += 1;
                }

                *slot = if next() % 2 == 0 { magnitude } else { -magnitude };
            }

            block
        })
        .collect()
}

/// Writes a message into the low bits the way JSteg does, skipping 0 and 1.
fn embed(blocks: &mut [Block], order: &[(usize, usize)], message: &[u8], msb_first: bool) {
    let total = message.len() * 8;
    let mut written = 0usize;

    'outer: for &(_, index) in order {
        for slot in blocks[index].iter_mut().skip(1) {
            if written == total {
                break 'outer;
            }

            let value = *slot;
            if value == 0 || value == 1 {
                continue;
            }

            let shift = if msb_first {
                7 - (written % 8)
            } else {
                written % 8
            };
            let bit = ((message[written / 8] >> shift) & 1) as i32;
            *slot = (value & !1) | bit;
            written += 1;
        }
    }

    assert_eq!(written, total, "the cover had too few usable coefficients");
}

/// Builds a single-component JPEG from blocks, then reads it back.
fn round_trip(blocks: &[Block]) -> Coefficients {
    let file = build(&Spec::grayscale(8 * blocks.len(), 8), &[blocks.to_vec()]);
    coefficients(&file).unwrap()
}

fn planted(message: &[u8], msb_first: bool, seed: u32) -> Coefficients {
    let mut blocks = cover(600, seed);
    let order: Vec<(usize, usize)> = (0..blocks.len()).map(|i| (0, i)).collect();
    embed(&mut blocks, &order, message, msb_first);
    round_trip(&blocks)
}

/// A message whose bits are balanced, which is what a real payload looks like:
/// anything worth hiding is compressed or encrypted first. A structured filler
/// such as `i * 37 % 251` has skewed bits, and the pairs then equalise toward
/// that skew rather than toward even, which the test correctly reads as a
/// deviation. That would make the detector look weaker than it is.
fn payload(bytes: usize, seed: u32) -> Vec<u8> {
    let mut state = seed | 1;
    (0..bytes)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 8) as u8
        })
        .collect()
}

/// Validates the cover before anything measures against it.
///
/// Five times now a detector has "worked" only because the fixture behaved
/// unlike real data. A cover whose adjacent magnitude counts are close is
/// already indistinguishable from an embedded one, so assert the decay here and
/// let this fail rather than the detector look good for the wrong reason.
#[test]
fn the_cover_falls_away_from_zero_the_way_a_photograph_does() {
    let found = round_trip(&cover(600, 0x5150));
    let counts = histogram(&found);
    let at = |v: i32| counts.iter().find(|(x, _)| *x == v).unwrap().1 as f64;

    for v in [2, 3, 4, 5] {
        let ratio = at(v + 1) / at(v);
        assert!(
            ratio < 0.8,
            "count({}) is {:.2} of count({v}), which is flat enough to read as embedded",
            v + 1,
            ratio
        );
    }

    assert!(at(1) > at(6) * 3.0, "the peak near zero is too shallow");
}

#[test]
fn reads_back_a_message_written_into_the_coefficients() {
    let found = planted(b"flag{jsteg_in_the_coefficients}", true, 0x1234);
    let sweep = sweep(&found, 4096);

    let hit = sweep
        .iter()
        .find(|c| c.preview.contains("flag{jsteg_in_the_coefficients}"))
        .expect("the payload should have surfaced");

    assert!(hit.msb_first);
    assert!(!hit.include_dc);
}

#[test]
fn reads_back_a_message_written_low_bit_first() {
    let found = planted(b"flag{reversed_bit_order}", false, 0x99aa);
    assert!(sweep(&found, 4096)
        .iter()
        .any(|c| !c.msb_first && c.preview.contains("flag{reversed_bit_order}")));
}

#[test]
fn a_clean_image_produces_nothing() {
    let found = round_trip(&cover(600, 0x5150));
    assert!(
        sweep(&found, 4096).is_empty(),
        "a cover with nothing in it must stay quiet"
    );
}

#[test]
fn the_chi_square_test_stays_quiet_on_a_clean_image() {
    // Ten covers, not one. A detector that fires on any of them is a detector
    // that will fire on a clean file someone actually cares about.
    for seed in [
        0x5150u32, 0xc0ffee, 0x2b2b2b, 1, 0xffff_ffff, 0x13579b, 0x2468ac, 0xdeadbeef, 0x515,
        0xa5a5a5a5,
    ] {
        let found = round_trip(&cover(600, seed));
        let result = chi_square(&found, 64);
        assert!(
            !result.detected,
            "seed {seed:#x} produced a false positive at p {}",
            result.peak_probability
        );
    }
}

#[test]
fn the_chi_square_test_sees_a_full_length_payload() {
    // Filling every usable coefficient is what the test is designed to catch.
    let mut blocks = cover(600, 0x77);
    let order: Vec<(usize, usize)> = (0..blocks.len()).map(|i| (0, i)).collect();

    let usable = blocks
        .iter()
        .map(|b| b[1..].iter().filter(|&&v| v != 0 && v != 1).count())
        .sum::<usize>();
    let message = payload(usable / 8, 0x5eed);

    embed(&mut blocks, &order, &message, true);
    let result = chi_square(&round_trip(&blocks), 64);

    assert!(
        result.detected,
        "peak probability was only {}",
        result.peak_probability
    );
}

#[test]
fn the_chi_square_test_locates_where_a_short_payload_stops() {
    let mut blocks = cover(900, 0xabc);
    let order: Vec<(usize, usize)> = (0..blocks.len()).map(|i| (0, i)).collect();

    let usable = blocks
        .iter()
        .map(|b| b[1..].iter().filter(|&&v| v != 0 && v != 1).count())
        .sum::<usize>();
    let message = payload(usable / 8 / 4, 0xbeef);

    embed(&mut blocks, &order, &message, true);
    let result = chi_square(&round_trip(&blocks), 64);

    assert!(result.detected);
    // The fit should collapse near where the message ran out, not at the end.
    assert!(
        result.embedded_fraction < 0.6,
        "boundary landed at {}, which does not look like a quarter-length payload",
        result.embedded_fraction
    );
}

#[test]
fn skips_the_two_values_jsteg_never_touches() {
    // A block of nothing but zeroes and ones yields no bits at all.
    let mut block = [0i32; 64];
    for (k, slot) in block.iter_mut().enumerate().take(32).skip(1) {
        *slot = (k % 2) as i32;
    }
    block[0] = 4;

    let found = round_trip(&[block]);
    assert!(extract(&found, false, true, 64).is_empty());
}

#[test]
fn reads_the_low_bit_of_a_negative_coefficient() {
    // Two's complement: -3 is odd, -4 is even.
    let mut block = [0i32; 64];
    block[0] = 0;
    for (i, k) in (1..17).enumerate() {
        block[k] = if i % 2 == 0 { -3 } else { -4 };
    }

    let found = round_trip(&[block]);
    assert_eq!(extract(&found, false, true, 8), vec![0b10101010, 0b10101010]);
}

#[test]
fn including_dc_shifts_every_bit_that_follows() {
    let found = planted(b"flag{dc_matters}", true, 0x321);
    let without = extract(&found, false, true, 64);
    let with = extract(&found, true, true, 64);
    assert_ne!(without, with);
}

#[test]
fn walks_the_components_in_entropy_stream_order() {
    // On a subsampled image an embedder writes four luma blocks, then one of
    // each chroma. Grouping by component instead would read a different stream.
    let spec = Spec {
        width: 16,
        height: 16,
        components: vec![(1, 2, 2), (2, 1, 1), (3, 1, 1)],
        restart_interval: 0,
        progressive: false,
    };

    let luma: Vec<Block> = (0..4)
        .map(|i| {
            let mut b = [0i32; 64];
            b[0] = i + 1;
            b[1] = 2;
            b
        })
        .collect();
    let mut cb = [0i32; 64];
    cb[1] = 9;
    let mut cr = [0i32; 64];
    cr[1] = 7;

    let file = build(&spec, &[luma, vec![cb], vec![cr]]);
    let found = coefficients(&file).unwrap();

    assert_eq!(found.order.len(), 6);
    assert_eq!(
        found.order,
        vec![(0, 0), (0, 1), (0, 2), (0, 3), (1, 0), (2, 0)]
    );

    // The chroma coefficients must come last in the flat stream.
    let flat = values(&found, false);
    let nonzero: Vec<i32> = flat.into_iter().filter(|&v| v != 0).collect();
    assert_eq!(nonzero, vec![2, 2, 2, 2, 9, 7]);
}

#[test]
fn the_histogram_covers_both_sides_of_zero() {
    let found = round_trip(&cover(200, 0x606));
    let counts = histogram(&found);

    assert_eq!(counts.len() as i32, HISTOGRAM_RANGE * 2 + 1);
    assert_eq!(counts.first().unwrap().0, -HISTOGRAM_RANGE);
    assert_eq!(counts.last().unwrap().0, HISTOGRAM_RANGE);

    // A photograph's coefficients pile up at zero and thin out from there.
    let zero = counts.iter().find(|(v, _)| *v == 0).unwrap().1;
    let far = counts.iter().find(|(v, _)| *v == 10).unwrap().1;
    assert!(zero > far * 4, "expected a peak at zero, got {zero} vs {far}");
}

#[test]
fn json_is_null_for_a_file_that_is_not_a_jpeg() {
    assert_eq!(json(b"\x89PNG\r\n\x1a\n", 512, 8), "null");
}

#[test]
fn json_carries_the_reason_a_progressive_file_was_refused() {
    let spec = Spec {
        progressive: true,
        ..Spec::grayscale(8, 8)
    };
    let mut b = [0i32; 64];
    b[0] = 1;
    let file = build(&spec, &[vec![b]]);

    let out = json(&file, 512, 8);
    assert!(out.contains("\"error\""), "{out}");
    assert!(out.contains("progressive"), "{out}");
}

#[test]
fn json_is_shaped_for_the_worker() {
    let mut blocks = cover(400, 0xd0d0);
    let order: Vec<(usize, usize)> = (0..blocks.len()).map(|i| (0, i)).collect();
    embed(&mut blocks, &order, b"flag{json_shape}", true);

    let file = build(&Spec::grayscale(8 * blocks.len(), 8), &[blocks]);
    let out = json(&file, 4096, 32);

    assert!(out.contains("\"combinations\":4"), "{out}");
    assert!(out.contains("\"histogram\":["), "{out}");
    assert!(out.contains("\"chi\":{"), "{out}");
    assert!(out.contains("flag{json_shape}"), "{out}");
}

