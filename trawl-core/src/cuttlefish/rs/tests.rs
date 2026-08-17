use super::*;

fn xorshift32(seed: u32) -> impl FnMut() -> u32 {
    let mut s = seed;
    move || {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        s
    }
}

/// A correlated cover with real local texture.
///
/// RS reads how a group of neighbours responds to being nudged, so the cover has
/// to have something to respond with. A pure gradient is so smooth that long runs
/// of pixels are identical, every group scores zero roughness, and both masks
/// make every group rougher: the counts saturate and the model degenerates. A
/// buffer of independent random bytes fails the other way, with no correlation to
/// read. Neither is a valid control; a real photograph is neither.
fn photo_like(width: usize, height: usize) -> Vec<u8> {
    let mut out = vec![0u8; width * height * 4];

    for y in 0..height {
        for x in 0..width {
            let o = (y * width + x) * 4;
            let (fx, fy) = (x as f32, y as f32);
            let (nx, ny) = (fx / width as f32, fy / height as f32);
            let r = ((nx - 0.5).powi(2) + (ny - 0.5).powi(2)).sqrt();

            // Smooth base plus fine detail at a few levels, so adjacent pixels
            // differ by small non-zero amounts the way a photograph does.
            let detail = 5.0 * (fx * 0.9).sin() + 4.0 * (fy * 1.1).cos()
                + 3.0 * ((fx + fy) * 0.35).sin();

            let sample = |base: f32| (base + detail).clamp(2.0, 253.0) as u8;

            out[o] = sample(180.0 - 96.0 * r);
            out[o + 1] = sample(138.0 + 52.0 * (nx * 3.0).sin());
            out[o + 2] = sample(100.0 + 48.0 * (ny * 2.0).cos());
            out[o + 3] = 255;
        }
    }

    out
}

/// Sequential LSB embedding over the leading `rate` of the R, G, B sample stream,
/// which is what a naive embedder does.
fn embed(rgba: &mut [u8], rate: f64, seed: u32) {
    let mut next = xorshift32(seed);
    let pixels = rgba.len() / 4;
    let target = (pixels as f64 * 3.0 * rate) as usize;
    let mut written = 0usize;

    'outer: for p in 0..pixels {
        for c in 0..3 {
            if written >= target {
                break 'outer;
            }
            let at = p * 4 + c;
            rgba[at] = (rgba[at] & 0xfe) | (next() & 1) as u8;
            written += 1;
        }
    }
}

#[test]
fn discrimination_measures_roughness() {
    assert_eq!(discriminate(&[10, 10, 10, 10]), 0);
    assert_eq!(discriminate(&[10, 20, 10, 20]), 30);
    assert_eq!(discriminate(&[0, 255, 0, 255]), 765);
}

#[test]
fn flip_up_pairs_each_even_value_with_the_odd_above_it() {
    assert_eq!(flip_up(0), 1);
    assert_eq!(flip_up(1), 0);
    assert_eq!(flip_up(254), 255);
    assert_eq!(flip_up(255), 254);
}

#[test]
fn flip_down_pairs_the_other_way_and_leaves_the_endpoints_alone() {
    assert_eq!(flip_down(1), 2);
    assert_eq!(flip_down(2), 1);
    assert_eq!(flip_down(253), 254);
    assert_eq!(flip_down(254), 253);
    assert_eq!(flip_down(0), 0, "0 has no partner below it");
    assert_eq!(flip_down(255), 255, "255 has no partner above it");
}

#[test]
fn both_flips_are_their_own_inverse_where_they_act() {
    for value in 0..=255u8 {
        assert_eq!(flip_up(flip_up(value)), value);
        assert_eq!(flip_down(flip_down(value)), value);
    }
}

#[test]
fn the_mask_touches_only_the_pixels_it_names() {
    let group = [10u8, 20, 30, 40];
    assert_eq!(apply(&group, MASK), [10, 21, 31, 40]);
    assert_eq!(apply(&group, negate(MASK)), [10, 19, 29, 40]);
}

/// The paper's central claim: a clean image responds symmetrically to the two
/// flips, so R_M and R₋M sit close together.
/// Guards the fixture itself. If the counts saturate at 0 or 1 the cover is
/// degenerate and every test below it is measuring nothing.
#[test]
fn the_control_cover_produces_a_usable_spread_of_groups() {
    let counts = scan(&photo_like(320, 240), 320, 240, 3, false);

    for (name, value) in [
        ("R_M", counts.regular),
        ("S_M", counts.singular),
        ("R_-M", counts.regular_negated),
        ("S_-M", counts.singular_negated),
    ] {
        assert!(
            (0.02..0.95).contains(&value),
            "{name} saturated at {value}: the cover is degenerate, not the algorithm"
        );
    }
}

/// The paper's central claim: a clean image responds symmetrically to the two
/// flips, so R_M sits close to R₋M and S_M close to S₋M.
#[test]
fn a_clean_cover_has_matching_counts_under_both_masks() {
    let cover = photo_like(320, 240);
    let counts = scan(&cover, 320, 240, 3, false);

    assert!(counts.groups > 1000);
    assert!(
        (counts.regular - counts.regular_negated).abs() < 0.1,
        "R_M {} vs R_-M {}",
        counts.regular,
        counts.regular_negated
    );
    assert!(
        (counts.singular - counts.singular_negated).abs() < 0.1,
        "S_M {} vs S_-M {}",
        counts.singular,
        counts.singular_negated
    );
}

#[test]
fn a_clean_cover_estimates_close_to_zero() {
    let cover = photo_like(320, 240);
    let estimate = analyse(&cover, 320, 240, 3);

    assert!(estimate.reliable, "{estimate:?}");
    assert!(
        estimate.rate < DETECTION_FLOOR,
        "clean cover estimated at {}",
        estimate.rate
    );
}

/// Embedding spread uniformly across the image, which is the distribution the
/// paper's model assumes.
fn scatter(rgba: &mut [u8], rate: f64, seed: u32) {
    let mut next = xorshift32(seed);
    let pixels = rgba.len() / 4;
    let threshold = (rate * u32::MAX as f64) as u32;

    for p in 0..pixels {
        for c in 0..3 {
            if next() < threshold {
                let at = p * 4 + c;
                rgba[at] = (rgba[at] & 0xfe) | (next() & 1) as u8;
            }
        }
    }
}

#[test]
fn the_estimate_tracks_a_scattered_payload() {
    for (rate, seed) in [(0.25f64, 0x11u32), (0.5, 0x22), (0.75, 0x33), (1.0, 0x44)] {
        let mut cover = photo_like(320, 240);
        scatter(&mut cover, rate, seed);

        let estimate = analyse(&cover, 320, 240, 3);
        assert!(estimate.reliable, "rate {rate}: {estimate:?}");
        assert!(
            (estimate.rate as f64 - rate).abs() < 0.12,
            "scattered {rate}, estimated {}",
            estimate.rate
        );
    }
}

/// A payload packed into the front of the image is spatially bimodal: fully
/// embedded, then untouched. The model assumes one uniform rate, so it still
/// detects but reads low. Chi-square is the better length estimate in that case,
/// which is the argument for running both.
#[test]
fn a_sequential_payload_is_detected_but_underestimated() {
    for (rate, seed) in [(0.25f64, 0x11u32), (0.5, 0x22), (0.75, 0x33)] {
        let mut cover = photo_like(320, 240);
        embed(&mut cover, rate, seed);

        let estimate = analyse(&cover, 320, 240, 3);
        assert!(estimate.reliable, "rate {rate}: {estimate:?}");
        assert!(
            estimate.rate > DETECTION_FLOOR,
            "sequential {rate} went undetected"
        );
        assert!(
            (estimate.rate as f64) <= rate + 0.12,
            "sequential {rate} should not read high, got {}",
            estimate.rate
        );
    }
}

#[test]
fn embedding_pushes_the_two_masks_apart() {
    let clean = photo_like(320, 240);
    let before = scan(&clean, 320, 240, 3, false);

    let mut stego = clean.clone();
    embed(&mut stego, 1.0, 0x99);
    let after = scan(&stego, 320, 240, 3, false);

    let gap = |c: &Counts| (c.regular - c.regular_negated).abs();
    assert!(
        gap(&after) > gap(&before) + 0.05,
        "gap moved from {} to {}",
        gap(&before),
        gap(&after)
    );
}

#[test]
fn too_few_groups_is_reported_as_unreliable_rather_than_guessed() {
    let tiny = photo_like(8, 4);
    let estimate = analyse(&tiny, 8, 4, 3);
    assert!(!estimate.reliable);
    assert_eq!(estimate.rate, 0.0);
}

#[test]
fn a_flat_image_does_not_produce_a_confident_answer() {
    let flat = vec![128u8; 320 * 240 * 4];
    let estimate = analyse(&flat, 320, 240, 3);

    assert!(
        !estimate.reliable || estimate.rate < DETECTION_FLOOR,
        "a constant image should not read as embedded: {estimate:?}"
    );
}

#[test]
fn json_carries_the_group_counts_that_justify_the_estimate() {
    let mut cover = photo_like(160, 120);
    embed(&mut cover, 0.5, 0x55);

    let text = json(&analyse(&cover, 160, 120, 3));
    assert!(text.starts_with('{') && text.ends_with('}'));
    for key in [
        "\"rate\"",
        "\"reliable\"",
        "\"detected\"",
        "\"regular\"",
        "\"singular\"",
        "\"regularNegated\"",
        "\"singularNegated\"",
        "\"groups\"",
    ] {
        assert!(text.contains(key), "{key} missing from {text}");
    }
}
