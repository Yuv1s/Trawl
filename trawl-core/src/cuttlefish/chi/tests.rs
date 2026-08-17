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

/// A cover whose pairs are maximally unequal: every sample is even, so 2i is
/// common and 2i+1 never occurs. This is what "nothing embedded" looks like to
/// the test.
fn unembedded(count: usize) -> Vec<u8> {
    (0..count).map(|i| ((i % 100) * 2) as u8).collect()
}

/// The same values with their low bit randomised, which is what embedding a
/// random payload does.
fn embed_lsbs(samples: &mut [u8], upto: usize, seed: u32) {
    let mut next = xorshift32(seed);
    for sample in samples.iter_mut().take(upto) {
        *sample = (*sample & 0xfe) | (next() & 1) as u8;
    }
}

#[test]
fn ln_gamma_matches_known_values() {
    assert!((ln_gamma(1.0) - 0.0).abs() < 1e-10);
    assert!((ln_gamma(2.0) - 0.0).abs() < 1e-10);
    assert!((ln_gamma(3.0) - std::f64::consts::LN_2).abs() < 1e-10);
    assert!((ln_gamma(0.5) - std::f64::consts::PI.sqrt().ln()).abs() < 1e-10);
    assert!((ln_gamma(6.0) - 120.0f64.ln()).abs() < 1e-10);
}

/// With two degrees of freedom the chi-square survival function is exactly
/// exp(-x/2), which pins the incomplete gamma implementation to a closed form.
#[test]
fn embedding_probability_matches_the_closed_form_at_two_degrees() {
    for x in [0.5f64, 1.0, 2.0, 5.0, 11.0, 30.0] {
        let got = embedding_probability(x, 2);
        let want = (-x / 2.0).exp();
        assert!((got - want).abs() < 1e-9, "x={x}: {got} vs {want}");
    }
}

#[test]
fn embedding_probability_matches_published_critical_values() {
    // 95th percentiles of the chi-square distribution, so the survival function
    // should read 0.05 at each.
    for (x, degrees) in [(3.841_459, 1usize), (5.991_465, 2), (18.307_038, 10)] {
        let p = embedding_probability(x, degrees);
        assert!((p - 0.05).abs() < 1e-4, "df={degrees}: {p}");
    }
}

#[test]
fn embedding_probability_is_one_for_a_perfect_fit_and_zero_when_hopeless() {
    assert!((embedding_probability(0.0, 40) - 1.0).abs() < 1e-12);
    assert!(embedding_probability(5000.0, 40) < 1e-12);
}

#[test]
fn degrees_of_freedom_ignore_pairs_too_sparse_to_trust() {
    let mut histogram = [0u64; 256];
    histogram[0] = 100;
    histogram[1] = 100;
    histogram[8] = 1; // expected 0.5, below the floor
    histogram[9] = 0;

    let (_, degrees) = statistic(&histogram);
    assert_eq!(degrees, 0, "one usable pair leaves zero degrees of freedom");
}

#[test]
fn a_clean_cover_reads_as_not_embedded() {
    let samples = unembedded(200_000);
    let points = sweep(&samples, 40);

    assert!(points.iter().all(|p| p.degrees > 0));
    assert!(
        points.iter().all(|p| p.p_embedding < 0.01),
        "clean cover looked embedded: {:?}",
        points.iter().map(|p| p.p_embedding).collect::<Vec<_>>()
    );
    assert!(!verdict(&points).detected);
}

#[test]
fn a_fully_embedded_cover_reads_as_embedded() {
    let mut samples = unembedded(200_000);
    let total = samples.len();
    embed_lsbs(&mut samples, total, 0xbeef);

    let points = sweep(&samples, 40);
    let result = verdict(&points);

    assert!(result.detected);
    assert!(result.peak_probability > 0.95);
    assert!(result.embedded_fraction > 0.95, "{result:?}");
}

/// The reason the sweep exists: the fit holds while the payload lasts and
/// collapses where it stops, so the collapse locates the payload boundary.
#[test]
fn the_prefix_sweep_locates_the_payload_boundary() {
    let mut samples = unembedded(200_000);
    embed_lsbs(&mut samples, 80_000, 0x1234);

    let points = sweep(&samples, 50);
    let at = |f: f32| {
        points
            .iter()
            .min_by(|a, b| {
                (a.fraction - f)
                    .abs()
                    .partial_cmp(&(b.fraction - f).abs())
                    .unwrap()
            })
            .unwrap()
    };

    assert!(at(0.2).p_embedding > 0.9, "inside the payload: {:?}", at(0.2));
    assert!(at(0.9).p_embedding < 0.1, "past the payload: {:?}", at(0.9));

    let result = verdict(&points);
    assert!(result.detected);
    assert!(
        (0.35..=0.5).contains(&result.embedded_fraction),
        "boundary estimated at {} for a payload ending at 0.40",
        result.embedded_fraction
    );
}

/// A documented limitation rather than a bug. The test asks whether the pairs are
/// equal; in a flat histogram they already are, so it reads as embedded with
/// nothing hidden. Any image whose values are near-uniform, including pure noise,
/// defeats this attack.
#[test]
fn a_uniform_histogram_defeats_the_attack() {
    let samples: Vec<u8> = (0..200_000).map(|i| (i % 256) as u8).collect();
    let points = sweep(&samples, 20);

    assert!(
        verdict(&points).detected,
        "documenting that a flat histogram is indistinguishable from full embedding"
    );
}

#[test]
fn sweep_handles_degenerate_input_without_panicking() {
    assert!(sweep(&[], 10).is_empty());
    assert!(sweep(&[1, 2, 3], 0).is_empty());

    let points = sweep(&[7u8; 3], 4);
    assert_eq!(points.len(), 4);
    assert!(
        points.iter().all(|p| p.degrees == 0),
        "three samples cannot support the approximation"
    );
    assert!(!verdict(&points).detected);
}
