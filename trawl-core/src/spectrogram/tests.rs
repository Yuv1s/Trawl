use super::*;

fn magnitude(re: &[f32], im: &[f32], bin: usize) -> f32 {
    (re[bin] * re[bin] + im[bin] * im[bin]).sqrt()
}

#[test]
fn a_constant_signal_is_all_dc() {
    let mut re = vec![1.0f32; 8];
    let mut im = vec![0.0f32; 8];

    fft(&mut re, &mut im);

    assert!((re[0] - 8.0).abs() < 1e-4, "bin 0 was {}", re[0]);
    for bin in 1..8 {
        assert!(magnitude(&re, &im, bin) < 1e-4, "bin {bin} should be empty");
    }
}

#[test]
fn a_cosine_lands_in_its_own_bin() {
    let n = 64;
    let k = 7;

    let mut re: Vec<f32> = (0..n)
        .map(|i| (2.0 * core::f64::consts::PI * k as f64 * i as f64 / n as f64).cos() as f32)
        .collect();
    let mut im = vec![0.0f32; n];

    fft(&mut re, &mut im);

    // A real cosine splits its energy between bin k and its mirror, so each side
    // carries half.
    assert!((magnitude(&re, &im, k) - n as f32 / 2.0).abs() < 1e-2);
    assert!((magnitude(&re, &im, n - k) - n as f32 / 2.0).abs() < 1e-2);

    for bin in 0..n {
        if bin == k || bin == n - k {
            continue;
        }
        assert!(magnitude(&re, &im, bin) < 1e-2, "leak into bin {bin}");
    }
}

#[test]
fn energy_is_conserved() {
    let n = 128;
    let input: Vec<f32> = (0..n).map(|i| ((i * 37 % 101) as f32 / 50.0) - 1.0).collect();

    let mut re = input.clone();
    let mut im = vec![0.0f32; n];
    fft(&mut re, &mut im);

    let time: f64 = input.iter().map(|&x| (x as f64) * (x as f64)).sum();
    let freq: f64 = (0..n)
        .map(|b| (re[b] as f64).powi(2) + (im[b] as f64).powi(2))
        .sum::<f64>()
        / n as f64;

    assert!(
        (time - freq).abs() / time < 1e-4,
        "Parseval: {time} vs {freq}"
    );
}

#[test]
fn a_single_sample_transforms_to_a_flat_spectrum() {
    let mut re = vec![0.0f32; 16];
    let mut im = vec![0.0f32; 16];
    re[0] = 1.0;

    fft(&mut re, &mut im);

    for bin in 0..16 {
        assert!((magnitude(&re, &im, bin) - 1.0).abs() < 1e-5);
    }
}

fn tone(hz: f32, seconds: f32, rate: u32) -> Vec<f32> {
    let count = (seconds * rate as f32) as usize;
    (0..count)
        .map(|i| {
            let t = i as f32 / rate as f32;
            (2.0 * core::f32::consts::PI * hz * t).sin() * 0.8
        })
        .collect()
}

#[test]
fn a_tone_draws_a_line_at_its_own_frequency() {
    let rate = 8000;
    let spec = analyse(&tone(1000.0, 0.5, rate), rate, 1024, 256).unwrap();

    // Bin height maps linearly to 0..rate/2, and row 0 is the top.
    let expected_bin = (1000.0 / (rate as f32 / 2.0) * spec.height as f32) as usize;
    let expected_row = spec.height - 1 - expected_bin;

    let column = spec.width / 2;
    let brightest = (0..spec.height)
        .max_by_key(|&row| spec.pixels[row * spec.width + column])
        .unwrap();

    assert!(
        brightest.abs_diff(expected_row) <= 1,
        "expected the line near row {expected_row}, found it at {brightest}"
    );
}

#[test]
fn silence_produces_no_bright_pixels() {
    let rate = 8000;
    let spec = analyse(&vec![0.0f32; 4000], rate, 1024, 256).unwrap();
    assert!(spec.pixels.iter().all(|&p| p == 0));
}

#[test]
fn a_tone_buried_at_the_bottom_of_the_range_is_still_drawn() {
    // Peak-relative normalisation is the point: a payload written a hundred dB
    // down is exactly what the tool exists to surface.
    let rate = 8000;
    let quiet: Vec<f32> = tone(1000.0, 0.5, rate).iter().map(|s| s * 1e-5).collect();
    let spec = analyse(&quiet, rate, 1024, 256).unwrap();

    assert!(spec.pixels.iter().any(|&p| p > 200));
}

#[test]
fn a_clip_shorter_than_one_window_is_declined_rather_than_padded() {
    assert!(analyse(&tone(440.0, 0.01, 8000), 8000, 1024, 256).is_none());
}

#[test]
fn a_long_file_is_strided_down_to_the_target_width() {
    let rate = 8000;
    let spec = analyse(&tone(440.0, 30.0, rate), rate, 1024, 400).unwrap();

    assert!(spec.width <= 402, "width ran to {}", spec.width);
    assert!(spec.hop > spec.window / 4);
}

#[test]
fn a_short_file_keeps_full_overlap() {
    let rate = 8000;
    let spec = analyse(&tone(440.0, 0.5, rate), rate, 1024, 4000).unwrap();
    assert_eq!(spec.hop, spec.window / 4);
}

#[test]
fn the_reported_ceiling_is_half_the_sample_rate() {
    let spec = analyse(&tone(440.0, 0.5, 44100), 44100, 1024, 256).unwrap();
    assert_eq!(spec.max_frequency, 22050.0);
    assert_eq!(spec.height, 512);
}
