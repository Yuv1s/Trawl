use super::*;

/// Writes a message into bit 0 of a run of samples, the way an audio stego tool
/// would, so the sweep has something real to find.
fn hide(message: &[u8], channels: usize, channel: Option<usize>, bit: u8, msb_first: bool) -> Vec<i32> {
    let bits: Vec<u32> = message
        .iter()
        .flat_map(|byte| {
            (0..8).map(move |i| {
                let shift = if msb_first { 7 - i } else { i };
                ((byte >> shift) & 1) as u32
            })
        })
        .collect();

    let step = if channel.is_some() { channels } else { 1 };
    let start = channel.unwrap_or(0);
    let mut samples = vec![0i32; start + bits.len() * step + channels];

    for (i, b) in bits.iter().enumerate() {
        let at = start + i * step;
        // Sit on a mid-scale value so the payload is not the only thing present.
        samples[at] = (0x1234 & !(1 << bit)) | ((*b as i32) << bit);
    }

    samples
}

#[test]
fn finds_a_message_written_into_the_low_bit() {
    let samples = hide(b"flag{audio_lsb}", 1, None, 0, true);
    let found = sweep(&samples, 1, 4096);

    let hit = found
        .iter()
        .find(|c| c.preview.contains("flag{audio_lsb}"))
        .expect("the payload should have surfaced");

    assert_eq!(hit.params.bit, 0);
    assert!(hit.params.msb_first);
    assert_eq!(hit.params.label, "mono");
}

#[test]
fn finds_a_message_in_one_channel_of_a_stereo_file() {
    let samples = hide(b"flag{right_channel_only}", 2, Some(1), 0, true);
    let found = sweep(&samples, 2, 4096);

    let hit = found
        .iter()
        .find(|c| c.preview.contains("flag{right_channel_only}"))
        .expect("the payload should have surfaced");

    assert_eq!(hit.params.label, "right");
    assert_eq!(hit.params.channel, Some(1));
}

#[test]
fn finds_a_message_written_lsb_first() {
    let samples = hide(b"flag{reversed_bit_order}", 1, None, 0, false);
    let found = sweep(&samples, 1, 4096);

    let hit = found
        .iter()
        .find(|c| c.preview.contains("flag{reversed_bit_order}"))
        .expect("the payload should have surfaced");

    assert!(!hit.params.msb_first);
}

#[test]
fn finds_a_message_one_bit_up_from_the_bottom() {
    let samples = hide(b"flag{second_bit_plane}", 1, None, 1, true);
    let found = sweep(&samples, 1, 4096);

    assert!(found
        .iter()
        .any(|c| c.params.bit == 1 && c.preview.contains("flag{second_bit_plane}")));
}

#[test]
fn a_recording_with_nothing_hidden_in_it_reports_nothing() {
    // A quiet sine, which is what a clean clip looks like: the low bits move,
    // but they move with the waveform rather than carrying text.
    let samples: Vec<i32> = (0..40000)
        .map(|i| {
            let t = i as f64 / 44100.0;
            ((2.0 * core::f64::consts::PI * 440.0 * t).sin() * 12000.0) as i32
        })
        .collect();

    assert!(sweep(&samples, 1, 4096).is_empty());
}

#[test]
fn silence_reports_nothing() {
    assert!(sweep(&vec![0i32; 40000], 1, 4096).is_empty());
}

#[test]
fn white_noise_reports_nothing() {
    let mut state = 0x9e3779b9u32;
    let samples: Vec<i32> = (0..40000)
        .map(|_| {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            ((state >> 16) as i16) as i32
        })
        .collect();

    assert!(sweep(&samples, 1, 4096).is_empty());
}

#[test]
fn reads_the_low_bit_of_a_negative_sample_correctly() {
    // Two's complement: -1 is all ones, so every bit plane reads 1.
    let extracted = extract(&[-1; 8], 1, None, 0, true, 16);
    assert_eq!(extracted, vec![0xff]);

    let extracted = extract(&[-2; 8], 1, None, 0, true, 16);
    assert_eq!(extracted, vec![0x00]);
}

#[test]
fn stops_at_the_byte_limit() {
    assert_eq!(extract(&vec![1i32; 8000], 1, None, 0, true, 10).len(), 10);
}

#[test]
fn names_the_channels_of_a_stereo_file_the_way_a_person_would() {
    let names: Vec<String> = channel_sets(2).into_iter().map(|(_, n)| n).collect();
    assert_eq!(names, vec!["all channels", "left", "right"]);

    let names: Vec<String> = channel_sets(6).into_iter().map(|(_, n)| n).collect();
    assert_eq!(names[0], "all channels");
    assert_eq!(names[6], "channel 6");
}

#[test]
fn does_not_count_the_same_read_twice_on_a_mono_file() {
    // One channel means "all channels" and "channel 1" are the same pass.
    assert_eq!(channel_sets(1).len(), 1);
    assert_eq!(combination_count(1), 6);
    assert_eq!(combination_count(2), 18);
}

#[test]
fn reports_the_search_space_it_actually_swept() {
    let samples = hide(b"flag{counted}", 2, Some(0), 0, true);
    let json = sweep_json(&samples, 2, 4096);

    assert!(json.contains("\"combinations\":18"));
    assert!(json.contains("\"channels\":\"left\""));
    assert!(json.contains("\"channelIndex\":0"));
}

#[test]
fn writes_null_for_a_read_that_covers_every_channel() {
    let samples = hide(b"flag{every_channel}", 2, None, 0, true);
    let json = sweep_json(&samples, 2, 4096);
    assert!(json.contains("\"channelIndex\":null"));
}
