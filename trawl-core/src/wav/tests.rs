use super::*;

/// Builds a RIFF file from a chunk list, so each test states exactly the layout
/// it is testing rather than patching bytes in a shared blob.
fn riff(chunks: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
    let mut body = b"WAVE".to_vec();

    for (id, payload) in chunks {
        body.extend_from_slice(*id);
        body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        body.extend_from_slice(payload);
        if payload.len() % 2 == 1 {
            body.push(0);
        }
    }

    let mut file = b"RIFF".to_vec();
    file.extend_from_slice(&(body.len() as u32).to_le_bytes());
    file.extend_from_slice(&body);
    file
}

fn fmt_chunk(tag: u16, channels: u16, rate: u32, bits: u16) -> Vec<u8> {
    let block_align = channels * bits / 8;
    let mut out = Vec::new();
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&channels.to_le_bytes());
    out.extend_from_slice(&rate.to_le_bytes());
    out.extend_from_slice(&(rate * block_align as u32).to_le_bytes());
    out.extend_from_slice(&block_align.to_le_bytes());
    out.extend_from_slice(&bits.to_le_bytes());
    out
}

fn pcm16(samples: &[i16]) -> Vec<u8> {
    samples.iter().flat_map(|s| s.to_le_bytes()).collect()
}

fn mono16(samples: &[i16]) -> Vec<u8> {
    riff(&[
        (b"fmt ", fmt_chunk(PCM, 1, 8000, 16)),
        (b"data", pcm16(samples)),
    ])
}

#[test]
fn reads_a_minimal_mono_file() {
    let file = mono16(&[0, 1000, -1000, 32767]);
    let wav = parse(&file).unwrap();

    assert_eq!(wav.format.tag, PCM);
    assert_eq!(wav.format.channels, 1);
    assert_eq!(wav.format.sample_rate, 8000);
    assert_eq!(wav.format.bits_per_sample, 16);
    assert_eq!(wav.frames, 4);
    assert_eq!(integer_samples(&file, &wav).unwrap(), vec![0, 1000, -1000, 32767]);
}

#[test]
fn rejects_a_file_that_is_not_riff() {
    assert_eq!(parse(b"\x89PNG\r\n\x1a\n").unwrap_err(), WavError::NotWav);
    assert!(!has_signature(b"RIFFxxxxAVI "));
}

#[test]
fn separates_the_channels_of_a_stereo_file() {
    let file = riff(&[
        (b"fmt ", fmt_chunk(PCM, 2, 44100, 16)),
        (b"data", pcm16(&[100, -100, 200, -200, 300, -300])),
    ]);
    let wav = parse(&file).unwrap();

    assert_eq!(wav.format.channels, 2);
    assert_eq!(wav.frames, 3);

    let samples = integer_samples(&file, &wav).unwrap();
    let left: Vec<i32> = samples.iter().step_by(2).copied().collect();
    assert_eq!(left, vec![100, 200, 300]);
}

#[test]
fn treats_eight_bit_samples_as_unsigned_with_silence_at_128() {
    let file = riff(&[
        (b"fmt ", fmt_chunk(PCM, 1, 8000, 8)),
        (b"data", vec![128, 129, 127, 255, 0]),
    ]);
    let wav = parse(&file).unwrap();

    assert_eq!(
        integer_samples(&file, &wav).unwrap(),
        vec![0, 1, -1, 127, -128]
    );
}

#[test]
fn sign_extends_twenty_four_bit_samples() {
    // 0xffffff is -1 at 24 bits, not 16,777,215.
    let file = riff(&[
        (b"fmt ", fmt_chunk(PCM, 1, 8000, 24)),
        (b"data", vec![0xff, 0xff, 0xff, 0x00, 0x00, 0x80]),
    ]);
    let wav = parse(&file).unwrap();

    assert_eq!(
        integer_samples(&file, &wav).unwrap(),
        vec![-1, -8_388_608]
    );
}

#[test]
fn unwraps_the_extensible_header_to_the_real_format() {
    let mut fmt = fmt_chunk(0xfffe, 2, 48000, 24);
    fmt.extend_from_slice(&22u16.to_le_bytes()); // cbSize
    fmt.extend_from_slice(&24u16.to_le_bytes()); // valid bits
    fmt.extend_from_slice(&3u32.to_le_bytes()); // channel mask
    fmt.extend_from_slice(&PCM.to_le_bytes()); // SubFormat GUID, first field
    fmt.extend_from_slice(&[0u8; 14]);

    let file = riff(&[(b"fmt ", fmt), (b"data", vec![0; 12])]);
    let wav = parse(&file).unwrap();

    assert_eq!(wav.format.tag, PCM);
    assert_eq!(wav.format.bits_per_sample, 24);
}

#[test]
fn refuses_a_compressed_format_instead_of_reading_noise() {
    let file = riff(&[
        (b"fmt ", fmt_chunk(0x0011, 1, 8000, 4)), // IMA ADPCM
        (b"data", vec![0; 16]),
    ]);
    assert_eq!(parse(&file).unwrap_err(), WavError::UnsupportedFormat(0x0011));
}

#[test]
fn says_so_rather_than_reading_a_low_bit_that_does_not_exist() {
    let file = riff(&[
        (b"fmt ", fmt_chunk(IEEE_FLOAT, 1, 8000, 32)),
        (b"data", 0.5f32.to_le_bytes().repeat(4)),
    ]);
    let wav = parse(&file).unwrap();

    assert_eq!(
        integer_samples(&file, &wav).unwrap_err(),
        WavError::FloatSamples
    );
    assert_eq!(mono(&file, &wav).unwrap(), vec![0.5; 4]);
}

#[test]
fn trusts_the_file_length_over_a_streamed_data_size() {
    let mut file = mono16(&[10, 20, 30, 40]);
    // Streamed writers leave 0xffffffff here and let the reader work it out.
    let data_at = file.len() - 8 - 4;
    file[data_at..data_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    // The RIFF size has to keep covering the file or the tail reads as trailing.
    let riff_size = (file.len() - 8) as u32;
    file[4..8].copy_from_slice(&riff_size.to_le_bytes());

    let wav = parse(&file).unwrap();
    assert_eq!(wav.frames, 4);
    assert_eq!(integer_samples(&file, &wav).unwrap(), vec![10, 20, 30, 40]);
}

#[test]
fn reports_bytes_past_the_declared_end_of_the_riff() {
    let mut file = mono16(&[1, 2, 3, 4]);
    let end = file.len();
    file.extend_from_slice(b"flag{after_the_riff}");

    let wav = parse(&file).unwrap();
    assert_eq!(wav.trailing, Some((end, 20)));
}

#[test]
fn does_not_read_appended_payload_as_another_chunk() {
    let mut file = mono16(&[1, 2, 3, 4]);
    file.extend_from_slice(b"flag{past_the_declared_end}");

    let wav = parse(&file).unwrap();
    assert_eq!(
        wav.chunks.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
        vec!["fmt ", "data"]
    );
}

#[test]
fn still_reads_a_real_chunk_left_past_a_wrong_riff_size() {
    let mut file = riff(&[
        (b"fmt ", fmt_chunk(PCM, 1, 8000, 16)),
        (b"data", pcm16(&[1, 2, 3, 4])),
        (b"note", b"written after the size was set".to_vec()),
    ]);
    // Some writers set the RIFF size before appending their last chunk.
    let short = (file.len() - 8 - 38) as u32;
    file[4..8].copy_from_slice(&short.to_le_bytes());

    let wav = parse(&file).unwrap();
    assert!(wav.chunks.iter().any(|c| c.id == "note"));
    assert!(chunk_text(&file, &wav)
        .iter()
        .any(|(_, _, s)| s.contains("written after the size was set")));
}

#[test]
fn a_file_with_nothing_appended_reports_no_trailing_bytes() {
    let wav = parse(&mono16(&[1, 2, 3, 4])).unwrap();
    assert_eq!(wav.trailing, None);
}

#[test]
fn walks_past_a_chunk_it_does_not_recognise() {
    let file = riff(&[
        (b"fmt ", fmt_chunk(PCM, 1, 8000, 16)),
        (b"LIST", b"INFOICMTflag{in_the_comment}".to_vec()),
        (b"data", pcm16(&[1, 2])),
    ]);
    let wav = parse(&file).unwrap();

    assert_eq!(wav.frames, 2);
    assert_eq!(
        wav.chunks.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
        vec!["fmt ", "LIST", "data"]
    );

    let text = chunk_text(&file, &wav);
    assert!(text.iter().any(|(id, _, s)| id == "LIST" && s.contains("flag{in_the_comment}")));
}

#[test]
fn skips_the_odd_byte_a_riff_pads_a_chunk_with() {
    let file = riff(&[
        (b"fmt ", fmt_chunk(PCM, 1, 8000, 16)),
        (b"note", b"odd".to_vec()), // 3 bytes, so one pad byte follows
        (b"data", pcm16(&[7, 8])),
    ]);
    let wav = parse(&file).unwrap();

    assert_eq!(wav.frames, 2);
    assert_eq!(integer_samples(&file, &wav).unwrap(), vec![7, 8]);
}

#[test]
fn marks_a_chunk_whose_length_runs_past_the_file_as_incomplete() {
    let mut file = mono16(&[1, 2, 3, 4]);
    let data_at = file.len() - 8 - 4;
    file[data_at..data_at + 4].copy_from_slice(&9999u32.to_le_bytes());

    let listed = chunks(&file).unwrap();
    let data = listed.iter().find(|c| c.id == "data").unwrap();
    assert!(!data.complete);

    // The clamp still gives back every sample the file actually holds.
    let wav = parse(&file).unwrap();
    assert_eq!(wav.frames, 4);
}

#[test]
fn a_file_with_no_data_chunk_says_which_part_is_missing() {
    let file = riff(&[(b"fmt ", fmt_chunk(PCM, 1, 8000, 16))]);
    assert_eq!(parse(&file).unwrap_err(), WavError::NoData);

    let file = riff(&[(b"data", pcm16(&[1, 2]))]);
    assert_eq!(parse(&file).unwrap_err(), WavError::NoFormat);
}

#[test]
fn scales_every_depth_to_the_same_range() {
    let loud = mono16(&[32767]);
    let wav = parse(&loud).unwrap();
    assert!((mono(&loud, &wav).unwrap()[0] - 1.0).abs() < 1e-3);

    let file = riff(&[
        (b"fmt ", fmt_chunk(PCM, 1, 8000, 8)),
        (b"data", vec![255]),
    ]);
    let wav = parse(&file).unwrap();
    assert!((mono(&file, &wav).unwrap()[0] - 0.992).abs() < 1e-2);
}

#[test]
fn averages_the_channels_when_mixing_down() {
    let file = riff(&[
        (b"fmt ", fmt_chunk(PCM, 2, 8000, 16)),
        (b"data", pcm16(&[32767, -32768])),
    ]);
    let wav = parse(&file).unwrap();
    assert!(mono(&file, &wav).unwrap()[0].abs() < 1e-3);
}

#[test]
fn reports_duration_from_the_frame_count() {
    let file = riff(&[
        (b"fmt ", fmt_chunk(PCM, 2, 8000, 16)),
        (b"data", pcm16(&vec![0i16; 8000 * 2])),
    ]);
    let wav = parse(&file).unwrap();
    assert!((wav.duration_seconds() - 1.0).abs() < 1e-4);
}

#[test]
fn does_not_read_text_out_of_the_audio_itself() {
    let mut samples = vec![0i16; 200];
    for (i, b) in b"flag{not_a_real_find}".iter().enumerate() {
        samples[i] = *b as i16;
    }

    let file = riff(&[
        (b"fmt ", fmt_chunk(PCM, 1, 8000, 16)),
        (b"data", pcm16(&samples)),
    ]);
    let wav = parse(&file).unwrap();

    // chunk_text is about chunks a player skips. Reading data would report every
    // quiet passage as a string.
    assert!(chunk_text(&file, &wav).is_empty());
}
