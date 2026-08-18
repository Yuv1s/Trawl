use super::*;

/// A palette where `pairs` colours appear twice and the rest appear once.
fn palette_with(pairs: usize, singles: usize) -> Vec<u8> {
    let mut out = Vec::new();

    for i in 0..pairs {
        let colour = [(i * 7) as u8, (i * 11) as u8, (i * 13) as u8];
        out.extend_from_slice(&colour);
        out.extend_from_slice(&colour);
    }

    for i in 0..singles {
        out.extend_from_slice(&[200 + i as u8, 100 + i as u8, 50 + i as u8]);
    }

    out
}

/// Paints `count` pixels, writing a message into the choice between copies.
fn paint(palette: &[u8], count: usize, message: &[u8], msb_first: bool) -> Vec<u8> {
    let found = groups(palette);
    assert!(!found.is_empty(), "the fixture palette has no duplicates");

    let mut out = Vec::with_capacity(count);
    let mut written = 0usize;

    for i in 0..count {
        let group = &found[i % found.len()];

        if written < message.len() * 8 {
            let shift = if msb_first {
                7 - (written % 8)
            } else {
                written % 8
            };
            let bit = (message[written / 8] >> shift) & 1;
            written += 1;
            out.push(group.indices[bit as usize]);
        } else {
            out.push(group.indices[0]);
        }
    }

    out
}

#[test]
fn finds_the_duplicated_colours() {
    let palette = palette_with(3, 10);
    let found = groups(&palette);

    assert_eq!(found.len(), 3);
    assert!(found.iter().all(|g| g.indices.len() == 2));
    assert!(found.iter().all(|g| g.bits == 1));
}

#[test]
fn ignores_a_palette_where_every_colour_is_distinct() {
    assert!(groups(&palette_with(0, 40)).is_empty());
    assert!(extract(&palette_with(0, 40), &[0, 1, 2, 3], true, 64).is_empty());
}

#[test]
fn reads_back_a_message_written_into_the_index_choices() {
    let palette = palette_with(2, 20);
    let indices = paint(&palette, 4000, b"flag{in_the_palette_indices}", true);

    let found = sweep(&palette, &indices, 4096);
    let hit = found
        .iter()
        .find(|c| c.preview.contains("flag{in_the_palette_indices}"))
        .expect("the payload should have surfaced");

    assert!(hit.msb_first);
}

#[test]
fn reads_back_a_message_packed_low_bit_first() {
    let palette = palette_with(2, 20);
    let indices = paint(&palette, 4000, b"flag{reversed_packing}", false);

    assert!(sweep(&palette, &indices, 4096)
        .iter()
        .any(|c| !c.msb_first && c.preview.contains("flag{reversed_packing}")));
}

#[test]
fn an_image_that_never_varies_its_choice_reports_nothing() {
    // Every pixel takes the first copy of its colour, which is what an ordinary
    // encoder produces. A stream of zero bits is not a payload.
    let palette = palette_with(3, 20);
    let found = groups(&palette);
    let indices: Vec<u8> = (0..4000).map(|i| found[i % found.len()].indices[0]).collect();

    assert!(sweep(&palette, &indices, 4096).is_empty());
}

#[test]
fn random_choices_report_nothing() {
    let palette = palette_with(3, 20);
    let found = groups(&palette);

    let mut state = 0x9e3779b9u32;
    let indices: Vec<u8> = (0..8000)
        .map(|i| {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            found[i % found.len()].indices[((state >> 19) & 1) as usize]
        })
        .collect();

    assert!(
        sweep(&palette, &indices, 4096).is_empty(),
        "noise in the index choices is not a message"
    );
}

#[test]
fn a_group_of_four_carries_two_bits_per_pixel() {
    let colour = [9u8, 9, 9];
    let mut palette = Vec::new();
    for _ in 0..4 {
        palette.extend_from_slice(&colour);
    }
    palette.extend_from_slice(&[1, 2, 3]);

    let found = groups(&palette);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].indices, vec![0, 1, 2, 3]);
    assert_eq!(found[0].bits, 2);

    // Indices 0b00, 0b01, 0b10, 0b11 pack to one byte.
    assert_eq!(extract(&palette, &[0, 1, 2, 3], true, 8), vec![0b00_01_10_11]);
}

#[test]
fn rounds_an_odd_group_down_to_whole_bits() {
    // Three copies would be log2(3) bits, which no encoder can write. Two of the
    // three are usable and the third is not, so one bit is all that is claimed.
    let colour = [4u8, 5, 6];
    let mut palette = Vec::new();
    for _ in 0..3 {
        palette.extend_from_slice(&colour);
    }

    let found = groups(&palette);
    assert_eq!(found[0].indices.len(), 3);
    assert_eq!(found[0].bits, 1);
}

#[test]
fn counts_only_the_pixels_that_can_carry_something() {
    let palette = palette_with(1, 10);
    let found = groups(&palette);
    let duplicated = found[0].indices[0];

    // Half the pixels use the duplicated colour, half use a unique one.
    let indices: Vec<u8> = (0..100)
        .map(|i| if i % 2 == 0 { duplicated } else { 5 })
        .collect();

    assert_eq!(capacity(&palette, &indices), 50);
}

#[test]
fn json_is_shaped_for_the_worker() {
    let palette = palette_with(2, 20);
    let indices = paint(&palette, 4000, b"flag{json_shape}", true);
    let out = json(&palette, &indices, 4096);

    assert!(out.contains("\"combinations\":2"), "{out}");
    assert!(out.contains("\"groups\":["), "{out}");
    assert!(out.contains("\"copies\":2"), "{out}");
    assert!(out.contains("flag{json_shape}"), "{out}");
}

#[test]
fn json_reports_an_ordinary_palette_as_carrying_nothing() {
    let palette = palette_with(0, 30);
    let out = json(&palette, &[0, 1, 2, 3], 4096);

    assert!(out.contains("\"groups\":[]"), "{out}");
    assert!(out.contains("\"candidates\":[]"), "{out}");
    assert!(out.contains("\"capacityBits\":0"), "{out}");
}
