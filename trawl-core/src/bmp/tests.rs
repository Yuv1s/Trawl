use super::*;

/// Builds a BMP the way an encoder would: 40-byte header, optional colour table,
/// rows padded to four bytes, bottom-up unless asked otherwise.
fn build(width: i32, height: i32, bpp: u16, table: &[[u8; 3]], rows: &[Vec<u8>]) -> Vec<u8> {
    let stride = ((width.unsigned_abs() as usize * bpp as usize).div_ceil(32)) * 4;
    let palette_bytes = table.len() * 4;
    let offset = 14 + 40 + palette_bytes;

    let mut out = b"BM".to_vec();
    out.extend_from_slice(&((offset + stride * rows.len()) as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(offset as u32).to_le_bytes());

    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&bpp.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&2835i32.to_le_bytes());
    out.extend_from_slice(&2835i32.to_le_bytes());
    out.extend_from_slice(&(table.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());

    for [r, g, b] in table {
        out.extend_from_slice(&[*b, *g, *r, 0]);
    }

    for row in rows {
        let mut padded = row.clone();
        padded.resize(stride, 0);
        out.extend_from_slice(&padded);
    }

    out
}

/// Blue, green, red, in that order, which is how BMP stores a pixel.
fn bgr(pixels: &[[u8; 3]]) -> Vec<u8> {
    pixels.iter().flat_map(|[r, g, b]| [*b, *g, *r]).collect()
}

fn pixel(rgba: &[u8], width: usize, x: usize, y: usize) -> [u8; 4] {
    let at = (y * width + x) * 4;
    [rgba[at], rgba[at + 1], rgba[at + 2], rgba[at + 3]]
}

#[test]
fn has_signature_only_accepts_bm() {
    assert!(has_signature(b"BM\x00\x00"));
    assert!(!has_signature(b"\x89PNG\r\n\x1a\n"));
    assert!(!has_signature(&[]));
}

#[test]
fn header_reads_the_geometry() {
    let file = build(4, 3, 24, &[], &vec![bgr(&[[0, 0, 0]; 4]); 3]);
    let header = header(&file).unwrap();

    assert_eq!(header.width, 4);
    assert_eq!(header.height, 3);
    assert_eq!(header.bits_per_pixel, 24);
    assert!(!header.top_down);
}

/// The detail that catches people out: the first row in the file is the bottom
/// row of the picture.
#[test]
fn rows_are_stored_bottom_up_by_default() {
    let top = bgr(&[[255, 0, 0], [255, 0, 0]]);
    let bottom = bgr(&[[0, 0, 255], [0, 0, 255]]);
    let file = build(2, 2, 24, &[], &[bottom, top]);

    let (header, rgba) = decode(&file).unwrap();
    assert_eq!(pixel(&rgba, header.width, 0, 0), [255, 0, 0, 255], "top row");
    assert_eq!(pixel(&rgba, header.width, 0, 1), [0, 0, 255, 255], "bottom row");
}

#[test]
fn a_negative_height_means_the_rows_are_already_in_order() {
    let first = bgr(&[[255, 0, 0], [255, 0, 0]]);
    let second = bgr(&[[0, 0, 255], [0, 0, 255]]);
    let file = build(2, -2, 24, &[], &[first, second]);

    let (header, rgba) = decode(&file).unwrap();
    assert!(header.top_down);
    assert_eq!(pixel(&rgba, header.width, 0, 0), [255, 0, 0, 255]);
    assert_eq!(pixel(&rgba, header.width, 0, 1), [0, 0, 255, 255]);
}

/// Three pixels of 24-bit colour is nine bytes, which the format rounds up to
/// twelve. Reading the padding as pixels shears the image.
#[test]
fn row_padding_to_four_bytes_is_skipped() {
    let row = |c: [u8; 3]| bgr(&[c, c, c]);
    let file = build(3, 2, 24, &[], &[row([10, 20, 30]), row([40, 50, 60])]);

    let (header, rgba) = decode(&file).unwrap();
    assert_eq!(header.width, 3);
    for x in 0..3 {
        assert_eq!(pixel(&rgba, 3, x, 0), [40, 50, 60, 255]);
        assert_eq!(pixel(&rgba, 3, x, 1), [10, 20, 30, 255]);
    }
}

#[test]
fn eight_bit_pixels_come_from_the_colour_table() {
    let table = [[255, 0, 0], [0, 255, 0], [0, 0, 255]];
    let file = build(3, 1, 8, &table, &[vec![2, 0, 1]]);

    let (_, rgba) = decode(&file).unwrap();
    assert_eq!(pixel(&rgba, 3, 0, 0), [0, 0, 255, 255]);
    assert_eq!(pixel(&rgba, 3, 1, 0), [255, 0, 0, 255]);
    assert_eq!(pixel(&rgba, 3, 2, 0), [0, 255, 0, 255]);
}

#[test]
fn four_and_one_bit_pixels_unpack_from_shared_bytes() {
    let table: Vec<[u8; 3]> = (0..16).map(|i| [i * 16, 0, 0]).collect();
    let file = build(4, 1, 4, &table, &[vec![0x12, 0x30]]);
    let (_, rgba) = decode(&file).unwrap();
    assert_eq!(pixel(&rgba, 4, 0, 0)[0], 16);
    assert_eq!(pixel(&rgba, 4, 1, 0)[0], 32);
    assert_eq!(pixel(&rgba, 4, 2, 0)[0], 48);
    assert_eq!(pixel(&rgba, 4, 3, 0)[0], 0);

    let mono = [[0, 0, 0], [255, 255, 255]];
    let file = build(8, 1, 1, &mono, &[vec![0b1010_0110]]);
    let (_, rgba) = decode(&file).unwrap();
    let levels: Vec<u8> = (0..8).map(|x| pixel(&rgba, 8, x, 0)[0]).collect();
    assert_eq!(levels, vec![255, 0, 255, 0, 0, 255, 255, 0]);
}

/// Plenty of encoders write zero into the fourth byte of a 32-bit BMP. Reading
/// that as alpha would render the whole image transparent.
#[test]
fn a_thirty_two_bit_image_with_no_alpha_set_is_treated_as_opaque() {
    let row: Vec<u8> = [[10u8, 20, 30], [40, 50, 60]]
        .iter()
        .flat_map(|[r, g, b]| [*b, *g, *r, 0])
        .collect();
    let file = build(2, 1, 32, &[], &[row]);

    let (_, rgba) = decode(&file).unwrap();
    assert_eq!(pixel(&rgba, 2, 0, 0), [10, 20, 30, 255]);
    assert_eq!(pixel(&rgba, 2, 1, 0), [40, 50, 60, 255]);
}

#[test]
fn alpha_is_honoured_once_something_has_set_it() {
    let row = vec![30, 20, 10, 128, 60, 50, 40, 255];
    let file = build(2, 1, 32, &[], &[row]);

    let (_, rgba) = decode(&file).unwrap();
    assert_eq!(pixel(&rgba, 2, 0, 0), [10, 20, 30, 128]);
    assert_eq!(pixel(&rgba, 2, 1, 0), [40, 50, 60, 255]);
}

#[test]
fn a_compressed_bitmap_is_refused_rather_than_misread() {
    let mut file = build(2, 2, 8, &[[0, 0, 0]], &[vec![0, 0], vec![0, 0]]);
    file[30] = 1; // BI_RLE8
    assert_eq!(decode(&file), Err(BmpError::UnsupportedCompression(1)));
}

#[test]
fn an_unsupported_depth_is_named_rather_than_guessed() {
    let mut file = build(2, 2, 24, &[], &vec![bgr(&[[0, 0, 0]; 2]); 2]);
    file[28] = 16;
    file[29] = 0;
    assert_eq!(decode(&file), Err(BmpError::UnsupportedDepth(16)));
}

#[test]
fn a_truncated_file_is_reported_not_read_past() {
    let file = build(8, 8, 24, &[], &vec![bgr(&[[1, 2, 3]; 8]); 8]);
    for cut in 0..file.len() {
        let _ = header(&file[..cut]);
        let _ = decode(&file[..cut]);
    }
    assert_eq!(decode(&file[..file.len() - 4]), Err(BmpError::Truncated));
}

#[test]
fn something_that_is_not_a_bitmap_is_refused() {
    assert_eq!(decode(b"\x89PNG\r\n\x1a\n"), Err(BmpError::NotBmp));
    assert_eq!(decode(&[]), Err(BmpError::NotBmp));
}
