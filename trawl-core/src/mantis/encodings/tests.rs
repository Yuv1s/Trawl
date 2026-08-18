use super::*;

#[test]
fn decodes_base64() {
    assert_eq!(base64(b"SGVsbG8sIHdvcmxkIQ==").unwrap(), b"Hello, world!");
    // Padding is optional in the wild.
    assert_eq!(base64(b"SGVsbG8sIHdvcmxkIQ").unwrap(), b"Hello, world!");
}

#[test]
fn base64_tolerates_the_line_breaks_of_a_pasted_blob() {
    let wrapped = b"SGVsbG8sIHdv\ncmxkIQ==\n";
    assert_eq!(base64(wrapped).unwrap(), b"Hello, world!");
}

#[test]
fn refuses_base64_that_is_not_base64() {
    assert!(base64(b"not valid base64!!").is_none());
    assert!(base64(b"short").is_none(), "too short to be worth guessing");
    // Padding only ever sits at the end.
    assert!(base64(b"SGVs=bG8sIHdvcmxkIQ").is_none());
}

#[test]
fn refuses_base64_whose_spare_bits_are_not_zero() {
    // Valid alphabet, valid length, but the encoder would never have produced
    // it. Accepting this is how a decoder invents data.
    assert!(base64(b"SGVsbG8sIHdvcmxkIR").is_none());
}

#[test]
fn decodes_the_url_safe_alphabet() {
    assert_eq!(base64_url(b"cXVlc3Rpb24_YW5zd2Vy").unwrap(), b"question?answer");
    // Without the distinguishing characters it is ordinary base64, so this
    // declines and lets the standard decoder take it.
    assert!(base64_url(b"SGVsbG8sIHdvcmxkIQ==").is_none());
}

#[test]
fn decodes_base32() {
    assert_eq!(base32(b"JBSWY3DPFQQFO33SNRSCC===").unwrap(), b"Hello, World!");
    assert!(base32(b"jbswy3dp").is_none(), "base32 is upper case");
}

#[test]
fn decodes_ascii85() {
    assert_eq!(ascii85(b"<~87cURD_*#4DfTZ)+T~>").unwrap(), b"Hello, World!");
    assert_eq!(ascii85(b"87cURD_*#4DfTZ)+T").unwrap(), b"Hello, World!");
}

#[test]
fn ascii85_expands_the_zero_shorthand() {
    assert_eq!(ascii85(b"zzzz87cURD]i,").unwrap()[..16], [0u8; 16]);
}

#[test]
fn decodes_hex_however_it_was_pasted() {
    assert_eq!(hex(b"48656c6c6f2c20776f726c6421").unwrap(), b"Hello, world!");
    assert_eq!(hex(b"48 65 6c 6c 6f 2c 20").unwrap(), b"Hello, ");
    assert_eq!(hex(b"48:65:6c:6c:6f:2c:20").unwrap(), b"Hello, ");
    assert_eq!(hex(b"0x48656c6c6f2c20").unwrap(), b"Hello, ");
}

#[test]
fn refuses_hex_with_an_odd_number_of_digits() {
    assert!(hex(b"48656c6c6f2c20776").is_none());
    assert!(hex(b"48656g6c6f2c2077").is_none(), "g is not a hex digit");
}

#[test]
fn decodes_percent_encoding() {
    assert_eq!(percent(b"hello%2C%20world%21").unwrap(), b"hello, world!");
    assert!(percent(b"nothing encoded here").is_none());
    assert!(percent(b"truncated%2").is_none());
}

#[test]
fn decodes_html_entities() {
    assert_eq!(html_entities(b"a &lt;b&gt; c").unwrap(), b"a <b> c");
    assert_eq!(html_entities(b"&#72;&#105;").unwrap(), b"Hi");
    assert_eq!(html_entities(b"&#x48;&#x69;").unwrap(), b"Hi");
    assert!(html_entities(b"plain text").is_none());
}

#[test]
fn leaves_an_ampersand_that_is_not_an_entity_alone() {
    assert_eq!(html_entities(b"Tom &amp; Jerry & Co").unwrap(), b"Tom & Jerry & Co");
}

#[test]
fn decodes_binary_text() {
    assert_eq!(binary(b"01001000 01101001").unwrap(), b"Hi");
    assert_eq!(binary(b"0100100001101001").unwrap(), b"Hi");
    assert!(binary(b"0100100 01101001").is_none(), "not a whole byte");
    assert!(binary(b"01001002").is_none());
}

#[test]
fn decodes_numbers_written_out() {
    assert_eq!(decimal(b"72 101 108 108 111").unwrap(), b"Hello");
    assert_eq!(decimal(b"72,101,108,108,111").unwrap(), b"Hello");
    assert!(decimal(b"72 101 300").is_none(), "300 is not a byte");
    assert!(decimal(b"72 101").is_none(), "too short to be worth guessing");
}

#[test]
fn rotates_letters_and_leaves_everything_else() {
    assert_eq!(rot13(b"Hello, world!").unwrap(), b"Uryyb, jbeyq!");
    // Thirteen is its own inverse.
    assert_eq!(rot13(&rot13(b"Hello").unwrap()).unwrap(), b"Hello");
    assert!(rot13(b"1234 5678").is_none(), "nothing to rotate");
}

#[test]
fn rot47_covers_the_punctuation_too() {
    assert_eq!(rot47(b"Hello, world!").unwrap(), b"w6==@[ H@C=5P");
    assert_eq!(rot47(&rot47(b"Hello, world!").unwrap()).unwrap(), b"Hello, world!");
}

#[test]
fn decodes_morse() {
    assert_eq!(morse(b".... . .-.. .-.. ---").unwrap(), b"HELLO");
    assert_eq!(morse(b".... .. / - .... . .-. .").unwrap(), b"HI THERE");
    assert!(morse(b"hello").is_none());
    assert!(morse(b"...--- ..").is_none(), "no such code");
}

#[test]
fn every_codec_declines_ordinary_english() {
    // The whole design rests on this. A codec that accepts prose will turn a
    // solved answer back into noise on the next pass.
    let prose = b"the quick brown fox jumps over the lazy dog";

    assert!(base64(prose).is_none());
    assert!(base32(prose).is_none());
    assert!(hex(prose).is_none());
    assert!(binary(prose).is_none());
    assert!(decimal(prose).is_none());
    assert!(percent(prose).is_none());
    assert!(html_entities(prose).is_none());
    assert!(morse(prose).is_none());
}
