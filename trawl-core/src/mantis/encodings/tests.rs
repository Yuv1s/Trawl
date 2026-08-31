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
    assert_eq!(
        base64_url(b"cXVlc3Rpb24_YW5zd2Vy").unwrap(),
        b"question?answer"
    );
    // Without the distinguishing characters it is ordinary base64, so this
    // declines and lets the standard decoder take it.
    assert!(base64_url(b"SGVsbG8sIHdvcmxkIQ==").is_none());
}

#[test]
fn decodes_base32() {
    assert_eq!(
        base32(b"JBSWY3DPFQQFO33SNRSCC===").unwrap(),
        b"Hello, World!"
    );
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
    assert_eq!(
        hex(b"48656c6c6f2c20776f726c6421").unwrap(),
        b"Hello, world!"
    );
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
    assert_eq!(
        html_entities(b"Tom &amp; Jerry & Co").unwrap(),
        b"Tom & Jerry & Co"
    );
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
    assert!(
        decimal(b"72 101").is_none(),
        "too short to be worth guessing"
    );
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
    assert_eq!(
        rot47(&rot47(b"Hello, world!").unwrap()).unwrap(),
        b"Hello, world!"
    );
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

#[test]
fn refuses_a_long_single_case_run_as_base64() {
    // Eighty lowercase letters are legal base64 and decode to noise. Real
    // base64 output spans both cases and the digits, so words of the right
    // length are the likelier explanation.
    let words = b"qxzjvbkwmpfdghlrntscyaeiouqxzjvbkwmpfdghlrntscyaeiouqxzjvbkwmpfdghlrntscyaeiouxy";
    assert_eq!(words.len() % 4, 0, "the fixture has to be a legal length");
    assert!(base64(words).is_none());

    // Short enough that the case mix proves nothing, so the rule stands aside.
    assert!(looks_encoded(b"aGVsbG8="));
    assert!(looks_encoded(b"abcdefgh"));

    // Real base64 spans the alphabet, so it is unaffected either way.
    assert!(looks_encoded(b"SGVsbG8sIHdvcmxkIQ=="));
    assert_eq!(base64(b"SGVsbG8sIHdvcmxkIQ==").unwrap(), b"Hello, world!");
}

#[test]
fn base58_matches_a_known_vector() {
    // The Bitcoin genesis address. Twenty-five bytes: a zero version byte, the
    // twenty-byte hash, and a four-byte checksum.
    assert_eq!(
        base58(b"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
        Some(vec![
            0x00, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1,
            0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6, 0x51, 0x0d, 0x16, 0x34
        ])
    );
}

#[test]
fn base58_keeps_leading_zeroes() {
    // A leading 1 is a zero byte. A number does not remember its leading
    // zeroes, so they are counted separately or the output comes back short.
    let out = base58(b"11StV1DL6CwTryKyV").expect("declined");

    assert_eq!(&out[..2], &[0, 0]);
    assert_eq!(&out[2..], b"hello world");
}

#[test]
fn base58_declines_its_excluded_letters() {
    // 0, O, I and l are the four left out of the alphabet on purpose.
    assert_eq!(base58(b"1BgGZ9tcN4rm0KBzDn7KprQz87SZ26SAMH"), None);
    assert_eq!(base58(b"1BgGZ9tcN4rmOKBzDn7KprQz87SZ26SAMH"), None);
}

#[test]
fn quoted_printable_decodes_escapes() {
    assert_eq!(
        quoted_printable(b"caf=C3=A9 and cr=C3=A8me"),
        Some("café and crème".as_bytes().to_vec())
    );
}

#[test]
fn quoted_printable_drops_soft_line_breaks() {
    assert_eq!(
        quoted_printable(b"the long line was wrapped=\r\nby the encoder"),
        Some(b"the long line was wrappedby the encoder".to_vec())
    );
}

#[test]
fn quoted_printable_declines_text_that_merely_contains_an_equals() {
    // Otherwise it accepts any sentence with a sum in it and hands it straight
    // back, which the peel would read as progress.
    assert_eq!(quoted_printable(b"two plus two = four, always"), None);
    assert_eq!(quoted_printable(b"trailing escape ="), None);
}

#[test]
fn uuencode_round_trips_a_known_body() {
    // "Cat" is the shortest worked example in the format's own documentation.
    assert_eq!(uuencode(b"#0V%T\n`\nend"), Some(b"Cat".to_vec()));
}

#[test]
fn uuencode_reads_a_full_wrapper() {
    // Length character, body, a zero-length line and the footer. The body
    // alphabet runs from space to backtick, so it contains a backslash.
    let body = "begin 644 message.txt\n3:&5L;&\\@=&AE<F4L('=O<FQD(0  \n`\nend";

    assert_eq!(
        uuencode(body.as_bytes()),
        Some(b"hello there, world!".to_vec())
    );
}

#[test]
fn uuencode_declines_a_line_that_lies_about_its_length() {
    assert_eq!(uuencode(b"M0V%T\n`\nend"), None);
}

#[test]
fn uuencode_declines_a_line_with_extra_bytes_past_its_declared_length() {
    // The length byte only ever promised the four bytes right after it. A
    // Hill or Playfair ciphertext is a long run of uppercase letters with no
    // line breaks in it at all, which becomes exactly this: one "line" whose
    // first letter looks like a length and has plenty of characters
    // following it, without the rest of the string having anything to do
    // with what that byte declared.
    assert_eq!(uuencode(b"#0V%Tsomelongtrailingrunoflettersthatisnotencodeddata"), None);
}

#[test]
fn base36_rotation_carries_letters_into_digits() {
    // The whole point of the wider ring: Y plus eleven leaves the letters.
    assert_eq!(rot_base36(b"Y", 11), b"9".to_vec());
    assert_eq!(rot_base36(b"9", 1), b"A".to_vec());
    assert_eq!(rot_base36(b"Z", 1), b"0".to_vec());
}

#[test]
fn base36_rotation_round_trips() {
    let text = b"YJNUMLUEZATEU=";
    assert_eq!(rot_base36(&rot_base36(text, 11), 25), text.to_vec());
    assert_eq!(rot_base36(b"=", 5), b"=".to_vec());
    assert_eq!(rot_base36(b"a", 0), b"a".to_vec());
}

#[test]
fn base36_rotation_loses_case_across_the_digits() {
    // A digit has no case to remember, so a lowercase letter that rotates onto
    // one comes back uppercase. Nothing can be done about that, and a caller
    // comparing against the original needs to know it.
    assert_eq!(rot_base36(b"y", 11), b"9".to_vec());
    assert_eq!(rot_base36(b"9", 25), b"Y".to_vec());
}

#[test]
fn atbash_is_its_own_inverse() {
    assert_eq!(atbash(b"Hello, World!"), b"Svool, Dliow!".to_vec());
    assert_eq!(
        atbash(&atbash(b"attack at dawn")),
        b"attack at dawn".to_vec()
    );
}
