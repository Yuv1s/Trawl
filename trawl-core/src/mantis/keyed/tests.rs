use super::*;

const PROSE: &[u8] =
    b"the treasure is buried under the old oak tree at the north end of the field \
and the map that shows it is folded inside the cover of the green book on the second shelf";

#[test]
fn applies_a_key_to_a_token_no_scorer_could_confirm() {
    // The case the whole module exists for. Eleven letters is far too few to
    // recover a key from, and the answer is a token that reads like nothing, so
    // every automatic route is closed. Handed the key, it is one step.
    let cipher = vigenere::encipher(b"j2ELwngXTZE", b"sigma");
    let found = with_key(&cipher, "SIGMA");

    let vigenere = found
        .iter()
        .find(|a| a.cipher == "Vigenère")
        .expect("no Vigenère attempt");

    assert_eq!(String::from_utf8_lossy(&vigenere.plaintext), "j2ELwngXTZE");
}

#[test]
fn reports_every_cipher_rather_than_choosing() {
    let found = with_key(b"anything at all", "key");
    let names: Vec<&str> = found.iter().map(|a| a.cipher).collect();

    assert!(names.contains(&"Vigenère"));
    assert!(names.contains(&"Beaufort"));
    assert!(names.contains(&"XOR"));
}

#[test]
fn never_filters_a_supplied_key() {
    // Nothing here reads. It still has to come back, because the person asking
    // is the one who decides.
    let found = with_key(b"qqqq zzzz xxxx", "nonsense");

    assert!(!found.is_empty());
    assert!(found.iter().all(|a| !a.plaintext.is_empty()));
}

#[test]
fn beaufort_is_its_own_inverse() {
    let once = beaufort(PROSE, b"lemon");
    assert_eq!(beaufort(&once, b"lemon"), PROSE);
}

#[test]
fn ignores_punctuation_in_the_key() {
    let plain = with_key(PROSE, "lemon");
    let messy = with_key(PROSE, "L-E-M-O-N!");

    assert_eq!(plain[0].plaintext, messy[0].plaintext);
}

#[test]
fn declines_an_empty_key() {
    assert!(with_key(PROSE, "").is_empty());
    assert!(with_key(PROSE, "1234").is_empty());
}

#[test]
fn the_dictionary_finds_a_key_that_is_in_it() {
    let cipher = vigenere::encipher(PROSE, b"lemon");
    let found = dictionary(&cipher).expect("the wordlist missed its own entry");

    assert_eq!(found.key, "lemon");
    assert_eq!(found.plaintext, PROSE.to_vec());
}

#[test]
fn the_dictionary_declines_a_key_that_is_not() {
    // The ordinary case, and it has to be quiet about it rather than reporting
    // whichever of the 48 read least badly.
    assert_eq!(dictionary(&vigenere::encipher(PROSE, b"zqxjkv")), None);
}

#[test]
fn the_dictionary_declines_text_too_short_to_judge() {
    assert_eq!(
        dictionary(&vigenere::encipher(b"attack at dawn", b"lemon")),
        None
    );
}

#[test]
fn the_dictionary_leaves_plain_english_alone() {
    assert_eq!(dictionary(PROSE), None);
}

#[test]
fn json_carries_the_attempts() {
    let out = json(&with_key(PROSE, "lemon"));

    assert!(out.starts_with('['));
    assert!(out.contains("\"key\":\"lemon\""), "{out}");
    assert!(out.contains("\"cipher\":"), "{out}");
    assert_eq!(json(&[]), "[]");
}

#[test]
fn offers_the_next_layer_when_one_key_was_not_enough() {
    // Two keys, applied in turn. Nothing can recover them separately from the
    // text alone, because enciphering twice is one cipher with a longer key.
    // Given the first, the second is an ordinary problem again.
    let plain: &[u8] =
        b"the museum keeps its oldest maps in a locked room beneath the reading hall, \
where the air is kept dry and the light is kept low, and nobody may bring a pen inside";
    let once = vigenere::encipher(plain, b"lemon");
    let twice = vigenere::encipher(&once, b"kwunkzl");

    let peeled = with_key(&twice, "kwunkzl");
    let vigenere = peeled
        .iter()
        .find(|a| a.cipher == "Vigenère")
        .expect("no Vigenère attempt");

    assert_eq!(vigenere.plaintext, once, "the first layer did not come off");
    assert!(
        vigenere.score < 0.5,
        "this was meant to still be enciphered"
    );
    assert!(
        vigenere.next.iter().any(|d| d.key == b"lemon"),
        "the layer underneath was not offered"
    );
}

#[test]
fn offers_nothing_further_once_the_text_reads() {
    // A second list of keys under a finished answer is noise, and worse, it
    // implies the answer was one option among several.
    let plain: &[u8] =
        b"the treasure is buried under the old oak tree at the north end of the field";
    let cipher = vigenere::encipher(plain, b"lemon");

    let done = with_key(&cipher, "lemon");
    let vigenere = done.iter().find(|a| a.cipher == "Vigenère").unwrap();

    assert_eq!(vigenere.plaintext, plain.to_vec());
    assert!(vigenere.next.is_empty());
}
