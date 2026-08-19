use super::*;

const PROSE: &[u8] =
    b"the treasure is buried under the old oak tree at the north end of the field \
and the map that shows it is folded inside the cover of the green book on the second shelf";

#[test]
fn counts_every_letter_and_nothing_else() {
    let table = table(b"Ab, c! a?");

    assert_eq!(table.total, 4);
    assert_eq!(table.letters.len(), 26);
    assert_eq!(table.letters[0].count, 2);
    assert_eq!(table.letters[1].count, 1);
    assert_eq!(table.letters[2].count, 1);
    assert_eq!(table.letters[3].count, 0);
}

#[test]
fn shares_add_up() {
    let table = table(PROSE);
    let total: f32 = table.letters.iter().map(|l| l.share).sum();

    assert!((total - 100.0).abs() < 0.1, "shares summed to {total}");
}

#[test]
fn empty_text_does_not_divide_by_zero() {
    let table = table(b"!!!");

    assert_eq!(table.total, 0);
    assert!(table.letters.iter().all(|l| l.share == 0.0));
    assert!(table.bigrams.is_empty());
    assert!(table.trigrams.is_empty());
}

#[test]
fn english_leans_on_e_and_t() {
    let table = table(PROSE);
    let mut ranked = table.letters.clone();
    ranked.sort_by_key(|l| core::cmp::Reverse(l.count));

    assert_eq!(ranked[0].letter, b'E');
    assert!(ranked[..4].iter().any(|l| l.letter == b'T'));
}

#[test]
fn finds_the_repeats_that_matter() {
    let table = table(PROSE);

    // THE is the commonest trigram in English and this sentence is no exception.
    assert_eq!(table.trigrams[0].text, b"THE".to_vec());
    assert!(table.trigrams[0].count >= 6);
}

#[test]
fn reports_only_runs_that_actually_repeat() {
    let table = table(PROSE);

    assert!(table.bigrams.iter().all(|r| r.count > 1));
    assert!(table.trigrams.iter().all(|r| r.count > 1));
}

#[test]
fn coincidence_separates_one_alphabet_from_several() {
    let plain = table(PROSE).coincidence;

    // Vigenère spreads the text across as many alphabets as the key is long,
    // which flattens the counts and drags this down towards 0.038.
    let enciphered = table(&crate::mantis::vigenere::encipher(PROSE, b"palimpsest")).coincidence;

    assert!(plain > 0.06, "English measured {plain}");
    assert!(enciphered < plain, "{enciphered} should sit below {plain}");
}

#[test]
fn json_reports_every_letter() {
    let out = json(PROSE);

    assert!(out.contains("\"total\":"), "{out}");
    assert!(out.contains("\"coincidence\":"), "{out}");
    assert!(out.contains("\"letter\":\"A\""), "{out}");
    assert!(out.contains("\"letter\":\"Z\""), "{out}");
    assert!(out.contains("\"english\":12.702"), "{out}");
}
