use super::*;

/// Test shorthands that pass no configured tags, matching pre-existing callers.
fn solve(data: &[u8]) -> Option<Candidate> {
    super::solve(data, &[])
}

fn derive(data: &[u8]) -> Vec<Derived> {
    super::derive(data, &[])
}

/// Long enough that letter counting has something to count. Short ciphertext is
/// where this attack fails honestly, and the tests should not pretend otherwise.
const PROSE: &[u8] =
    b"the treasure is buried under the old oak tree at the north end of the field \
and you will need a spade and a lantern to find it before the tide comes in again tonight";

fn text(data: &[u8]) -> String {
    String::from_utf8_lossy(data).into_owned()
}

#[test]
fn enciphering_and_deciphering_undo_each_other() {
    let hidden = encipher(PROSE, b"lemon");
    assert_ne!(hidden, PROSE);
    assert_eq!(decipher(&hidden, b"lemon"), PROSE);
}

#[test]
fn leaves_spaces_and_punctuation_where_they_were() {
    let plain = b"attack at dawn, from the north!";
    let hidden = encipher(plain, b"key");

    // The shape survives even though every letter moved.
    assert_eq!(hidden.len(), plain.len());
    for (a, b) in plain.iter().zip(&hidden) {
        assert_eq!(a.is_ascii_alphabetic(), b.is_ascii_alphabetic());
        if !a.is_ascii_alphabetic() {
            assert_eq!(a, b);
        }
    }
    assert_eq!(decipher(&hidden, b"key"), plain);
}

#[test]
fn the_key_advances_only_on_letters() {
    // Counting spaces as key positions gives a decryption that is right for the
    // first word and wrong after it, which is the classic way to get this wrong.
    let plain = b"aaa aaa aaa";
    let hidden = encipher(plain, b"ab");

    assert_eq!(text(&hidden), "aba bab aba");
    assert_eq!(decipher(&hidden, b"ab"), plain);
}

#[test]
fn measures_english_as_lumpier_than_random() {
    // Natural prose, not a pangram. A pangram is deliberately flat, which is
    // the opposite of the property being measured here.
    let english = index_of_coincidence(&letters_of(PROSE));
    assert!(english > 0.06, "English measured {english}");

    let mut state = 0x1234_5678u32;
    let flat: Vec<u8> = (0..400)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            b'a' + (state % 26) as u8
        })
        .collect();

    let random = index_of_coincidence(&flat);
    assert!(random < 0.05, "random measured {random}");
}

#[test]
fn works_out_the_key_length() {
    for key in [b"key".as_slice(), b"lemon".as_slice(), b"cipher".as_slice()] {
        let hidden = encipher(PROSE, key);
        let lengths = key_lengths(&hidden, 20);

        assert!(
            lengths[..3].contains(&key.len()),
            "key {:?} of length {}: got {:?}",
            text(key),
            key.len(),
            &lengths[..5]
        );
    }
}

#[test]
fn solves_without_being_told_anything() {
    for key in [b"key".as_slice(), b"lemon".as_slice(), b"cipher".as_slice()] {
        let hidden = encipher(PROSE, key);
        let found = solve(&hidden).unwrap_or_else(|| panic!("gave up on key {:?}", text(key)));

        assert_eq!(text(&found.key), text(key));
        assert_eq!(found.plaintext, PROSE);
    }
}

#[test]
fn solves_a_key_that_is_a_word_with_repeats() {
    let hidden = encipher(PROSE, b"banana");
    let found = solve(&hidden).expect("gave up");

    assert_eq!(text(&found.key), "banana");
    assert_eq!(found.plaintext, PROSE);
}

#[test]
fn reports_the_shortest_key_rather_than_a_multiple() {
    // A key repeated twice deciphers exactly as well, and the length search
    // often lands on the multiple.
    assert_eq!(shortest_period(b"keykey"), b"key".to_vec());
    assert_eq!(shortest_period(b"abab"), b"ab".to_vec());
    assert_eq!(shortest_period(b"lemon"), b"lemon".to_vec());
}

#[test]
fn leaves_plain_english_alone() {
    // Never enciphered, so there is nothing to solve, and a key of "a" that
    // changes nothing is not a discovery.
    let found = solve(PROSE);
    assert!(
        found.is_none() || found.as_ref().unwrap().key == b"a".to_vec(),
        "claimed key {:?} on plain text",
        found.map(|f| text(&f.key))
    );
}

#[test]
fn reports_nothing_on_random_letters() {
    // The control that matters. Every key length yields some decryption, so a
    // solver with no bar reports a confident answer for pure noise.
    let mut state = 0x2545_f491u32;
    let noise: Vec<u8> = (0..400)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            b'a' + (state % 26) as u8
        })
        .collect();

    assert!(solve(&noise).is_none(), "invented a key for noise");
}

#[test]
fn declines_a_ciphertext_too_short_to_judge() {
    // Letter counting on forty letters is guesswork. Saying so is the honest
    // answer, and the alternative is a confident wrong key.
    let hidden = encipher(b"attack at dawn from the north side", b"key");
    assert!(solve(&hidden).is_none());
}

#[test]
fn an_empty_key_changes_nothing() {
    assert_eq!(encipher(PROSE, b""), PROSE);
    assert_eq!(decipher(PROSE, b""), PROSE);
}

#[test]
fn derives_keys_from_the_text_rather_than_a_list() {
    let prose: &[u8] =
        b"the museum keeps its oldest maps in a locked room beneath the reading hall, \
where the air is kept dry and the light is kept low. visitors are welcome on the first thursday of \
every month, though the archivist asks that nobody bring a pen.";

    let found = derive(&encipher(prose, b"lemon"));

    assert!(!found.is_empty());
    assert_eq!(found[0].key, b"lemon".to_vec());
    assert_eq!(found[0].plaintext, prose.to_vec());
    assert_eq!(found[0].per_column, letters_of(prose).len() / 5);
}

#[test]
fn different_ciphertext_gives_different_keys() {
    // The point of deriving rather than listing. Nothing here is fixed.
    let one = derive(b"attack at dawn on the eastern gate and bring the ladders with you");
    let two = derive(b"the quick brown fox jumps over the lazy dog again and again and again");

    assert_ne!(
        one.iter().map(|d| d.key.clone()).collect::<Vec<_>>(),
        two.iter().map(|d| d.key.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn every_derived_key_reproduces_its_own_plaintext() {
    let found = derive(b"lxfopvefrnhr wlgxjbg pmqsvyzmk qbxrtmkgz vwtszjfkqr");

    assert!(!found.is_empty());
    for derived in &found {
        assert_eq!(
            decipher(
                b"lxfopvefrnhr wlgxjbg pmqsvyzmk qbxrtmkgz vwtszjfkqr",
                &derived.key
            ),
            derived.plaintext
        );
    }
}

#[test]
fn keys_are_unique() {
    let found = derive(b"attack at dawn on the eastern gate and bring the ladders with you");

    let mut keys: Vec<Vec<u8>> = found.iter().map(|d| d.key.clone()).collect();
    let before = keys.len();
    keys.sort();
    keys.dedup();

    assert_eq!(keys.len(), before, "the same key was offered twice");
}

#[test]
fn reports_how_thin_each_column_was() {
    let found = derive(b"attack at dawn on the eastern gate and bring the ladders with you");

    assert!(found.iter().all(|d| d.per_column >= COUNTABLE));
}

#[test]
fn declines_text_with_nothing_to_count() {
    assert!(derive(b"ab").is_empty());
    assert!(derive(b"").is_empty());
}

#[test]
#[ignore]
fn probe_hard_short_keys() {
    let cases: [(&str, &str); 5] = [
        ("welcome to the world", "kwunkzl"),
        ("welcome to the world", "cat"),
        ("the treasure is buried under the old oak tree", "kwunkzl"),
        (
            "the treasure is buried under the old oak tree at dawn tonight",
            "kwunkzl",
        ),
        (
            "attack the eastern gate at dawn and bring every ladder you can find",
            "kwunkzl",
        ),
    ];

    println!(
        "{:<6} {:>7} {:>9}  {:<10} top derived",
        "letters", "keyLen", "perCol", "wanted"
    );
    for (plain, key) in cases {
        let cipher = encipher(plain.as_bytes(), key.as_bytes());
        let letters = letters_of(plain.as_bytes()).len();
        let found = derive(&cipher);
        let at = found.iter().position(|d| d.key == key.as_bytes());

        println!(
            "{letters:<6} {:>7} {:>9.1}  {key:<10} rank={:?} top={:?}",
            key.len(),
            letters as f32 / key.len() as f32,
            at,
            found
                .first()
                .map(|d| String::from_utf8_lossy(&d.key).into_owned())
        );
    }
}

#[test]
#[ignore]
fn probe_solve_score_separation() {
    let cases: [(&str, &str); 7] = [
        ("welcome to the world and everything in it", "cat"),
        ("the treasure is buried under the old oak tree", "kwunkzl"),
        (
            "the treasure is buried under the old oak tree at dawn",
            "lemon",
        ),
        (
            "attack the eastern gate at dawn and bring ladders",
            "security",
        ),
        (
            "attack the eastern gate at dawn and bring every ladder you can",
            "kwunkzl",
        ),
        (
            "the treasure is buried under the old oak tree at dawn",
            "cryptography",
        ),
        (
            "attack the eastern gate at dawn and bring ladders",
            "cryptography",
        ),
    ];

    println!("{:<14} {:>7} {:>8}  verdict", "key", "perCol", "score");
    for (plain, key) in cases {
        let cipher = encipher(plain.as_bytes(), key.as_bytes());
        let n = letters_of(plain.as_bytes()).len();
        match solve(&cipher) {
            Some(c) => {
                let right = c.key == key.as_bytes();
                println!(
                    "{key:<14} {:>7.1} {:>8.3}  {}",
                    n as f32 / key.len() as f32,
                    c.score,
                    if right { "correct" } else { "WRONG" }
                );
            }
            None => println!(
                "{key:<14} {:>7.1} {:>8}  declined",
                n as f32 / key.len() as f32,
                "-"
            ),
        }
    }
}

#[test]
fn recovers_a_seven_letter_key_from_thirty_seven_letters() {
    // Five letters per key position. Counting columns needed twelve and would
    // have declined this outright; climbing judges each key letter by every
    // trigram its letters touch, which is where the extra reach comes from.
    let plain = b"the treasure is buried under the old oak tree";
    let found = solve(&encipher(plain, b"kwunkzl")).expect("nothing came back");

    assert_eq!(found.key, b"kwunkzl".to_vec());
    assert_eq!(found.plaintext, plain.to_vec());
}

#[test]
fn gets_most_of_a_key_where_no_algorithm_can_get_all_of_it() {
    // Seventeen letters, seven letter key, two and a bit letters per position.
    // The exact key is not recoverable and not because the search is weak: the
    // real key scores 2970 in trigrams where a wrong one scores 3042, so the
    // evidence prefers the wrong answer. Reading the words rather than the
    // letters gets within one letter of it, which is close enough to read.
    let found = derive(&encipher(b"welcome to the world", b"kwunkzl"));
    let top = &found[0];

    let wrong = top
        .key
        .iter()
        .zip(b"kwunkzl")
        .filter(|(got, want)| got != want)
        .count();

    assert_eq!(top.key.len(), 7, "found a key of the wrong length");
    assert!(wrong <= 1, "{wrong} letters out, expected at most one");
}

#[test]
fn declines_text_nobody_enciphered() {
    // Both halves of the risk in reaching further down: text that already reads,
    // where a key of almost nothing but A would otherwise "solve" it to itself,
    // and text with no English in it at all.
    for plain in [
        &b"the treasure is buried under the old oak tree"[..],
        b"attack the eastern gate at dawn and bring ladders",
        b"welcome to the world and everything that is in it",
    ] {
        assert_eq!(solve(plain), None, "claimed a key for plain English");
    }

    let mut state = 0x9e3779b97f4a7c15u64;
    let noise: Vec<u8> = (0..90)
        .map(|i| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            if i % 6 == 5 {
                b' '
            } else {
                b'a' + (state.wrapping_mul(0x2545f4914f6cdd1d) % 26) as u8
            }
        })
        .collect();

    assert_eq!(solve(&noise), None, "claimed a key for noise");
}

#[test]
fn a_flag_shape_settles_a_key_no_counting_could_reach() {
    // Eighteen letters and a six letter key is three per position, well under
    // what any statistical attack needs. The braces are the way in: nothing here
    // enciphers punctuation, so the four letters before the brace are a tag, and
    // if they spell "flag" then four of the six key positions fall out by
    // subtraction, leaving two to search exhaustively.
    //
    // The last position is where the evidence runs out. "nello_haman" scores
    // four thousandths above "hello_human" on this much text, so the right key
    // is offered beside the wrong one rather than instead of it.
    let plain = b"fine.. flag{hello_human}";
    let found = derive(&encipher(plain, b"bghfud"));

    let at = found
        .iter()
        .position(|d| d.key == b"bghfud")
        .expect("the crib never reached the key");

    assert!(at < 3, "the key was found but buried at {at}");
    assert_eq!(found[at].plaintext, plain.to_vec());

    assert!(
        String::from_utf8_lossy(&found[at].plaintext).contains("flag{"),
        "the crib lost the tag it pinned"
    );
}

#[test]
fn the_crib_costs_nothing_when_there_is_no_flag() {
    assert!(from_crib(b"the treasure is buried under the old oak tree", &[]).is_empty());
    assert!(from_crib(b"", &[]).is_empty());
}

#[test]
fn a_wrong_crib_is_judged_like_any_other_key() {
    // Braces around something that is not a flag. The crib still fires and still
    // has to earn its place, so nothing is reported.
    let text = b"set x{1} and y{2} then run it twice over and check the output";

    assert_eq!(solve(text), None);
}

#[test]
fn a_whole_tag_settles_a_whole_key_with_nothing_left_to_search() {
    // Twelve letters and a six letter key, two per position. Nothing statistical
    // reaches that. Assuming the seven letters before the brace spell "testCTF"
    // settles all six positions by subtraction, and because seven letters over a
    // six letter key reach one position twice, the assumption had to agree with
    // itself to survive. It did.
    let plain = b"testCTF{hello}";
    let found = derive(&encipher(plain, b"ubuxdq"));

    assert_eq!(found[0].key, b"ubuxdq".to_vec());
    assert_eq!(found[0].plaintext, plain.to_vec());
    assert_eq!(found[0].deduced, 6, "the whole key should be deduced");
    assert!(
        found[0].assumed > found[0].deduced,
        "nothing was actually checked"
    );
}

#[test]
fn a_deduced_key_wins_over_a_readable_wrong_one() {
    // The case that decides how this is ranked. The answer here is leetspeak and
    // reads like nothing, so every score in the module prefers something else.
    // Only the crib knows, and what it knows is checkable.
    let plain = b"testCTF{W3lc0me2DaD@sh}";
    let found = derive(&encipher(plain, b"hmvvvr"));

    assert_eq!(found[0].key, b"hmvvvr".to_vec());
    assert_eq!(found[0].plaintext, plain.to_vec());
    assert!(
        found[0].score < 0.5,
        "this is meant to be the case where reading it does not help"
    );
}

#[test]
fn an_unchecked_crib_does_not_outrank_a_checked_one() {
    // A four letter tag settling a four letter key pins each position once and
    // proves nothing: any four letters would have done it. It must not sit above
    // a longer tag that had to agree with itself.
    let found = derive(&encipher(b"testCTF{hello}", b"ubuxdq"));
    let checked = |d: &Derived| d.assumed > d.deduced;

    assert!(checked(&found[0]), "an unchecked crib led the list");
}

/// Varied English, not one sentence repeated. A repeated sentence gives every
/// column the same letters over and over, which flatters any solver.
const POOL: [&str; 8] = [
    "the museum keeps its oldest maps in a locked room beneath the reading hall",
    "visitors are welcome on the first thursday of every month though the archivist asks that nobody bring a pen",
    "the treasure is buried under the old oak tree at the north end of the field",
    "he got the shape of the bay wrong and the rivers right which tells you something",
    "attack the eastern gate at dawn and bring every ladder you can find in the yard",
    "a map only gives up its detail to somebody willing to sit with it for an hour",
    "the quiet is the point she says because nobody reads a chart in a hurry",
    "drawn by a man who never saw it working from the notes of sailors who had",
];

fn sample(letters: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = seed as usize;
    while letters_of(&out).len() < letters {
        out.extend_from_slice(POOL[at % POOL.len()].as_bytes());
        out.push(b' ');
        at += 1;
    }
    // Trim to roughly the asked-for length, on a word boundary.
    let mut kept = Vec::new();
    for word in out.split(|&b| b == b' ') {
        if letters_of(&kept).len() >= letters {
            break;
        }
        kept.extend_from_slice(word);
        kept.push(b' ');
    }
    kept
}

fn random_key(length: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e3779b97f4a7c15) | 1;
    (0..length)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            b'a' + (state.wrapping_mul(0x2545f4914f6cdd1d) % 26) as u8
        })
        .collect()
}

#[test]
#[ignore]
fn probe_generality() {
    println!(
        "{:>7} {:>7} {:>8}  {:>8} {:>8}",
        "letters", "keyLen", "perCol", "rank 0", "top 3"
    );
    for letters in [40usize, 70, 120, 220] {
        for key_len in [3usize, 5, 8] {
            let (mut first, mut top3) = (0, 0);
            let runs = 6;

            for seed in 0..runs as u64 {
                let plain = sample(letters, seed);
                let key = random_key(key_len, seed + 977);
                let found = derive(&encipher(&plain, &key));

                if found.first().map(|d| d.key == key).unwrap_or(false) {
                    first += 1;
                }
                if found.iter().take(3).any(|d| d.key == key) {
                    top3 += 1;
                }
            }

            println!(
                "{letters:>7} {key_len:>7} {:>8.1}  {first:>4}/{runs:<3} {top3:>4}/{runs:<3}",
                letters as f32 / key_len as f32
            );
        }
    }
}

#[test]
#[ignore]
fn probe_stacked_status() {
    fn lcm(a: usize, b: usize) -> usize {
        let (mut x, mut y) = (a, b);
        while y != 0 {
            let t = y;
            y = x % y;
            x = t;
        }
        a / x * b
    }

    println!(
        "{:>16} {:>10} {:>8} {:>8}  solved",
        "keys", "effective", "letters", "perCol"
    );
    for keys in [
        vec!["cat", "dog"],
        vec!["lemon", "cat"],
        vec!["ab", "cat", "lion"],
        vec!["lemon", "kwunkzl", "ab"],
    ] {
        let effective = keys.iter().fold(1usize, |n, k| lcm(n, k.len()));

        for letters in [200usize, 500, 900, 1400] {
            let plain = sample(letters, 3);
            let mut cipher = plain.clone();
            for key in &keys {
                cipher = encipher(&cipher, key.as_bytes());
            }

            let got = solve(&cipher)
                .map(|c| c.plaintext == plain)
                .unwrap_or(false);
            println!(
                "{:>16} {effective:>10} {:>8} {:>8.1}  {}",
                keys.join("+"),
                letters_of(&plain).len(),
                letters_of(&plain).len() as f32 / effective as f32,
                if got { "yes" } else { "no" }
            );
        }
    }
}
