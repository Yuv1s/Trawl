use super::*;

fn peeled(input: &str) -> Peel {
    peel(input.as_bytes())
}

fn text(peel: &Peel) -> String {
    String::from_utf8_lossy(&peel.result).into_owned()
}

fn names(peel: &Peel) -> Vec<&str> {
    peel.steps.iter().map(|s| s.encoding).collect()
}

#[test]
fn scores_prose_above_an_encoded_blob() {
    let prose = plainness(b"the quick brown fox jumps over the lazy dog");
    let blob = plainness(b"dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==");

    assert!(prose > blob, "prose {prose} should beat base64 {blob}");
    assert!(prose > 0.5, "prose scored only {prose}");
}

#[test]
fn scores_binary_noise_lowest() {
    let noise: Vec<u8> = (0..200u32)
        .map(|i| (i.wrapping_mul(7919) % 256) as u8)
        .collect();
    assert!(
        plainness(&noise) < 0.35,
        "noise scored {}",
        plainness(&noise)
    );
}

#[test]
fn peels_a_single_layer() {
    let found = peeled("dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==");

    assert_eq!(names(&found), vec!["base64"]);
    assert_eq!(text(&found), "the quick brown fox jumps over the lazy dog");
}

#[test]
fn peels_a_chain_all_the_way_down() {
    // base64 of hex of the message, which is the shape of a real challenge.
    let message = "meet me at the docks at midnight";
    let as_hex: String = message.bytes().map(|b| format!("{b:02x}")).collect();

    let mut encoded = String::new();
    let raw = as_hex.as_bytes();
    for chunk in raw.chunks(3) {
        let mut buffer = [0u8; 3];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let n = u32::from_be_bytes([0, buffer[0], buffer[1], buffer[2]]);
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for i in 0..4 {
            if i <= chunk.len() {
                encoded.push(alphabet[((n >> (18 - i * 6)) & 63) as usize] as char);
            } else {
                encoded.push('=');
            }
        }
    }

    let found = peeled(&encoded);
    assert_eq!(text(&found), message);
    assert_eq!(names(&found), vec!["base64", "hex"]);
}

#[test]
fn stops_when_it_reaches_the_answer() {
    let found = peeled("dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==");

    // The answer is valid input to several codecs. Peeling past it would take a
    // readable sentence and return noise.
    assert_eq!(found.steps.len(), 1);
    assert!(found.score > 0.5);
}

#[test]
fn leaves_plain_english_completely_alone() {
    for prose in [
        "the quick brown fox jumps over the lazy dog",
        "meet me at the docks at midnight and bring the money",
        "this is an ordinary sentence with nothing hidden in it at all",
    ] {
        let found = peeled(prose);
        assert!(
            found.steps.is_empty(),
            "peeled {:?} into {:?} via {:?}",
            prose,
            text(&found),
            names(&found)
        );
        assert_eq!(text(&found), prose);
    }
}

#[test]
fn leaves_random_noise_alone() {
    // Nothing here decodes to anything readable, so nothing should be claimed.
    let mut state = 0x2545f491u32;
    let noise: String = (0..80)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            char::from(b'a' + (state % 26) as u8)
        })
        .collect();

    let found = peeled(&noise);
    assert!(
        found.steps.is_empty(),
        "invented {:?} out of noise",
        names(&found)
    );
}

#[test]
fn takes_a_flag_as_the_end_of_the_road() {
    let flag = "flag{peeled_all_the_way}";
    let encoded: String = flag.bytes().map(|b| format!("{b:02x}")).collect();

    let found = peeled(&encoded);
    assert_eq!(text(&found), flag);
    assert!(found.steps.last().unwrap().reason.contains("flag shape"));
}

#[test]
fn accepts_a_flag_even_when_it_reads_like_nothing() {
    // Underscores and braces score badly as English. Letting frequency veto a
    // flag would be absurd, so a flag shape overrides the score.
    let flag = "flag{x_y_z_q_j_k}";
    let encoded: String = flag.bytes().map(|b| format!("{b:02x}")).collect();

    assert_eq!(text(&peeled(&encoded)), flag);
}

#[test]
fn recognises_a_file_that_falls_out_of_a_decode() {
    // base64 of a PNG header, which is how a whole file arrives pasted in chat.
    let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut encoded = String::new();
    for chunk in png.chunks(3) {
        let mut buffer = [0u8; 3];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let n = u32::from_be_bytes([0, buffer[0], buffer[1], buffer[2]]);
        for i in 0..4 {
            if i <= chunk.len() {
                encoded.push(alphabet[((n >> (18 - i * 6)) & 63) as usize] as char);
            } else {
                encoded.push('=');
            }
        }
    }

    let found = peeled(&encoded);
    assert!(found.result.starts_with(b"\x89PNG"));
    assert!(found.steps.last().unwrap().reason.contains("PNG"));
}

#[test]
fn solves_a_rotation_without_being_told_the_shift() {
    // Caesar by another name. Every shift decodes, so only the result can say
    // which one was meant.
    let shifted = encodings::rot_n(b"attack at dawn from the north side", 7);
    let found = peel(&shifted);

    assert_eq!(text(&found), "attack at dawn from the north side");
}

#[test]
fn peels_morse() {
    let found = peeled(".... . .-.. .-.. --- / - .... . .-. .");
    assert_eq!(text(&found), "HELLO THERE");
}

#[test]
fn peels_binary_text() {
    let message = "attack at dawn";
    let encoded: String = message
        .bytes()
        .map(|b| format!("{b:08b}"))
        .collect::<Vec<_>>()
        .join(" ");

    assert_eq!(text(&peeled(&encoded)), message);
}

#[test]
fn never_runs_away_on_a_rotation_that_undoes_itself() {
    // ROT13 twice is the identity, so a peeler that does not track where it has
    // been will bounce between two states until it hits the depth limit.
    let found = peeled("Gur dhvpx oebja sbk whzcf bire gur ynml qbt");

    assert_eq!(text(&found), "The quick brown fox jumps over the lazy dog");
    assert!(found.steps.len() <= 2, "took {} steps", found.steps.len());
}

#[test]
fn stops_at_the_depth_limit_rather_than_forever() {
    // Deeply nested, so the guard is what ends it rather than success.
    // Six rounds, not twenty: hex doubles the length each time, so twenty would
    // build a fourteen-megabyte string and the test would be measuring that
    // rather than the guard.
    let mut encoded = "attack at dawn".to_string();
    for _ in 0..6 {
        encoded = encoded.bytes().map(|b| format!("{b:02x}")).collect();
    }

    let found = peeled(&encoded);
    assert!(found.steps.len() <= 8, "ran {} deep", found.steps.len());
}

#[test]
fn reports_an_empty_input_without_falling_over() {
    let found = peel(b"");
    assert!(found.steps.is_empty());
    assert_eq!(found.score, 0.0);
}

#[test]
fn json_is_shaped_for_the_worker() {
    let out = json(b"dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==");

    assert!(out.contains("\"depth\":1"), "{out}");
    assert!(out.contains("\"encoding\":\"base64\""), "{out}");
    assert!(out.contains("the quick brown fox"), "{out}");
}

#[test]
fn json_reports_a_string_it_could_not_peel() {
    let out = json(b"the quick brown fox jumps over the lazy dog");
    assert!(out.contains("\"depth\":0"), "{out}");
    assert!(out.contains("\"steps\":[]"), "{out}");
}

#[test]
fn attacks_the_cipher_hiding_under_an_encoding() {
    // Hex around XOR, which is how these are actually built: the cipher output
    // is unreadable bytes, so it gets wrapped to survive being pasted.
    let message = b"the treasure is buried under the old oak tree at the north end";
    let encrypted = xor::apply(message, b"KEY");
    let wrapped: String = encrypted.iter().map(|b| format!("{b:02x}")).collect();

    let reading = read(wrapped.as_bytes());

    assert_eq!(
        reading
            .peel
            .steps
            .iter()
            .map(|s| s.encoding)
            .collect::<Vec<_>>(),
        vec!["hex"],
        "the wrapper should come off first"
    );

    let found = reading
        .xor
        .repeating
        .expect("the cipher underneath was missed");
    assert_eq!(found.key, b"KEY".to_vec());
    assert_eq!(found.plaintext, message.to_vec());
}

#[test]
fn does_not_attack_something_the_peel_already_solved() {
    // The answer is in hand, so running a cipher attack over it would only
    // produce noise with a confident label on it.
    let reading = read(b"dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==");

    assert_eq!(
        reading.peel.result,
        b"the quick brown fox jumps over the lazy dog"
    );
    assert!(!reading.xor.found());
}

#[test]
fn finds_a_single_byte_key_in_a_pasted_string() {
    let flag = b"flag{xor_is_not_encryption}";
    let encrypted = xor::apply(flag, &[0x5a]);
    let wrapped: String = encrypted.iter().map(|b| format!("{b:02x}")).collect();

    let reading = read(wrapped.as_bytes());
    let found = &reading.xor.single;

    assert!(!found.is_empty(), "nothing came back");
    assert_eq!(found[0].plaintext, flag.to_vec());
    assert_eq!(found[0].key, vec![0x5a]);
}

#[test]
fn stays_quiet_on_a_string_with_nothing_in_it() {
    let reading = read(b"this is an ordinary sentence with nothing hidden in it");
    assert!(reading.peel.steps.is_empty());
    assert!(!reading.xor.found());
}

#[test]
fn json_carries_the_cipher_alongside_the_chain() {
    let encrypted = xor::apply(b"meet me at the docks at midnight tonight", &[0x33]);
    let wrapped: String = encrypted.iter().map(|b| format!("{b:02x}")).collect();

    let out = json(wrapped.as_bytes());
    assert!(out.contains("\"encoding\":\"hex\""), "{out}");
    assert!(out.contains("\"kind\":\"single byte\""), "{out}");
    assert!(out.contains("meet me at the docks"), "{out}");
}

#[test]
fn leaves_a_hash_alone_instead_of_unwrapping_it() {
    // Thirty-two hex digits decode perfectly into sixteen bytes of noise, and
    // the structural unwrap used to do exactly that and present the noise.
    for digest in [
        "5d41402abc4b2a76b9719d911017c592",
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    ] {
        let reading = read(digest.as_bytes());

        assert!(reading.peel.steps.is_empty(), "unwrapped {digest}");
        assert_eq!(reading.peel.result, digest.as_bytes());
        assert!(reading.hash.is_some(), "did not recognise {digest}");
        assert!(!reading.xor.found(), "attacked a digest");
    }
}

#[test]
fn names_a_hash_without_pretending_to_know_which() {
    let reading = read(b"5d41402abc4b2a76b9719d911017c592");
    let hash = reading.hash.expect("not recognised");

    assert!(
        hash.candidates.len() > 1,
        "shape alone cannot narrow to one"
    );
    assert!(!hash.certain);
}

#[test]
fn json_carries_the_hash_when_there_is_one() {
    let out = json(b"$2b$12$GhvMmNVjRW29ulnudl.LbuAnUtN/LRfe1JsBm1Xu6LE3059z5Tr8m");
    assert!(out.contains("\"hash\":{"), "{out}");
    assert!(out.contains("\"bcrypt\""), "{out}");
    assert!(out.contains("\"depth\":0"), "{out}");

    let plain = json(b"the quick brown fox jumps over the lazy dog");
    assert!(plain.contains("\"hash\":null"), "{plain}");
}

#[test]
fn finds_a_rail_fence_end_to_end() {
    let message = b"the treasure is buried under the old oak tree at the north end of the field";
    let reading = read(&transposition::rail_encipher(message, 4));

    let found = reading.transposition.expect("the transposition was missed");
    assert_eq!(found.shape, transposition::Shape::RailFence { rails: 4 });
    assert_eq!(found.plaintext, message.to_vec());
}

#[test]
fn finds_an_affine_end_to_end() {
    let message = b"the treasure is buried under the old oak tree at the north end of the field";
    let reading = read(&affine::encipher(message, 7, 11));

    let found = reading.affine.expect("the affine cipher was missed");
    assert_eq!((found.a, found.b), (7, 11));
    assert_eq!(found.plaintext, message.to_vec());
}

#[test]
fn finds_a_substitution_end_to_end() {
    let message: &[u8] = b"the museum keeps its oldest maps in a locked room beneath the reading \
hall, where the air is kept dry and the light is kept low. visitors are welcome on the first \
thursday of every month, though the archivist asks that nobody bring a pen.";
    let key = [
        7, 22, 4, 19, 0, 25, 11, 14, 8, 23, 17, 3, 20, 9, 15, 5, 24, 1, 12, 18, 6, 21, 16, 2, 13,
        10,
    ];

    let reading = read(&substitution::encipher(message, &key));

    let found = reading.substitution.expect("the substitution was missed");
    assert_eq!(found.plaintext, message.to_vec());
}

#[test]
fn does_not_run_the_new_attacks_on_text_that_already_reads() {
    // Every one of these produces some answer for any input. Running them over
    // something already readable is how a tool starts contradicting itself.
    let reading = read(b"the quick brown fox jumps over the lazy dog and keeps going");

    assert_eq!(reading.affine, None);
    assert_eq!(reading.transposition, None);
    assert_eq!(reading.substitution, None);
}

#[test]
fn json_carries_every_attack() {
    let out = json(b"the quick brown fox jumps over the lazy dog");

    for key in ["\"affine\":", "\"transposition\":", "\"substitution\":"] {
        assert!(out.contains(key), "{key} missing from {out}");
    }
}

#[test]
#[ignore]
fn probe_bars() {
    let message: &[u8] = b"the museum keeps its oldest maps in a locked room beneath the reading hall, where the air is kept dry and the light is kept low. visitors are welcome on the first thursday of every month, though the archivist asks that nobody bring a pen.";
    let key = [
        7, 22, 4, 19, 0, 25, 11, 14, 8, 23, 17, 3, 20, 9, 15, 5, 24, 1, 12, 18, 6, 21, 16, 2, 13,
        10,
    ];

    let mut state = 0x9e3779b97f4a7c15u64;
    let noise: Vec<u8> = (0..300)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let n = state.wrapping_mul(0x2545f4914f6cdd1d) % 27;
            if n == 26 { b' ' } else { b'a' + n as u8 }
        })
        .collect();

    let inputs = [
        ("plain", message.to_vec()),
        ("railfence", transposition::rail_encipher(message, 4)),
        (
            "columnar",
            transposition::columnar_encipher(message, &[2, 0, 4, 1, 3]),
        ),
        ("affine", affine::encipher(message, 7, 11)),
        ("substitution", substitution::encipher(message, &key)),
        ("noise", noise),
    ];

    println!(
        "{:<14} {:>8} {:>8} {:>8} {:>8}",
        "input", "plain", "affine", "transp", "subst"
    );
    for (label, text) in &inputs {
        let a = affine::solve(text).map_or(0.0, |c| c.score);
        let t = transposition::solve(text).map_or(0.0, |c| c.score);
        let u = substitution::solve(text).map_or(0.0, |c| c.score);
        println!(
            "{label:<14} {:>8.3} {a:>8.3} {t:>8.3} {u:>8.3}",
            plainness(text)
        );
    }
}

#[test]
fn transposed_english_is_not_mistaken_for_readable() {
    // The regression that matters. Rearranging English leaves the letter mix
    // exactly English and the spacing untouched, so a scorer that weighs those
    // heavily calls the result readable and every attack is skipped. Detection
    // then depends on which sentence you happened to paste.
    let message = b"the museum keeps its oldest maps in a locked room beneath the reading hall, where the air is kept dry and the light is kept low. visitors are welcome on the first thursday";

    for rails in 3..=6 {
        let scrambled = transposition::rail_encipher(message, rails);
        let score = plainness(&scrambled);

        assert!(
            score < 0.5,
            "{rails} rails scored {score}, which reads as already solved"
        );

        let found = read(&scrambled)
            .transposition
            .unwrap_or_else(|| panic!("{rails} rails was skipped"));
        assert_eq!(found.plaintext, message.to_vec(), "{rails} rails");
    }
}

#[test]
fn a_frequency_table_comes_back_for_anything() {
    // Reported whether or not an attack landed, so the panel always has
    // something honest to show.
    for text in [
        &b"the quick brown fox jumps over the lazy dog"[..],
        b"!!!!",
        b"",
    ] {
        let table = frequency::table(text);
        assert_eq!(table.letters.len(), 26);
    }
}

#[test]
fn stops_at_a_token_rather_than_unwrapping_it_into_noise() {
    // The case that exposed this: a flag that is a random token rather than a
    // sentence. Such a token is valid base64 by accident, so a peeler that
    // treats "decodes" as "is encoded" walks straight past the answer and hands
    // back the noise underneath.
    let token = b"j2ELwngXTZE";
    let wrapped = encodings::base64_of(token);

    let peeled = peel(&wrapped);
    assert_eq!(
        String::from_utf8_lossy(&peeled.result),
        String::from_utf8_lossy(token),
        "peeled {:?} instead of stopping",
        peeled.steps.iter().map(|s| s.encoding).collect::<Vec<_>>()
    );
}

#[test]
fn still_unwraps_base64_that_arrives_in_whole_groups() {
    // The other half of the same rule. Padding and a length that divides by
    // four are what make the reading justified rather than merely possible, and
    // that has to keep working on text nobody can read.
    let secret = xor::apply(b"the treasure is buried under the old oak tree", b"KEY");
    let wrapped = encodings::base64_of(&secret);

    let reading = read(&wrapped);
    assert_eq!(
        reading.peel.steps.first().map(|s| s.encoding),
        Some("base64"),
        "the wrapper should still come off a cipher"
    );
    assert!(reading.xor.found(), "the cipher underneath was missed");
    assert!(
        reading
            .xor
            .best_first()
            .iter()
            .any(|(_, c)| c.plaintext == b"the treasure is buried under the old oak tree"),
        "the key came back but the message did not"
    );
}

#[test]
#[ignore]
fn probe_letter_density() {
    let english: &[u8] = b"the treasure is buried under the old oak tree at the north end";
    let samples: [(&str, Vec<u8>); 5] = [
        ("english", english.to_vec()),
        ("xor ciphertext", xor::apply(english, b"KEY")),
        ("base64 blob", encodings::base64_of(english)),
        (
            "hex string",
            english
                .iter()
                .flat_map(|b| format!("{b:02x}").into_bytes())
                .collect(),
        ),
        ("random token", b"j2ELwngXTZE".to_vec()),
    ];

    for (label, data) in samples {
        let printable = data.iter().filter(|&&b| (0x20..0x7f).contains(&b)).count();
        let letters = data.iter().filter(|b| b.is_ascii_alphabetic()).count();
        println!(
            "{label:16} letters/printable = {:.2}  ({letters}/{printable})  plainness={:.3}",
            letters as f32 / printable.max(1) as f32,
            plainness(&data)
        );
    }
}

#[test]
fn hands_over_the_shortlist_when_nothing_reads() {
    // The user's case: a random token, wrapped, then rotated over a wider
    // alphabet than Trawl rotates by default. Nothing here reads as English at
    // any depth, so no attack can decide it, and the right answer is still one
    // line of a list a person can scan.
    let reading = read(b"YTAPV4O8YA4616NDT5======");

    assert!(!reading.shortlist.is_empty(), "nothing was offered");
    assert_eq!(reading.shortlist[0].how, "base36 +25");

    let chain = reading.shortlist[0].then.as_ref().expect("led nowhere");
    assert_eq!(String::from_utf8_lossy(&chain.result), "j2ELwngXTZE");
}

#[test]
fn does_not_offer_a_shortlist_when_something_did_read() {
    // Sixty guesses printed under a solved cipher is noise, and it undercuts
    // the answer by implying it was one option among many.
    let solved = read(&transposition::rail_encipher(
        b"the treasure is buried under the old oak tree at the north end of the field",
        4,
    ));

    assert!(solved.transposition.is_some());
    assert!(solved.shortlist.is_empty());
}

#[test]
#[ignore]
fn probe_reported_false_positive() {
    let pasted = b"NIZEKTDXNZTVQVC2IU======j2ELwngXTZE";
    let r = read(pasted);

    println!("plainness of input {:.3}", plainness(pasted));
    println!(
        "peel steps {:?}",
        r.peel.steps.iter().map(|s| s.encoding).collect::<Vec<_>>()
    );
    println!("shortlist  {} readings", r.shortlist.len());

    for (kind, c) in r.xor.best_first() {
        println!(
            "xor {kind} key={} score={:.3} plainness={:.3} text={:?}",
            c.key_text(),
            c.score,
            plainness(&c.plaintext),
            String::from_utf8_lossy(&c.plaintext)
        );
    }
}

#[test]
#[ignore]
fn probe_word_fit_by_length() {
    fn shares(data: &[u8]) -> (f32, f32) {
        let text = core::str::from_utf8(data).unwrap_or("");
        let (mut tok, mut tok_hit, mut ch, mut ch_hit) = (0f32, 0f32, 0f32, 0f32);

        for token in text.split_whitespace() {
            let word: String = token
                .chars()
                .filter(|c| c.is_ascii_alphabetic())
                .flat_map(|c| c.to_lowercase())
                .collect();
            if word.is_empty() {
                continue;
            }
            tok += 1.0;
            ch += word.len() as f32;
            if COMMON.contains(&word.as_str()) {
                tok_hit += 1.0;
                ch_hit += word.len() as f32;
            }
        }
        (tok_hit / tok.max(1.0), ch_hit / ch.max(1.0))
    }

    let samples: [(&str, &[u8]); 4] = [
        ("english prose", b"the treasure is buried under the old oak tree at the north end of the field and the map that shows it is folded inside the cover of the green book"),
        ("english short", b"the quick brown fox jumps over the lazy dog"),
        ("the xor garbage", b"\\TGX@FYESQFKLKH TH 6/   a XQjeuEIGN"),
        ("one letter only", b"zzzz a qqqq wwww"),
    ];

    println!("{:<18} {:>10} {:>10}", "sample", "by token", "by letter");
    for (label, data) in samples {
        let (t, c) = shares(data);
        println!("{label:<18} {t:>10.3} {c:>10.3}");
    }
}

#[test]
fn a_wordlist_key_is_found_where_the_columns_are_too_thin_to_climb() {
    // The window the wordlist still owns. A twelve letter key over forty-one
    // letters leaves three and a half letters per position, which is below what
    // climbing can reach, so recovery declines. Guessing is all that is left,
    // and there is still enough text to know a guess landed.
    let message = b"attack the eastern gate at dawn and bring ladders";
    let cipher = vigenere::encipher(message, b"cryptography");

    assert!(
        vigenere::solve(&cipher).is_none(),
        "recovery got there alone"
    );

    let found = read(&cipher)
        .dictionary
        .expect("the wordlist missed its own entry");
    assert_eq!(found.key, "cryptography");
    assert_eq!(found.plaintext, message.to_vec());
}

#[test]
fn no_wordlist_guess_when_the_text_gave_up_its_own_key() {
    // Guessing after a real recovery would offer a worse answer alongside a
    // better one, and leave the reader to tell which was which.
    let message = b"the treasure is buried under the old oak tree at the north end of the field \
and the map that shows it is folded inside the cover of the green book on the second shelf";

    let reading = read(&vigenere::encipher(message, b"palimpsest"));

    assert!(reading.vigenere.is_some(), "the real recovery failed");
    assert!(reading.dictionary.is_none());
}

#[test]
#[ignore]
fn probe_layered_vigenere() {
    fn b64(data: &[u8]) -> Vec<u8> {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        for chunk in data.chunks(3) {
            let mut n = 0u32;
            for (i, &b) in chunk.iter().enumerate() {
                n |= (b as u32) << (16 - 8 * i);
            }
            for i in 0..4 {
                out.push(if i <= chunk.len() {
                    A[((n >> (18 - 6 * i)) & 63) as usize]
                } else {
                    b'='
                });
            }
        }
        out
    }

    let prose: &[u8] =
        b"the treasure is buried under the old oak tree at the north end of the field";

    for (label, built) in [
        ("vigenere only", vigenere::encipher(prose, b"key")),
        (
            "base64 over vigenere",
            b64(&vigenere::encipher(prose, b"key")),
        ),
        ("hex over base64 over vigenere", {
            let inner = b64(&vigenere::encipher(prose, b"key"));
            inner
                .iter()
                .flat_map(|b| format!("{b:02x}").into_bytes())
                .collect()
        }),
    ] {
        let r = read(&built);
        println!(
            "{label:32} steps={:?} dict={:?} vig={:?}",
            r.peel.steps.iter().map(|s| s.encoding).collect::<Vec<_>>(),
            r.dictionary.as_ref().map(|a| a.key.clone()),
            r.vigenere
                .as_ref()
                .map(|v| String::from_utf8_lossy(&v.key).into_owned())
        );
    }
}

#[test]
fn every_reading_offers_keys_worked_out_of_the_text() {
    let out = json(b"lxfopvefrnhr wlgxjbg pmqsvyzmk qbxrtmkgz vwtszjfkqr");

    assert!(out.contains("\"derivedKeys\":[{"), "{out}");
    assert!(out.contains("\"perColumn\":"), "{out}");
}

#[test]
fn the_offered_keys_come_from_the_ciphertext_not_a_list() {
    // Two different texts, two different sets of keys. Nothing is fixed.
    let keys = |data: &[u8]| {
        read(data)
            .derived
            .iter()
            .map(|d| String::from_utf8_lossy(&d.key).into_owned())
            .collect::<Vec<_>>()
    };

    let one = keys(&vigenere::encipher(
        b"attack at dawn on the eastern gate and bring the ladders with you",
        b"lemon",
    ));
    let two = keys(&vigenere::encipher(
        b"the quick brown fox jumps over the lazy dog again and again and again",
        b"lemon",
    ));

    assert!(!one.is_empty());
    assert_ne!(one, two);
}

#[test]
fn the_top_offered_key_is_the_real_one_when_the_text_allows() {
    let prose: &[u8] = b"the museum keeps its oldest maps in a locked room beneath the reading hall, where the air is kept dry and the light is kept low. visitors are welcome on the first thursday of every month, though the archivist asks that nobody bring a pen.";

    let reading = read(&vigenere::encipher(prose, b"lemon"));

    assert_eq!(reading.derived[0].key, b"lemon".to_vec());
    assert_eq!(reading.derived[0].plaintext, prose.to_vec());
}

#[test]
#[ignore]
fn probe_letters_per_column() {
    let base: &[u8] =
        b"the treasure is buried under the old oak tree at the north end of the field \
and the map that shows it is folded inside the cover of the green book on the second shelf. ";

    println!("keyLen letters perColumn exact");
    for key in [
        b"lemon".to_vec(),
        b"palimpsest".to_vec(),
        b"cryptographic".to_vec(),
    ] {
        for repeats in [1usize, 2, 3, 4, 6, 8] {
            let prose: Vec<u8> = base.repeat(repeats);
            let letters = crate::mantis::ngram::letters(&prose).len();
            let built = vigenere::encipher(&prose, &key);
            let exact = vigenere::solve(&built)
                .map(|c| c.plaintext == prose)
                .unwrap_or(false);
            println!(
                "{:6} {letters:7} {:9.1} {exact}",
                key.len(),
                letters as f32 / key.len() as f32
            );
        }
    }
}

#[test]
fn recovers_keys_of_several_lengths_from_varied_prose() {
    // Varied prose rather than one sentence repeated. A repeated sentence gives
    // every column the same letters over and over, which is not English and can
    // make a multiple of the key look as good as the key.
    let varied: &[u8] = b"the museum keeps its oldest maps in a locked room beneath the reading hall, where the air is kept dry and the light is kept low. visitors are welcome on the first thursday of every month, though the archivist asks that nobody bring a pen. the quiet is the point, she says, because a map only gives up its detail to somebody willing to sit with it for an hour. the oldest sheet in the collection shows a coastline that no longer exists, drawn by a man who never saw it, working from the notes of sailors who had. he got the shape of the bay wrong and the rivers right, which tells you something about what those sailors thought worth describing to a stranger.";

    for key in [&b"key"[..], b"lemon", b"palimpsest"] {
        let built = vigenere::encipher(varied, key);
        let found = vigenere::solve(&built);
        let found =
            found.unwrap_or_else(|| panic!("{:?} was missed", String::from_utf8_lossy(key)));
        assert_eq!(found.key, key.to_vec());
        assert_eq!(found.plaintext, varied.to_vec());
    }
}

#[test]
fn undoes_vigenere_stacked_three_deep() {
    // Stacking does not make a new cipher. Enciphering three times with keys of
    // three, five and two letters is one Vigenère whose key is the lowest common
    // multiple of them, thirty letters long, and a thirty letter key is an
    // ordinary key given text to find it in.
    let base: &[u8] = b"the museum keeps its oldest maps in a locked room beneath the reading hall, where the air is kept dry and the light is kept low. visitors are welcome on the first thursday of every month, though the archivist asks that nobody bring a pen. the quiet is the point, she says, because a map only gives up its detail to somebody willing to sit with it for an hour. ";
    // Thirty columns need roughly twenty-five letters each before they can be
    // counted, so this needs to be a page rather than a paragraph.
    let prose = base.repeat(3);

    let stacked = vigenere::encipher(
        &vigenere::encipher(&vigenere::encipher(&prose, b"key"), b"lemon"),
        b"ab",
    );

    let found = read(&stacked).vigenere.expect("three layers defeated it");
    assert_eq!(found.key.len(), 30, "expected the combined key");
    assert_eq!(found.plaintext, prose);
}

#[test]
fn refuses_a_long_key_it_has_no_text_to_find() {
    // The other half of the same rule. Thirty columns of four letters each is
    // not a search, it is a confident wrong answer waiting to happen.
    let short: &[u8] =
        b"the treasure is buried under the old oak tree at the north end of the field";
    let stacked = vigenere::encipher(
        &vigenere::encipher(&vigenere::encipher(short, b"key"), b"lemon"),
        b"ab",
    );

    assert!(read(&stacked).vigenere.is_none());
}

#[test]
#[ignore]
fn probe_enciphered_flag() {
    let cipher = b"gouj.. zobm{ojfop_nbruq}";
    let r = read(cipher);

    println!("conclusive  {:?}", conclusive(cipher));
    println!("plainness   {:.3}", plainness(cipher));
    println!("derived     {} keys", r.derived.len());
    println!("vigenere    {:?}", r.vigenere.is_some());
    println!("letters     {}", ngram::letters(cipher).len());
    println!("direct derive -> {} keys", vigenere::derive(cipher).len());
    for d in vigenere::derive(cipher).iter().take(3) {
        println!(
            "   {:<8} perCol={} -> {:?}",
            String::from_utf8_lossy(&d.key),
            d.per_column,
            String::from_utf8_lossy(&d.plaintext)
        );
    }
}
