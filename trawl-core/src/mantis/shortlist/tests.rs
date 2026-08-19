use super::*;

/// The shape of chain that prompted this module: a random token, wrapped, then
/// rotated over digits and letters together. No layer of it reads as English,
/// so nothing can decide it, and all of it is perfectly visible to someone
/// looking at a list.
///
/// Base32 rather than base64 for the wrapper, because its alphabet is uppercase
/// only. A base36 rotation cannot round-trip mixed case: a lowercase letter that
/// lands on a digit has nowhere to keep its case and comes back uppercase.
const CHAIN: &[u8] = b"YTAPV4O8YA4616NDT5======";

#[test]
fn declines_input_too_short_or_too_long() {
    assert!(every(b"ab").is_empty());
    assert!(every(&vec![b'a'; MAX_INPUT + 1]).is_empty());
}

#[test]
fn never_offers_the_input_back_unchanged() {
    assert!(
        every(b"attack at dawn")
            .iter()
            .all(|r| r.text != b"attack at dawn")
    );
}

#[test]
fn lays_out_every_rotation() {
    let all = every(b"attack at dawn");

    assert!(all.iter().any(|r| r.how == "ROT 13"));
    assert!(all.iter().any(|r| r.how.starts_with("base36 +")));
    assert!(all.iter().any(|r| r.how == "Atbash"));
    assert!(all.iter().any(|r| r.how == "reversed"));
}

#[test]
fn puts_a_flag_first() {
    // ROT 13 of a flag. Nothing else in the list can beat something that
    // announces itself.
    let hidden = encodings::rot_n(b"CTF{n0t_s0_h1dden_after_all}", 13);
    let all = every(&hidden);

    assert_eq!(all[0].how, "ROT 13");
    assert!(all[0].found.is_some(), "the flag was not recognised");
}

#[test]
fn puts_english_first_when_there_is_english() {
    let all = every(&encodings::rot_n(
        b"the treasure is buried under the old oak tree",
        7,
    ));

    assert_eq!(all[0].how, "ROT 19", "ROT 19 undoes a shift of 7");
    assert!(all[0].score > 0.7, "scored only {}", all[0].score);
}

#[test]
fn ranks_the_rotation_that_decodes_onward() {
    // The point of the module. None of these readings is English, so score
    // alone cannot separate them. One of them is clean base64 and the rest are
    // not, and that is the whole signal.
    let all = every(CHAIN);
    let winner = &all[0];

    assert!(
        winner.then.is_some(),
        "top pick {:?} leads nowhere, so the list is sorted on the wrong thing",
        winner.how
    );
    assert_eq!(winner.how, "base36 +25");
    assert_eq!(
        String::from_utf8_lossy(&winner.then.as_ref().unwrap().result),
        "j2ELwngXTZE"
    );
}

#[test]
fn a_reading_that_decodes_cleanly_is_the_rare_one() {
    // The signal the ordering rests on. Plenty of rotations can be forced
    // through a decoder; almost none of them come out as text on the other
    // side, and that is what separates the right one from the rest.
    let all = every(CHAIN);
    let clean = |r: &&Reading| match &r.then {
        Some(chain) => chain.result.iter().all(|&b| (0x20..0x7f).contains(&b)),
        None => false,
    };

    assert!(
        clean(&&all[0]),
        "the top pick should decode to readable bytes"
    );
    assert!(
        all.iter().filter(clean).count() <= 3,
        "too many decoded cleanly for that to be evidence"
    );
}

#[test]
fn json_carries_the_chain() {
    let out = json(&every(CHAIN));

    assert!(out.starts_with('['), "{out}");
    assert!(out.contains("\"how\":\"base36 +25\""), "{out}");
    assert!(out.contains("\"through\":[\"base32\"]"), "{out}");
}

#[test]
fn json_of_nothing_is_an_empty_list() {
    assert_eq!(json(&[]), "[]");
}
