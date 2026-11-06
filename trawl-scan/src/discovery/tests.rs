use super::*;

#[test]
fn a_straight_server_that_404s_makes_any_200_a_hit() {
    // Both made-up paths came back 404, so the server tells the truth and a
    // real 200 is a real file.
    let baseline = Baseline::from_samples(&[(404, 200), (404, 210)]);
    assert!(baseline.is_hit(200, 900));
    assert!(baseline.is_hit(200, 12));
    assert!(!baseline.is_hit(404, 200));
    // Empty 200s are not files worth reporting.
    assert!(!baseline.is_hit(200, 0));
}

#[test]
fn a_soft_404_server_needs_the_body_to_differ() {
    // Every made-up path came back 200 with the same ~500-byte front page, so
    // a bare 200 proves nothing; only a body that is not the catch-all counts.
    let baseline = Baseline::from_samples(&[(200, 500), (200, 500)]);

    // The catch-all itself, near enough, is not a hit.
    assert!(!baseline.is_hit(200, 500));
    assert!(!baseline.is_hit(200, 520));
    // A real file, whose body is nothing like the front page, is.
    assert!(baseline.is_hit(200, 2400));
    assert!(baseline.is_hit(200, 30));
}

#[test]
fn a_soft_404_server_within_tolerance_is_still_the_catch_all() {
    let baseline = Baseline::from_samples(&[(200, 1000), (200, 1000)]);
    // Small drift is the same page rendered a touch differently, not a find.
    assert!(!baseline.is_hit(200, 1000 + SOFT_404_TOLERANCE));
    assert!(!baseline.is_hit(200, 1000 - SOFT_404_TOLERANCE));
    // Past the tolerance it is a different document.
    assert!(baseline.is_hit(200, 1000 + SOFT_404_TOLERANCE + 1));
}

#[test]
fn a_mixed_calibration_is_treated_as_a_straight_server() {
    // One made-up path 404s, one redirects: not a consistent soft-404, so a
    // 200 is trusted rather than second-guessed.
    let baseline = Baseline::from_samples(&[(404, 0), (301, 0)]);
    assert!(baseline.is_hit(200, 100));
}

#[test]
fn a_forbidden_file_is_a_hit_on_a_server_that_otherwise_404s() {
    // Nonsense 404s but a named path 403s: the file is there and guarded,
    // which is itself the finding.
    let baseline = Baseline::from_samples(&[(404, 0), (404, 0)]);
    assert!(baseline.is_hit(403, 0));
    assert!(baseline.is_hit(401, 0));
}

#[test]
fn a_forbidden_answer_on_a_soft_404_server_is_not_trusted() {
    // A server that soft-404s throws 403s around too, so they say nothing.
    let baseline = Baseline::from_samples(&[(200, 800), (200, 800)]);
    assert!(!baseline.is_hit(403, 0));
}

#[test]
fn calibration_paths_are_two_distinct_names_that_should_not_exist() {
    let [a, b] = calibration_paths(0x1234_5678_9abc_def0);
    assert_ne!(a, b);
    assert!(a.starts_with('/') && b.starts_with('/'));
    // One looks like a bare path, one like a file, to catch either 404 style.
    assert!(!a.contains('.'));
    assert!(b.ends_with(".html"));
}

#[test]
fn the_wordlist_holds_the_names_a_flag_actually_gets() {
    // A guard against someone quietly gutting the list: the obvious ones have
    // to stay in it.
    for name in ["/flag.txt", "/flag", "/secret.txt", "/key.txt", "/uploads/"] {
        assert!(
            DISCOVERY_PATHS.contains(&name),
            "{name} missing from the sweep"
        );
    }
    // Every entry is a rooted path.
    assert!(DISCOVERY_PATHS.iter().all(|p| p.starts_with('/')));
}

#[test]
fn an_answer_that_says_the_request_went_wrong_is_told_apart() {
    let honest = Baseline::from_samples(&[(404, 10), (404, 10)]);
    assert!(honest.went_wrong(429));
    assert!(honest.went_wrong(503));
    assert!(!honest.went_wrong(404));
    assert!(!honest.went_wrong(403));
    assert!(!honest.went_wrong(200));

    // Nonsense gets a 500 here, so a 500 says nothing went wrong with this name.
    let broken = Baseline::from_samples(&[(500, 10), (500, 10)]);
    assert!(!broken.went_wrong(500));
    assert!(broken.went_wrong(503));
}

#[test]
fn a_refusal_is_new_only_if_nonsense_did_not_get_it_before() {
    let honest = Baseline::from_samples(&[(404, 10), (404, 10)]);
    assert!(honest.is_new_refusal(401));
    assert!(honest.is_new_refusal(403));
    assert!(honest.is_new_refusal(429));
    assert!(!honest.is_new_refusal(404));
    assert!(!honest.is_new_refusal(200));

    // Nonsense always got a 403 here, so getting one again means nothing has changed.
    let guarded = Baseline::from_samples(&[(403, 10), (403, 10)]);
    assert!(!guarded.is_new_refusal(403));
    assert!(guarded.is_new_refusal(401));
}
