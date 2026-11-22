//! Canary corpus integrity: `tests/corpus/canary.txt` is data a contributor
//! can extend without Rust, so its structure and its tie to the text are
//! asserted here. A typo in an expected value would otherwise weaken the
//! recall gate without failing anything.

mod common;

use std::collections::HashSet;

use common::{canaries, parse_corpus};
use mask::types::EntityType;

#[test]
fn every_case_has_text_expected_values_and_a_unique_name() {
    let cases = canaries();
    assert!(cases.len() >= 6, "the corpus shrank: {} cases", cases.len());
    let mut names: HashSet<&str> = HashSet::new();
    for case in cases {
        assert!(!case.name.is_empty(), "empty case name");
        assert!(
            names.insert(case.name.as_str()),
            "duplicate case {}",
            case.name
        );
        assert!(!case.text.trim().is_empty(), "{}: empty text", case.name);
        assert!(
            !case.expected.is_empty(),
            "{}: no expected entities",
            case.name
        );
        for (kind, value) in &case.expected {
            assert!(!value.trim().is_empty(), "{}: empty {kind:?}", case.name);
            assert!(
                case.text.contains(value.as_str()),
                "{}: {value:?} does not occur in the text",
                case.name
            );
        }
    }
}

#[test]
fn corpus_covers_every_built_in_detection_type() {
    let mut seen: HashSet<EntityType> = HashSet::new();
    for case in canaries() {
        seen.extend(case.expected.iter().map(|(kind, _)| *kind));
    }
    // Location is dictionary-only (no rule or lexicon produces it), so the
    // corpus pins the six types the built-in detector claims.
    for kind in [
        EntityType::Person,
        EntityType::Org,
        EntityType::Address,
        EntityType::Phone,
        EntityType::Email,
        EntityType::Account,
    ] {
        assert!(seen.contains(&kind), "corpus has no {kind:?} case");
    }
}

#[test]
fn parser_keeps_colons_inside_text() {
    let cases = parse_corpus("# case: t\ntext: 時刻 12:34 に 山田太郎\nperson: 山田太郎\n");
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].name, "t");
    assert_eq!(cases[0].text, "時刻 12:34 に 山田太郎");
    assert_eq!(cases[0].expected.len(), 1);
}

#[test]
fn parser_rejects_an_unknown_type() {
    let result = std::panic::catch_unwind(|| parse_corpus("# case: t\ntext: x\nnickname: y\n"));
    assert!(result.is_err(), "an unknown type must fail loudly");
}
