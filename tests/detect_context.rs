//! Detection context: the false-positive corpus that `surnames.txt` requires
//! for every lexicon addition, plus the positive cases that must keep masking.
//!
//! The negative corpus is data (`tests/corpus/false_positive.txt`) so a
//! contributor can pin a collision without Rust. The positive cases live here
//! because they assert exact spans, which the canary corpus already does for
//! `person:`—these are the contexts the canary phrasing does not cover.

use mask::detect::dictionary::UserDictionary;
use mask::detect::ner::NativeNer;
use mask::detect::{detect, explain};
use mask::types::{Entity, EntityType};

struct Case {
    name: String,
    text: String,
    must_not: Vec<String>,
}

fn cases() -> Vec<Case> {
    let source = include_str!("corpus/false_positive.txt");
    let mut cases: Vec<Case> = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix("# case:") {
            cases.push(Case {
                name: name.trim().to_string(),
                text: String::new(),
                must_not: Vec::new(),
            });
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let case = cases.last_mut().expect("case before any `# case:` header");
        if let Some(text) = line.strip_prefix("text:") {
            case.text = text.trim().to_string();
        } else if let Some(value) = line.strip_prefix("must_not:") {
            case.must_not.push(value.trim().to_string());
        } else {
            panic!("{}: unknown line {line:?}", case.name);
        }
    }
    cases
}

fn persons(text: &str) -> Vec<Entity> {
    let ner = NativeNer::new();
    let dictionary = UserDictionary::new();
    detect(text, Some(&dictionary), Some(&ner))
        .entities
        .into_iter()
        .filter(|entity| entity.kind == EntityType::Person)
        .collect()
}

#[test]
fn false_positive_corpus_is_not_masked() {
    let cases = cases();
    assert!(!cases.is_empty(), "the corpus is empty");
    for case in cases {
        assert!(!case.text.is_empty(), "{}: no text", case.name);
        assert!(!case.must_not.is_empty(), "{}: no must_not", case.name);
        for entity in persons(&case.text) {
            for value in &case.must_not {
                assert!(
                    !entity.text.contains(value.as_str()),
                    "{}: masked {value:?} as {:?} in {:?}",
                    case.name,
                    entity.text,
                    case.text
                );
            }
        }
    }
}

#[test]
fn honorifics_and_full_names_still_mask() {
    for (text, expected) in [
        ("田中さんに確認してください。", "田中"),
        ("明日は山田様が来ます。", "山田"),
        ("山田太郎です。よろしくお願いします。", "山田太郎"),
        ("佐藤花子が担当します。", "佐藤花子"),
        ("出口さんに聞く。", "出口"),
        ("大川課長に確認する。", "大川"),
        ("氏名: 田中", "田中"),
        ("担当者：小野", "小野"),
    ] {
        let found = persons(text);
        assert!(
            found.iter().any(|entity| entity.text == expected),
            "{text:?}: expected {expected:?}, got {found:?}"
        );
    }
}

#[test]
fn an_unambiguous_surname_may_take_a_particle() {
    // Faithful to the issue: a particle is weak evidence, accepted for a
    // surname that is not on the everyday-word stoplist and rejected for one
    // that is (see the false-positive corpus).
    let found = persons("山田は欠席です。");
    assert!(
        found.iter().any(|entity| entity.text == "山田"),
        "{found:?}"
    );
}

#[test]
fn explain_reports_the_rule_and_matches_detection() {
    let text = "山田太郎さんと佐藤花子、tanaka@example.com。";
    let dictionary = UserDictionary::new();
    let ner = NativeNer::new();
    let detected = detect(text, Some(&dictionary), Some(&ner));
    let explained = explain(text, Some(&dictionary), Some(&ner));

    let spans: Vec<Entity> = explained.iter().map(|e| e.entity.clone()).collect();
    assert_eq!(spans, detected.entities, "--explain changed detection");

    let reason = |value: &str| {
        explained
            .iter()
            .find(|e| e.entity.text == value)
            .unwrap_or_else(|| panic!("no explanation for {value:?}: {explained:?}"))
            .reason
    };
    assert_eq!(reason("山田太郎"), "family+given name + honorific");
    assert_eq!(reason("佐藤花子"), "family+given name");
    assert_eq!(reason("tanaka@example.com"), "email");
}
