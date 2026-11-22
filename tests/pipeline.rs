//! Pipeline tests: rules, dictionary, replacement, restore, canary gates.

mod common;

use common::{canaries, dict_file};
use mask::detect::detect;
use mask::detect::dictionary::UserDictionary;
use mask::detect::ner::NativeNer;
use mask::detect::rules::run_rule_detection;
use mask::replace::{mask_text, PseudonymMap};
use mask::restore::{audit_output, levenshtein, restore, restore_stream_buffer};
use mask::types::{DetectionResult, Entity, EntityType, Source};
use mask::Session;

fn types_with_text(entities: &[Entity]) -> Vec<(EntityType, String)> {
    entities.iter().map(|e| (e.kind, e.text.clone())).collect()
}

fn ent(kind: EntityType, start: usize, end: usize, text: &str) -> Entity {
    Entity::new(kind, start, end, text, 1.0, Source::Rule)
}

fn session_with(terms: &[(&str, EntityType)]) -> Session {
    let dictionary =
        UserDictionary::from_terms(terms.iter().map(|(term, kind)| (term.to_string(), *kind)));
    Session::new(dictionary, false)
}

// --- rules -------------------------------------------------------------------

#[test]
fn rule_email() {
    let found = types_with_text(&run_rule_detection(
        "連絡先は taro.yamada+Work@example.co.jp まで",
    ));
    assert!(found.contains(&(EntityType::Email, "taro.yamada+Work@example.co.jp".into())));
}

#[test]
fn rule_phone_hyphen() {
    let found = types_with_text(&run_rule_detection("電話は090-1234-5678です"));
    assert!(found.contains(&(EntityType::Phone, "090-1234-5678".into())));
}

#[test]
fn rule_phone_parenthesised() {
    let found = types_with_text(&run_rule_detection("(03) 1234-5678 に電話"));
    assert!(found.contains(&(EntityType::Phone, "(03) 1234-5678".into())));
}

#[test]
fn rule_postal_and_address() {
    let found = types_with_text(&run_rule_detection(
        "〒160-0022 東京都新宿区新宿三丁目1番1号サカエビル203",
    ));
    let addresses: Vec<&str> = found
        .iter()
        .filter(|(kind, _)| *kind == EntityType::Address)
        .map(|(_, text)| text.as_str())
        .collect();
    assert!(!addresses.is_empty());
    assert!(addresses.iter().any(|a| a.contains("東京都新宿区")));
}

#[test]
fn rule_ward_only_address() {
    let found = types_with_text(&run_rule_detection(
        "港区赤坂一丁目2番3号のマンション103号室です",
    ));
    assert!(found
        .iter()
        .any(|(kind, text)| *kind == EntityType::Address && text.contains("赤坂")));
}

#[test]
fn rule_bank_account() {
    let found = types_with_text(&run_rule_detection("普通 1234567 に振込"));
    assert!(found.contains(&(EntityType::Account, "普通 1234567".into())));
}

#[test]
fn rule_card_number() {
    let found = types_with_text(&run_rule_detection("カードは4242-4242-4242-4242"));
    assert!(found
        .iter()
        .any(|(kind, text)| *kind == EntityType::Account && text.contains("4242")));
}

#[test]
fn rule_dates_are_not_phone_numbers() {
    let found = types_with_text(&run_rule_detection(
        "納期は 2019-04-01 です。第2019-04号ではありません",
    ));
    assert!(!found
        .iter()
        .any(|(kind, text)| *kind == EntityType::Phone && text.contains("2019-04-01")));
}

#[test]
fn rule_recall_on_canaries() {
    let mut hits = 0usize;
    let mut misses: Vec<String> = Vec::new();
    for canary in canaries() {
        let found = types_with_text(&run_rule_detection(&canary.text));
        for (kind, value) in &canary.expected {
            if matches!(*kind, EntityType::Person | EntityType::Org) {
                continue; // name detection territory
            }
            let hit = found
                .iter()
                .any(|(k, t)| k == kind && t.contains(value.as_str()));
            if hit {
                hits += 1;
            } else {
                misses.push(format!("{}: {kind:?} {value:?}", canary.name));
            }
        }
    }
    let total = hits + misses.len();
    let recall = hits as f64 / total as f64;
    assert!(recall >= 0.95, "rule recall {recall:.2} misses: {misses:?}");
}

// --- dictionary --------------------------------------------------------------

#[test]
fn dictionary_exact_term_round_trips() {
    let mut session = session_with(&[("山田太郎", EntityType::Person)]);
    let (masked, result) = session.masked("昨日、山田太郎さんから電話がありました");
    assert!(result
        .entities
        .iter()
        .any(|e| e.kind == EntityType::Person && e.text == "山田太郎"));
    assert!(!masked.contains("山田太郎"));
    let restored = session.unmasked(&masked);
    assert!(restored.text.contains("山田太郎"));
}

#[test]
fn dictionary_longest_match_wins() {
    let mut session = session_with(&[
        ("山田", EntityType::Person),
        ("山田太郎", EntityType::Person),
    ]);
    let (_, result) = session.masked("山田太郎の弟の山田次郎");
    let texts: Vec<&str> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityType::Person && e.source == Source::Dict)
        .map(|e| e.text.as_str())
        .collect();
    assert!(texts.contains(&"山田太郎"));
}

#[test]
fn dictionary_covered_substring_not_double_detected() {
    let mut session = session_with(&[
        ("山田", EntityType::Person),
        ("山田太郎", EntityType::Person),
    ]);
    let (_, result) = session.masked("山田太郎に会った");
    let hits: Vec<&Entity> = result
        .entities
        .iter()
        .filter(|e| e.source == Source::Dict)
        .collect();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].text, "山田太郎");
}

#[test]
fn dictionary_load_tsv_and_missing_file() {
    let path = dict_file(&[("鈴木一郎", "person"), ("○○銀行", "org")]);
    let dictionary = UserDictionary::load(&path).unwrap();
    assert_eq!(dictionary.size(), 2);
    let mut session = Session::new(dictionary, false);
    let (masked, _) = session.masked("鈴木一郎は○○銀行の融資を受けた");
    assert!(!masked.contains("鈴木一郎"));
    assert!(!masked.contains("○○銀行"));

    let missing = UserDictionary::load("/nonexistent/dict.tsv").unwrap();
    assert!(missing.is_empty());
    assert!(missing.scan("山田太郎です").is_empty());
}

#[test]
fn dictionary_ignores_comments_and_unknown_types() {
    let dictionary = UserDictionary::parse("# comment\n\n山田太郎\tperson\n謎\tunknown\n");
    assert_eq!(dictionary.size(), 1);
}

// --- replacement -------------------------------------------------------------

#[test]
fn same_value_same_token() {
    let mut map = PseudonymMap::new();
    let first = map.assign(EntityType::Person, "山田太郎");
    let second = map.assign(EntityType::Person, "山田太郎");
    assert_eq!(first.token, second.token);
    assert_eq!(map.restore_value(&first.token), Some("山田太郎"));
}

#[test]
fn variant_unification_prevents_fragmentation() {
    let mut map = PseudonymMap::new();
    let full = map.assign(EntityType::Person, "山田太郎");
    let short = map.assign(EntityType::Person, "山田");
    assert_eq!(short.token, full.token);
    // the mapping keeps the longer variant for restoration
    assert_eq!(map.restore_value(&full.token), Some("山田太郎"));
}

#[test]
fn id_pool_is_shuffled_not_sequential() {
    let mut digits: Vec<String> = Vec::new();
    for _ in 0..30 {
        let mut map = PseudonymMap::new();
        let token = map.assign(EntityType::Person, "山田太郎").token;
        let digits_part: String = token.chars().filter(|c| c.is_ascii_digit()).collect();
        digits.push(digits_part);
    }
    digits.sort();
    digits.dedup();
    assert!(digits.len() > 5, "ids suspiciously predictable: {digits:?}");
}

#[test]
fn mask_text_shifts_spans_correctly() {
    let mut map = PseudonymMap::new();
    let text = "山田太郎は090-1234-5678に連絡した。山田太郎のFAXはない";
    let result = DetectionResult::new(
        text,
        vec![
            ent(EntityType::Person, 0, "山田太郎".len(), "山田太郎"),
            ent(
                EntityType::Phone,
                "山田太郎は".len(),
                "山田太郎は090-1234-5678".len(),
                "090-1234-5678",
            ),
            ent(
                EntityType::Person,
                text.rfind("山田太郎").unwrap(),
                text.rfind("山田太郎").unwrap() + "山田太郎".len(),
                "山田太郎",
            ),
        ],
    );
    let masked = mask_text(&result, &mut map);
    assert!(!masked.contains("山田太郎"));
    assert!(!masked.contains("090-1234-5678"));
    assert_eq!(masked.matches('⟦').count(), 3);
}

#[test]
fn different_types_get_different_tokens() {
    let mut map = PseudonymMap::new();
    let person = map.assign(EntityType::Person, "山田");
    let org = map.assign(EntityType::Org, "山田");
    assert_ne!(person.token, org.token);
}

// --- restore -----------------------------------------------------------------

#[test]
fn restore_exact_token() {
    let mut map = PseudonymMap::new();
    let rec = map.assign(EntityType::Person, "山田太郎");
    let out = restore(&format!("ご担当者は{}様ですね", rec.token), &map);
    assert_eq!(out.text, "ご担当者は山田太郎様ですね");
    assert_eq!(out.restored, 1);
    assert!(out.warnings.is_empty());
}

#[test]
fn restore_multiple_tokens() {
    let mut map = PseudonymMap::new();
    let person = map.assign(EntityType::Person, "山田太郎");
    let address = map.assign(EntityType::Address, "港区赤坂一丁目2番3号");
    let out = restore(
        &format!("{}様は{}在住です", person.token, address.token),
        &map,
    );
    assert_eq!(out.text, "山田太郎様は港区赤坂一丁目2番3号在住です");
}

#[test]
fn mutated_token_is_repaired_with_a_warning() {
    let mut map = PseudonymMap::new();
    let rec = map.assign(EntityType::Person, "山田太郎");
    let mutated = rec.token.replace('⟧', ""); // lost closing bracket
    let out = restore(&format!("担当は{mutated}です"), &map);
    assert!(out.fuzzy_repaired == 1 || !out.unresolved_tokens.is_empty());
    if out.fuzzy_repaired == 1 {
        assert_eq!(out.text, "担当は山田太郎です");
        assert!(!out.warnings.is_empty());
    }
}

#[test]
fn hallucinated_token_never_guesses_another_entity() {
    let mut map = PseudonymMap::new();
    map.assign(EntityType::Person, "山田太郎");
    let out = restore("担当は⟦人名999⟧です", &map);
    assert!(out.text.contains("⟦人名999⟧"));
    assert!(!out.text.contains("山田太郎"));
}

#[test]
fn stream_buffer_holds_partial_tokens() {
    let (safe, keep) = restore_stream_buffer("こんにちは⟦人名");
    assert_eq!(safe, "こんにちは");
    assert_eq!(keep, "⟦人名");
    let (safe, keep) = restore_stream_buffer("こんにちは⟦人名17⟧");
    assert_eq!(safe, "こんにちは⟦人名17⟧");
    assert_eq!(keep, "");
    let (safe, keep) = restore_stream_buffer("普通のテキスト");
    assert_eq!(safe, "普通のテキスト");
    assert_eq!(keep, "");
}

#[test]
fn levenshtein_is_capped() {
    assert_eq!(levenshtein("⟦人名17⟧", "⟦人名17⟧", 2), 0);
    assert_eq!(levenshtein("⟦人名17", "⟦人名17⟧", 2), 1);
    assert!(levenshtein("あいうえおかきくけこ", "全然違う文字列です", 2) > 2);
}

#[test]
fn audit_flags_direct_leak() {
    let mut map = PseudonymMap::new();
    map.assign(EntityType::Person, "山田太郎");
    let warnings = audit_output("担当は⟦人名999⟧です", "担当は山田太郎です", &map);
    assert!(warnings
        .iter()
        .any(|w| w.contains("beyond restored occurrences")));
}

#[test]
fn audit_flags_token_residue() {
    let mut map = PseudonymMap::new();
    map.assign(EntityType::Person, "山田太郎");
    let warnings = audit_output("x", "残骸⟦人名999⟧残り", &map);
    assert!(warnings.iter().any(|w| w.contains("token residue")));
}

#[test]
fn restore_miss_keeps_placeholder_and_warns() {
    let mut map = PseudonymMap::new();
    map.assign(EntityType::Person, "山田太郎");
    let out = restore("⟦住所77⟧の近くで会いましょう", &map);
    assert!(out.text.contains("⟦住所77⟧"));
    assert_eq!(out.unresolved_tokens, vec!["⟦住所77⟧".to_string()]);
    assert!(!out.warnings.is_empty());
}

// --- native name detection ---------------------------------------------------

#[test]
fn ner_finds_names_and_stops_at_honorifics() {
    let ner = NativeNer::new();
    let found = ner.scan("山田太郎様あて。佐藤花子が担当です。");
    let texts: Vec<&str> = found.iter().map(|e| e.text.as_str()).collect();
    assert!(texts.contains(&"山田太郎"), "{texts:?}");
    assert!(texts.contains(&"佐藤花子"), "{texts:?}");
}

#[test]
fn ner_can_be_disabled() {
    let mut with_ner = Session::new(UserDictionary::new(), true);
    let (_, result) = with_ner.masked("山田太郎さん");
    assert!(result.entities.iter().any(|e| e.source == Source::Ner));

    let mut without_ner = Session::new(UserDictionary::new(), false);
    let (_, result) = without_ner.masked("山田太郎さん");
    assert!(result.entities.iter().all(|e| e.source != Source::Ner));
}

// --- canary gates ------------------------------------------------------------

#[test]
fn canary_recall_gate_full_pipeline() {
    let mut session = Session::new(UserDictionary::new(), true);
    let mut misses: Vec<String> = Vec::new();
    for canary in canaries() {
        let (_, result) = session.masked(&canary.text);
        for (kind, value) in &canary.expected {
            let hit = result
                .entities
                .iter()
                .any(|e| e.kind == *kind && e.text.contains(value.as_str()));
            if !hit {
                misses.push(format!("{}: {kind:?} {value:?}", canary.name));
            }
        }
    }
    assert!(misses.is_empty(), "recall misses:\n{}", misses.join("\n"));
}

#[test]
fn canary_no_raw_pii_in_masked_output() {
    let mut session = Session::new(UserDictionary::new(), true);
    for canary in canaries() {
        let (masked, _) = session.masked(&canary.text);
        for (_, value) in &canary.expected {
            assert!(
                !masked.contains(value.as_str()),
                "{}: {value:?} leaked into masked text",
                canary.name
            );
        }
    }
}

#[test]
fn canary_masked_text_keeps_one_token_per_entity() {
    let mut session = Session::new(UserDictionary::new(), true);
    let canary = &canaries()[0];
    let (masked, _) = session.masked(&canary.text);
    assert_eq!(masked.matches('⟦').count(), masked.matches('⟧').count());
    assert_eq!(
        masked.matches('⟦').count(),
        canary.expected.len(),
        "masked: {masked}"
    );
}

#[test]
fn canary_restore_round_trip() {
    let mut session = Session::new(UserDictionary::new(), true);
    for canary in canaries() {
        let (masked, _) = session.masked(&canary.text);
        let out = session.unmasked(&masked);
        for (_, value) in &canary.expected {
            assert!(
                out.text.contains(value.as_str()),
                "{}: lost {value:?}",
                canary.name
            );
        }
        assert!(out.unresolved_tokens.is_empty());
    }
}

#[test]
fn canary_streaming_restore_matches_batch() {
    let mut session = Session::new(UserDictionary::new(), true);
    let canary = &canaries()[1];
    let (masked, _) = session.masked(&canary.text);
    let chars: Vec<char> = masked.chars().collect();
    let mut emitted = String::new();
    let mut pending = String::new();
    for chunk in chars.chunks(3) {
        let buf = format!("{pending}{}", chunk.iter().collect::<String>());
        let (safe, keep) = restore_stream_buffer(&buf);
        emitted.push_str(&safe);
        pending = keep;
    }
    emitted.push_str(&pending);
    let out = session.unmasked(&emitted);
    for (_, value) in &canary.expected {
        assert!(
            out.text.contains(value.as_str()),
            "streaming lost {value:?}"
        );
    }
}

#[test]
fn audit_catches_model_mentioning_raw_pii() {
    let mut session = Session::new(UserDictionary::new(), true);
    let canary = &canaries()[0];
    let (masked, _) = session.masked(&canary.text);
    let out = session.unmasked(&format!("{masked} 本名で言いますと山田太郎です。"));
    assert!(out
        .warnings
        .iter()
        .any(|w| w.contains("beyond restored occurrences")));
}

#[test]
fn detect_merges_longest_span_and_prefers_rules() {
    // A dictionary entry inside a longer rule span must not split that span.
    let dictionary = UserDictionary::from_terms([("ACME".to_string(), EntityType::Person)]);
    let result = detect("株式会社ACMEに連絡", Some(&dictionary), None);
    let orgs: Vec<&Entity> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityType::Org)
        .collect();
    assert_eq!(orgs.len(), 1, "{:?}", result.entities);
    assert_eq!(orgs[0].source, Source::Rule);
    assert!(result
        .entities
        .iter()
        .all(|e| !(e.kind == EntityType::Person && e.text == "ACME")));
}
