//! Merged detection pipeline: rules + user dictionary + native name detection.
//!
//! Merge policy (recall-first, one entity per span):
//! 1. Longest span wins on overlap.
//! 2. Tie on span -> source priority rule > dict > ner (exact/attested beats model).

pub mod dictionary;
pub mod ner;
pub mod rules;
pub mod suspect;

use crate::types::{DetectionResult, Entity, Source};

use dictionary::UserDictionary;
use ner::NativeNer;

pub fn detect(
    text: &str,
    dictionary: Option<&UserDictionary>,
    ner: Option<&NativeNer>,
) -> DetectionResult {
    let mut entities: Vec<Entity> = rules::run_rule_detection(text);
    if let Some(dictionary) = dictionary {
        entities.extend(dictionary.scan(text));
    }
    if let Some(ner) = ner {
        entities.extend(ner.scan(text));
    }
    DetectionResult::new(text.to_string(), merge(entities))
}

/// Drop overlapping entities, preferring longer spans then source priority.
pub fn merge(entities: Vec<Entity>) -> Vec<Entity> {
    let mut ordered = entities;
    ordered.sort_by(|a, b| {
        b.char_len()
            .cmp(&a.char_len())
            .then_with(|| b.source.priority().cmp(&a.source.priority()))
            .then_with(|| a.start.cmp(&b.start))
    });
    let mut kept: Vec<Entity> = Vec::new();
    for ent in ordered {
        if kept.iter().any(|k| ent.overlaps(k)) {
            continue;
        }
        kept.push(ent);
    }
    kept.sort_by_key(|e| e.start);
    kept
}

/// Convenience: source priority value (rule > dict > ner).
pub fn source_priority(source: Source) -> u8 {
    source.priority()
}
