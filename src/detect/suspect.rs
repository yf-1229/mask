//! Post-detection "did we miss someone?" hints, used by `mask audit`.
//!
//! This is deliberately **not** detection: it never masks, never blocks and
//! never changes the guarantee. It points a human at the places the detector is
//! most likely to have missed — an unmasked run of 2–4 kanji immediately
//! followed by an honorific (`山田様`, `鈴木一郎さん`, …) — so the operator can
//! register the term with `mask dict add`.
//!
//! The rule is narrow on purpose. A hint that fires on every name-like word
//! would be ignored; a hint that fires on an honorific without a mask is a
//! near-certain miss in Japanese business text. Names written in kana, and
//! names longer than four characters, are out of scope; the README states it.

use crate::types::DetectionResult;

/// Honorifics that make an immediately preceding unmasked name suspicious.
///
/// Longest first so `先生` is not read as a one-character honorific if the list
/// ever grows to share a prefix.
const HONORIFICS: &[&str] = &[
    "先生",
    "ちゃん",
    "さん",
    "さま",
    "くん",
    "様",
    "氏",
    "殿",
    "君",
];

/// Shortest and longest kanji run treated as a name candidate.
const MIN_NAME: usize = 2;
const MAX_NAME: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuspicionKind {
    /// A 2–4 kanji run before an honorific that no detector claimed.
    HonorificName,
}

impl SuspicionKind {
    /// Human-readable, value-free description for the audit report.
    pub fn label(self) -> &'static str {
        match self {
            SuspicionKind::HonorificName => "unmasked name before an honorific",
        }
    }
}

/// One place worth a human's look. Offsets are byte offsets into the audited
/// text; the values themselves never enter the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Suspicion {
    pub start: usize,
    pub end: usize,
    /// 1-based line number of `start`.
    pub line: usize,
    pub kind: SuspicionKind,
}

/// Find unmasked name candidates before honorifics.
pub fn scan(text: &str, detected: &DetectionResult) -> Vec<Suspicion> {
    let mut found: Vec<Suspicion> = Vec::new();
    for (index, _) in text.char_indices() {
        if honorific_at(text, index).is_none() {
            continue;
        }
        let start = kanji_run_start(text, index);
        let run = &text[start..index];
        let length = run.chars().count();
        if !(MIN_NAME..=MAX_NAME).contains(&length) {
            continue;
        }
        if detected
            .entities
            .iter()
            .any(|entity| entity.start < index && entity.end > start)
        {
            continue;
        }
        found.push(Suspicion {
            start,
            end: index,
            line: line_of(text, start),
            kind: SuspicionKind::HonorificName,
        });
    }
    found
}

fn honorific_at(text: &str, index: usize) -> Option<&'static str> {
    HONORIFICS
        .iter()
        .find(|honorific| text[index..].starts_with(*honorific))
        .copied()
}

/// Start of the contiguous kanji run that ends at `end`.
fn kanji_run_start(text: &str, end: usize) -> usize {
    let mut start = end;
    for (offset, c) in text[..end].char_indices().rev() {
        if is_name_kanji(c) {
            start = offset;
        } else {
            break;
        }
    }
    start
}

/// Kanji, the repetition mark and the ideographic zero: the characters a
/// personal name is normally written with.
fn is_name_kanji(c: char) -> bool {
    matches!(c,
        '\u{4e00}'..='\u{9fff}'
        | '々' | '〇'
        | '\u{3400}'..='\u{4dbf}'
    )
}

fn line_of(text: &str, index: usize) -> usize {
    text[..index].bytes().filter(|byte| *byte == b'\n').count() + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Entity, EntityType, Source, BAND_EXACT};

    fn detection(text: &str, spans: &[(usize, usize)]) -> DetectionResult {
        let entities = spans
            .iter()
            .map(|(start, end)| {
                Entity::new(
                    EntityType::Person,
                    *start,
                    *end,
                    &text[*start..*end],
                    BAND_EXACT,
                    Source::Dict,
                )
            })
            .collect();
        DetectionResult::new(text, entities)
    }

    fn lines(hints: &[Suspicion]) -> Vec<usize> {
        hints.iter().map(|hint| hint.line).collect()
    }

    #[test]
    fn flags_an_unmasked_name_before_an_honorific() {
        let text = "鈴木一郎様にご連絡ください。";
        let hints = scan(text, &detection(text, &[]));
        assert_eq!(hints.len(), 1);
        assert_eq!(&text[hints[0].start..hints[0].end], "鈴木一郎");
        assert_eq!(hints[0].line, 1);
        assert_eq!(hints[0].kind, SuspicionKind::HonorificName);
    }

    #[test]
    fn does_not_flag_a_detected_name() {
        let text = "鈴木一郎様にご連絡ください。";
        let hints = scan(text, &detection(text, &[(0, 12)]));
        assert!(hints.is_empty(), "{hints:?}");
    }

    #[test]
    fn does_not_flag_an_entity_that_covers_the_whole_phrase() {
        let text = "山田太郎様";
        let hints = scan(text, &detection(text, &[(0, 15)]));
        assert!(hints.is_empty(), "{hints:?}");
    }

    #[test]
    fn ignores_one_character_runs_and_long_runs() {
        let short = "お客様";
        assert!(scan(short, &detection(short, &[])).is_empty());
        let long = "株式会社山田太郎様";
        assert!(scan(long, &detection(long, &[])).is_empty());
    }

    #[test]
    fn ignores_kana_names() {
        // Documented limitation: the hint looks at kanji runs only.
        let text = "さくら様";
        assert!(scan(text, &detection(text, &[])).is_empty());
    }

    #[test]
    fn reports_every_line_number() {
        let text = "鈴木一郎様\n本文\n佐藤花子さん";
        let hints = scan(text, &detection(text, &[]));
        assert_eq!(lines(&hints), vec![1, 3]);
    }

    #[test]
    fn a_repeated_honorific_reports_once() {
        let text = "山田様";
        let hints = scan(text, &detection(text, &[]));
        assert_eq!(hints.len(), 1);
    }
}
