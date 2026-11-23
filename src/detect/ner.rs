//! Native (offline, dependency-free) Japanese person-name detection.
//!
//! The reference implementation used spaCy + ja_ginza, which cannot be shipped
//! as a native binary on Windows/macOS/Linux without dragging a Python runtime
//! and a ~500 MB model along. This detector keeps the same role — find person
//! mentions that structural rules cannot see — with a self-contained lexicon
//! strategy.
//!
//! A lexicon match is not enough on its own: `出口` is an exit far more often
//! than a surname, and `根本的` is an adverb. A surname is accepted as a person
//! only in one of these contexts:
//!
//! 1. an honorific follows (`田中さん`, `山田様`, `佐藤課長`),
//! 2. a family+given two-element name follows (`山田太郎`, `佐藤花子`), unless
//!    the span ends in a place/derivative suffix (`田中町`, `根本的`),
//! 3. a structured name field precedes it on the same line (`氏名: 田中`),
//! 4. for unambiguous surnames only, a particle follows (`山田が`, `佐藤は`);
//!    for [`stoplist.txt`] entries a bare particle is exactly the ambiguous
//!    case (`出口は混んでいる`, `大川の水`), so it is not accepted.
//!
//! Span extension still stops at honorifics, titles and particles, so
//! `山田太郎様` masks the name, not the honorific.
//!
//! ## Adding a surname
//!
//! The lexicon is data (`surnames.txt`), so a reviewed surname is a one-line
//! change with no Rust. **Every lexicon addition must ship with a
//! false-positive case** in `tests/corpus/false_positive.txt` (and, when a
//! positive is expected, a canary case in `tests/corpus/canary.txt`): a
//! surname that collides with an everyday word is only reviewed once both
//! directions are pinned. The two corpus files are parsed by `tests/`, not by
//! this module, so adding a case needs no code either.
//!
//! Operator-supplied names that are not in the lexicon belong in the
//! dictionary layer (`dictionary.tsv`), which is exact and user-attested.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use crate::types::{Entity, EntityType, Source};

/// Honorifics and titles that mark a preceding surname as a person.
const HONORIFICS: &[&str] = &[
    "さん",
    "ちゃん",
    "くん",
    "さま",
    "様",
    "氏",
    "君",
    "殿",
    "どの",
    "先生",
    "課長",
    "部長",
    "社長",
    "専務",
    "常務",
    "係長",
    "所長",
    "店長",
    "院長",
    "教授",
];

/// Standards that terminate a name span; a given name never continues past one.
const STOP_WORDS: &[&str] = &[
    "株式会社",
    "有限会社",
    "合同会社",
    "銀行",
    "支店",
    "本店",
    "様方",
    "気付",
    "宛先",
    "宛",
    "様",
    "氏",
    "君",
    "殿",
    "先生",
    "課長",
    "部長",
    "社長",
    "専務",
    "常務",
    "係長",
    "所長",
    "店長",
    "院長",
    "教授",
    "さん",
    "ちゃん",
    "くん",
    "さま",
    "どの",
];

/// Particles that can follow an unambiguous person noun (`山田が来た`). They
/// are weaker evidence than an honorific: a place or an adverb takes them too,
/// which is why ambiguous surnames (`stoplist.txt`) do not accept this case.
const PARTICLES: &[char] = &['が', 'は', 'に', 'を', 'と', 'で', 'へ', 'も'];

/// Labels that introduce a person name in a structured field. The label must
/// be on the same line, before the surname, and followed only by separators.
const NAME_FIELDS: &[&str] = &[
    "氏名",
    "お名前",
    "名前",
    "姓名",
    "担当者",
    "ご担当",
    "担当",
    "宛名",
    "受取人",
    "契約者",
    "申込者",
];

/// Suffixes of place names, administrative divisions and derivational
/// compounds. A family+given candidate ending in one of these (`田中町`,
/// `山下公園`, `根本的`) is a compound, not a personal name.
const NON_NAME_SUFFIXES: &[&str] = &[
    "町", "市", "区", "村", "郡", "県", "都", "府", "道", "駅", "線", "的", "通", "沿", "公園",
    "街道", "神社", "寺院", "城", "港", "空港", "所", "庁", "署", "校", "館", "局", "園", "社",
    "会",
];

/// Common Japanese surnames for the offline detector, one per line in
/// `surnames.txt` (`#` comments and blanks ignored). Data, not code: adding a
/// reviewed surname is a one-line change — together with its false-positive
/// corpus case (see the module docs).
const SURNAMES_DATA: &str = include_str!("surnames.txt");

/// Surnames that are also everyday words; see `stoplist.txt`.
const STOPLIST_DATA: &str = include_str!("stoplist.txt");

fn surnames() -> &'static [&'static str] {
    static SURNAMES: LazyLock<Vec<&'static str>> = LazyLock::new(|| parse_lexicon(SURNAMES_DATA));
    &SURNAMES
}

fn stoplist() -> &'static HashSet<&'static str> {
    static STOPLIST: LazyLock<HashSet<&'static str>> =
        LazyLock::new(|| parse_lexicon(STOPLIST_DATA).into_iter().collect());
    &STOPLIST
}

fn parse_lexicon(data: &'static str) -> Vec<&'static str> {
    data.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

#[derive(Clone, Debug)]
struct Node {
    children: HashMap<char, usize>,
    terminal: bool,
}

/// Offline Japanese name detector (see module docs).
#[derive(Clone, Debug)]
pub struct NativeNer {
    nodes: Vec<Node>,
}

impl Default for NativeNer {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeNer {
    pub fn new() -> Self {
        let mut nodes = vec![Node {
            children: HashMap::new(),
            terminal: false,
        }];
        for surname in surnames() {
            let mut current = 0usize;
            for c in surname.chars() {
                let next = match nodes[current].children.get(&c) {
                    Some(&idx) => idx,
                    None => {
                        nodes.push(Node {
                            children: HashMap::new(),
                            terminal: false,
                        });
                        let idx = nodes.len() - 1;
                        nodes[current].children.insert(c, idx);
                        idx
                    }
                };
                current = next;
            }
            nodes[current].terminal = true;
        }
        NativeNer { nodes }
    }

    /// Longest surname match starting at `start` (a char boundary).
    fn longest_surname(&self, text: &str, start: usize) -> Option<usize> {
        let mut node = 0usize;
        let mut best: Option<usize> = None;
        for (offset, c) in text[start..].char_indices() {
            let Some(&next) = self.nodes[node].children.get(&c) else {
                break;
            };
            node = next;
            if self.nodes[node].terminal {
                best = Some(start + offset + c.len_utf8());
            }
        }
        best
    }

    pub fn scan(&self, text: &str) -> Vec<Entity> {
        self.scan_explained(text)
            .into_iter()
            .map(|(entity, _)| entity)
            .collect()
    }

    /// Like [`Self::scan`], with the rule that accepted each span. `--explain`
    /// uses it; detection itself ignores the reason.
    pub fn scan_explained(&self, text: &str) -> Vec<(Entity, &'static str)> {
        if text.trim().is_empty() {
            return Vec::new();
        }
        let mut out: Vec<(Entity, &'static str)> = Vec::new();
        let mut index = 0usize;
        while index < text.len() {
            let Some(surname_end) = self.longest_surname(text, index) else {
                index = next_char_boundary(text, index);
                continue;
            };
            let surname = &text[index..surname_end];
            let extended_end = extend_given(text, surname_end);
            let has_given = extended_end > surname_end;
            let is_full_name = has_given && !ends_in_non_name_suffix(&text[index..extended_end]);

            let (end, reason) = if honorific_at(text, extended_end).is_some() {
                let reason = if has_given {
                    "family+given name + honorific"
                } else {
                    "surname + honorific"
                };
                (extended_end, reason)
            } else if is_full_name {
                (extended_end, "family+given name")
            } else if in_name_field(text, index) {
                (surname_end, "structured name field")
            } else if !is_ambiguous(surname) && particle_at(text, surname_end).is_some() {
                (surname_end, "surname + particle")
            } else {
                // No context: skip the match, not the rest of the text.
                index = next_char_boundary(text, index);
                continue;
            };

            out.push((
                Entity::new(
                    EntityType::Person,
                    index,
                    end,
                    &text[index..end],
                    0.85,
                    Source::Ner,
                ),
                reason,
            ));
            // Always forward: a match is at least two bytes long.
            index = end;
        }
        out
    }
}

/// Extend a surname with up to three name characters for the given name.
fn extend_given(text: &str, start: usize) -> usize {
    let mut end = start;
    let mut extra = 0usize;
    while extra < 3 {
        let rest = &text[end..];
        if STOP_WORDS.iter().any(|w| rest.starts_with(w)) {
            break;
        }
        let Some(c) = rest.chars().next() else {
            break;
        };
        if !is_name_char(c) {
            break;
        }
        end += c.len_utf8();
        extra += 1;
    }
    end
}

fn honorific_at(text: &str, index: usize) -> Option<&'static str> {
    let rest = text.get(index..)?;
    HONORIFICS
        .iter()
        .copied()
        .find(|word| rest.starts_with(word))
}

fn particle_at(text: &str, index: usize) -> Option<char> {
    text.get(index..)?
        .chars()
        .next()
        .filter(|c| PARTICLES.contains(c))
}

fn is_ambiguous(surname: &str) -> bool {
    stoplist().contains(surname)
}

fn ends_in_non_name_suffix(span: &str) -> bool {
    NON_NAME_SUFFIXES
        .iter()
        .any(|suffix| span.ends_with(suffix))
}

/// True when the surname sits in a `氏名: …` / `担当 山田` style field on its
/// own line. Same-line only: a label in the previous paragraph is not evidence.
fn in_name_field(text: &str, start: usize) -> bool {
    let line_start = text[..start].rfind('\n').map_or(0, |i| i + 1);
    let prefix = text[line_start..start].trim_end();
    let prefix = prefix.trim_end_matches([':', '：', '=', '＝', '|', '｜', ' ', '　']);
    NAME_FIELDS.iter().any(|label| prefix.ends_with(label))
}

fn next_char_boundary(text: &str, index: usize) -> usize {
    let mut i = index + 1;
    while i < text.len() && !text.is_char_boundary(i) {
        i += 1;
    }
    i.min(text.len())
}

/// Characters that may continue a personal name (kanji, 々, ー, katakana).
/// Hiragana is excluded so particles and honorifics terminate the span.
fn is_name_char(c: char) -> bool {
    matches!(c,
        '\u{4e00}'..='\u{9fff}'
        | '々' | 'ー'
        | '\u{30a1}'..='\u{30fa}'
        | '\u{3400}'..='\u{4dbf}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surname_data_is_clean() {
        let names = surnames();
        assert!(names.len() >= 500, "lexicon shrank: {}", names.len());
        let unique: HashSet<&str> = names.iter().copied().collect();
        assert_eq!(unique.len(), names.len(), "duplicate surname");
        for name in names {
            let length = name.chars().count();
            assert!(
                (2..=4).contains(&length),
                "{name:?} has {length} characters"
            );
            assert!(
                name.chars()
                    .all(|c| matches!(c, '\u{4e00}'..='\u{9fff}' | '々' | '\u{3400}'..='\u{4dbf}')),
                "{name:?} has a character outside the surname ranges"
            );
        }
    }

    #[test]
    fn stoplist_data_is_clean() {
        let entries = parse_lexicon(STOPLIST_DATA);
        assert!(!entries.is_empty(), "stoplist is empty");
        let unique: HashSet<&str> = entries.iter().copied().collect();
        assert_eq!(unique.len(), entries.len(), "duplicate stoplist entry");
        for entry in entries {
            assert!(
                entry.chars().count() >= 2,
                "{entry:?} is too short to be a surname"
            );
        }
    }

    #[test]
    fn the_detector_uses_the_data_file() {
        let detector = NativeNer::new();
        let found = detector.scan("浜田様と北村さん");
        assert_eq!(found.len(), 2, "{found:?}");
    }

    #[test]
    fn a_surname_needs_context_but_honorifics_are_enough() {
        let detector = NativeNer::new();
        let bare = detector.scan("出口は混んでいる。根本的に違う。田中町に住む。");
        assert!(bare.is_empty(), "{bare:?}");
        let named = detector.scan("田中さんに確認。山田太郎です。氏名: 大川");
        let texts: Vec<&str> = named.iter().map(|e| e.text.as_str()).collect();
        assert_eq!(texts, ["田中", "山田太郎", "大川"], "{named:?}");
    }
}
