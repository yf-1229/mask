//! Native (offline, dependency-free) Japanese person-name detection.
//!
//! The reference implementation used spaCy + ja_ginza, which cannot be shipped
//! as a native binary on Windows/macOS/Linux without dragging a Python runtime
//! and a ~500 MB model along. This detector keeps the same role — find person
//! mentions that structural rules cannot see — with a self-contained lexicon
//! strategy:
//!
//! 1. longest-match over a lexicon of common Japanese surnames (2-4 chars),
//! 2. extend with up to three name characters for the given name,
//! 3. stop at honorifics, titles and particles so "山田太郎様" masks the name,
//!    not the honorific.
//!
//! Consistent with the project's recall-first policy, a bare surname is still
//! masked: a false positive only costs a token, a miss leaks a person.
//! The lexicon is data (`surnames.txt`), so a reviewed surname is a one-line
//! change with no Rust. Operator-supplied names that are not in it belong in the
//! dictionary layer (`dictionary.tsv`), which is exact and user-attested.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::types::{Entity, EntityType, Source};

/// Honorifics / titles that terminate a name span.
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

/// Common Japanese surnames for the offline detector, one per line in
/// `surnames.txt` (`#` comments and blanks ignored). Data, not code: adding a
/// reviewed surname is a one-line change.
const SURNAMES_DATA: &str = include_str!("surnames.txt");

fn surnames() -> &'static [&'static str] {
    static SURNAMES: OnceLock<Vec<&'static str>> = OnceLock::new();
    SURNAMES.get_or_init(|| {
        SURNAMES_DATA
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect()
    })
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
        if text.trim().is_empty() {
            return Vec::new();
        }
        let mut out: Vec<Entity> = Vec::new();
        let mut index = 0usize;
        while index < text.len() {
            let Some(surname_end) = self.longest_surname(text, index) else {
                index = next_char_boundary(text, index);
                continue;
            };
            let mut end = surname_end;
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
            let span_text = &text[index..end];
            out.push(Entity::new(
                EntityType::Person,
                index,
                end,
                span_text,
                0.85,
                Source::Ner,
            ));
            // Always forward: a match is at least two bytes long.
            index = end;
        }
        out
    }
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
    use std::collections::HashSet;

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
    fn the_detector_uses_the_data_file() {
        let detector = NativeNer::new();
        let found = detector.scan("浜田様と北村さん");
        assert_eq!(found.len(), 2, "{found:?}");
    }
}
