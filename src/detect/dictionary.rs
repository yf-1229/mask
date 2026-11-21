//! User-attested dictionary detection layer.
//!
//! The dictionary holds known pseudonyms/real names discovered during
//! operation (detection misses registered by the operator). Entries are exact
//! matches, highest trust after rules. Loaded once at startup; reload is
//! explicit.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::normalize::next_boundary;
use crate::types::{Entity, EntityType, Source, BAND_EXACT};

/// Longest-match dictionary of known sensitive terms.
#[derive(Clone, Debug, Default)]
pub struct UserDictionary {
    /// Sorted longest-first so "山田太郎" wins over "山田".
    terms: Vec<(String, EntityType)>,
}

impl UserDictionary {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_terms<I>(terms: I) -> Self
    where
        I: IntoIterator<Item = (String, EntityType)>,
    {
        let mut dict = UserDictionary { terms: Vec::new() };
        for (term, kind) in terms {
            dict.insert(term, kind);
        }
        dict
    }

    fn sort(&mut self) {
        // longest first so "山田太郎" is tried before "山田"
        self.terms
            .sort_by_key(|(term, _)| std::cmp::Reverse(term.chars().count()));
    }

    fn insert(&mut self, term: String, kind: EntityType) {
        if term.is_empty() {
            return;
        }
        if let Some(slot) = self.terms.iter_mut().find(|(t, _)| *t == term) {
            slot.1 = kind;
        } else {
            self.terms.push((term, kind));
        }
        self.sort();
    }

    pub fn add(&mut self, term: &str, kind: EntityType) {
        self.insert(term.to_string(), kind);
    }

    /// Load TSV lines: `<term>\t<type>`. A missing file yields an empty
    /// dictionary (same as the reference implementation).
    pub fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path: PathBuf = path.as_ref().to_path_buf();
        if !path.exists() {
            return Ok(UserDictionary::new());
        }
        let text = std::fs::read_to_string(&path)?;
        Ok(Self::parse(&text))
    }

    /// Parse TSV content; blank lines and `#` comments are ignored, unknown
    /// types are skipped.
    pub fn parse(text: &str) -> Self {
        let mut dict = UserDictionary::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split('\t');
            let term = parts.next().unwrap_or("");
            let Some(kind) = parts.next().and_then(EntityType::from_name) else {
                continue;
            };
            dict.insert(term.to_string(), kind);
        }
        dict
    }

    /// Number of registered terms (indicator surface; contents stay put).
    pub fn size(&self) -> usize {
        self.terms.len()
    }

    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    pub fn scan(&self, text: &str) -> Vec<Entity> {
        let mut found: Vec<Entity> = Vec::new();
        let mut taken: Vec<(usize, usize)> = Vec::new();
        for (term, kind) in &self.terms {
            let mut start = 0usize;
            while start <= text.len() {
                let Some(pos) = text[start..].find(term.as_str()) else {
                    break;
                };
                let idx = start + pos;
                let span = (idx, idx + term.len());
                if !taken.iter().any(|&(s, e)| s < span.1 && span.0 < e) {
                    taken.push(span);
                    found.push(Entity::new(
                        *kind,
                        span.0,
                        span.1,
                        term.clone(),
                        BAND_EXACT,
                        Source::Dict,
                    ));
                }
                start = next_boundary(text, idx);
            }
        }
        found.sort_by_key(|e| e.start);
        found
    }
}

/// Convenience: build a dictionary from an iterator of `(term, type name)`.
pub fn from_named_terms<I, S>(terms: I) -> UserDictionary
where
    I: IntoIterator<Item = (S, S)>,
    S: AsRef<str>,
{
    let map: HashMap<String, EntityType> = terms
        .into_iter()
        .filter_map(|(term, kind)| {
            EntityType::from_name(kind.as_ref()).map(|k| (term.as_ref().to_string(), k))
        })
        .collect();
    UserDictionary::from_terms(map)
}
