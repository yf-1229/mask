//! User-attested dictionary detection layer.
//!
//! The dictionary holds known pseudonyms/real names discovered during
//! operation (detection misses registered by the operator). Entries are exact
//! matches, highest trust after rules.
//!
//! Three properties keep the file trustworthy, not just the match:
//!
//! - [`UserDictionary::parse_report`] reports what could not be used as counts
//!   and line numbers only — never values — so `mask dict check` can fail on a
//!   typo instead of silently shrinking recall.
//! - [`UserDictionary::merge_additive`] is the reload rule: additions and type
//!   changes apply, removals wait for a restart. A running gateway therefore
//!   only ever gains coverage when the file changes; a reload cannot be used to
//!   quiet detection.
//! - [`append_or_update`] is the one writer: it validates the term, preserves
//!   comments and line endings, and replaces the file atomically so a reader
//!   never sees half a line.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use crate::normalize::next_boundary;
use crate::types::{Entity, EntityType, Source, BAND_EXACT};

/// Longest-match dictionary of known sensitive terms.
#[derive(Clone, Debug, Default)]
pub struct UserDictionary {
    /// Sorted longest-first so "山田太郎" wins over "山田".
    terms: Vec<(String, EntityType)>,
}

/// What one parse of a TSV document could not use. Values never appear here:
/// only counts and 1-based line numbers, so a report can be logged or shown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParseReport {
    pub terms: usize,
    pub skipped: usize,
    pub skipped_lines: Vec<usize>,
}

/// What an additive reload changed relative to the in-memory table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub added: usize,
    pub updated: usize,
    /// Kept in memory although the file no longer lists them (restart clears).
    pub kept: usize,
    pub terms: usize,
}

impl MergeReport {
    pub fn changed(self) -> bool {
        self.added + self.updated > 0
    }
}

/// What [`append_or_update`] did to the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddOutcome {
    Added,
    Updated { from: Option<EntityType> },
    Unchanged,
}

/// Validate a term before it can reach the TSV. Returns the trimmed term.
///
/// The rules are the file format's, not a policy: a tab would split the line
/// into the wrong columns, a newline would forge a second entry, and a leading
/// `#` would turn the entry into a comment that the next load skips.
pub fn validate_term(term: &str) -> Result<&str, &'static str> {
    let term = term.trim();
    if term.is_empty() {
        return Err("term is empty");
    }
    if term.chars().any(|c| matches!(c, '\t' | '\n' | '\r')) {
        return Err("term must not contain tabs or newlines");
    }
    if term.starts_with('#') {
        return Err("term must not start with '#' (that line is a comment)");
    }
    if term.chars().count() > 256 {
        return Err("term is longer than 256 characters");
    }
    Ok(term)
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
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
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
        Self::parse_report(text).0
    }

    /// Parse TSV content and report what was skipped (counts and line numbers).
    pub fn parse_report(text: &str) -> (Self, ParseReport) {
        // A byte-order mark is common when the file came from a spreadsheet;
        // it belongs to the file, not to the first term.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut merged: HashMap<String, EntityType> = HashMap::new();
        let mut report = ParseReport::default();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split('\t');
            let term = parts.next().unwrap_or("").trim();
            let kind = parts.next().and_then(EntityType::from_name);
            match kind {
                Some(kind) if !term.is_empty() => {
                    merged.insert(term.to_string(), kind);
                }
                _ => {
                    report.skipped += 1;
                    report.skipped_lines.push(index + 1);
                }
            }
        }
        let terms: Vec<(String, EntityType)> = merged.into_iter().collect();
        let mut dict = UserDictionary { terms };
        dict.sort();
        report.terms = dict.terms.len();
        (dict, report)
    }

    /// Merge a freshly loaded file into this dictionary, additively.
    ///
    /// New terms and changed types apply; terms that vanished from the file are
    /// kept so that a live reload can never reduce coverage — removal is a
    /// restart decision, made by a human who knows the mapping table will be
    /// cleared too.
    pub fn merge_additive(&mut self, newer: &UserDictionary) -> MergeReport {
        let mut report = MergeReport::default();
        let current: HashMap<&str, EntityType> = self
            .terms
            .iter()
            .map(|(term, kind)| (term.as_str(), *kind))
            .collect();
        let incoming: HashSet<&str> = newer.terms.iter().map(|(term, _)| term.as_str()).collect();

        let mut additions: Vec<(String, EntityType)> = Vec::new();
        let mut updates: Vec<(String, EntityType)> = Vec::new();
        for (term, kind) in &newer.terms {
            match current.get(term.as_str()) {
                None => additions.push((term.clone(), *kind)),
                Some(existing) if existing != kind => updates.push((term.clone(), *kind)),
                Some(_) => {}
            }
        }
        drop(current);
        report.kept = self
            .terms
            .iter()
            .filter(|(term, _)| !incoming.contains(term.as_str()))
            .count();
        drop(incoming);

        report.added = additions.len();
        report.updated = updates.len();
        for (term, kind) in additions {
            self.terms.push((term, kind));
        }
        for (term, kind) in updates {
            if let Some(slot) = self.terms.iter_mut().find(|(t, _)| *t == term) {
                slot.1 = kind;
            }
        }
        if report.changed() {
            self.sort();
        }
        report.terms = self.terms.len();
        report
    }

    /// Registered type for an exact term, if any.
    pub fn get(&self, term: &str) -> Option<EntityType> {
        self.terms
            .iter()
            .find(|(t, _)| t == term)
            .map(|(_, kind)| *kind)
    }

    /// Every term and its type (length-ordered; sort for display if needed).
    pub fn entries(&self) -> impl Iterator<Item = (&str, EntityType)> {
        self.terms.iter().map(|(term, kind)| (term.as_str(), *kind))
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

/// Add a term to `path`, or correct its type in place. Creates the file when
/// missing.
///
/// The rewrite is atomic (temp file in the same directory, then rename) and
/// keeps comments, unrelated lines and their line endings: an editing typo
/// cannot leave a reader with a truncated dictionary.
pub fn append_or_update(path: &Path, term: &str, kind: EntityType) -> io::Result<AddOutcome> {
    let term = validate_term(term)
        .map_err(|reason| io::Error::new(io::ErrorKind::InvalidInput, reason))?;
    let existing = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error),
    };
    // Keep a spreadsheet's byte-order mark, but do not let it hide the first
    // term from the duplicate check.
    let (bom, existing) = match existing.strip_prefix('\u{feff}') {
        Some(rest) => ("\u{feff}", rest),
        None => ("", existing.as_str()),
    };
    let canonical = format!("{term}\t{kind}");
    let eol = if existing.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };

    let mut matched = false;
    let mut changed = false;
    let mut first_from: Option<EntityType> = None;
    let mut out = String::with_capacity(bom.len() + existing.len() + canonical.len() + 2);
    out.push_str(bom);
    for line in existing.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let body = body.strip_suffix('\r').unwrap_or(body);
        let trimmed = body.trim();
        let is_entry = !trimmed.is_empty() && !trimmed.starts_with('#');
        let first = body.split('\t').next().unwrap_or("").trim();
        if is_entry && first == term {
            let from = body.split('\t').nth(1).and_then(EntityType::from_name);
            if !matched {
                matched = true;
                first_from = from;
            }
            changed |= from != Some(kind);
            // Duplicate lines for the same term are folded onto one type too.
            let ending = &line[body.len()..];
            out.push_str(&canonical);
            out.push_str(ending);
        } else {
            out.push_str(line);
        }
    }
    let outcome = if !matched {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push_str(eol);
        }
        out.push_str(&canonical);
        out.push_str(eol);
        AddOutcome::Added
    } else if changed {
        AddOutcome::Updated { from: first_from }
    } else {
        AddOutcome::Unchanged
    };
    write_atomic(path, &out)?;
    Ok(outcome)
}

/// Replace `path` with `text` atomically (same directory, temp file + rename).
fn write_atomic(path: &Path, text: &str) -> io::Result<()> {
    use std::io::Write;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "dictionary path has no file name",
        )
    })?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    {
        let mut file = std::fs::File::create(&temp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
    }
    // A dictionary the operator made 0600 stays 0600 across a rewrite; a new
    // one is created 0600 on Unix from the start (it holds real names).
    match std::fs::metadata(path) {
        Ok(metadata) => {
            let _ = std::fs::set_permissions(&temp, metadata.permissions());
        }
        Err(_) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
    std::fs::rename(&temp, path)
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
