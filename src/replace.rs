//! Replacement layer: opaque per-session pseudonym tokens.
//!
//! Token format: `⟦<label><pool id>⟧`, e.g. `⟦人名17⟧`.
//!
//! Invariants enforced here:
//! - One value per entity type maps to exactly one token per session. Matching
//!   is exact (after NFKC normalization): "田中" and "田中町" are distinct
//!   entities with distinct tokens, so restoring a token can never turn one
//!   raw value into another.
//! - The id pool is shuffled per session so token ids carry no positional
//!   meaning ("人名1" is not "the first person that appeared").
//! - The table lives only in process memory. The only way it leaves is the
//!   encrypted handoff envelope (gateway `/admin/export` -> seal ->
//!   `/admin/import`); there is no plaintext serialization.
//! - `import_record` never rebinds an existing token to a different value: on a
//!   token clash the local binding wins and the clash is reported, so an
//!   imported artifact can never silently restore to the wrong person.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::normalize::normalize_key;
use crate::types::{DetectionResult, EntityType};

pub const TOKEN_OPEN: char = '⟦';
pub const TOKEN_CLOSE: char = '⟧';
/// Same opening bracket as a string literal (regex construction, formatting).
pub const TOKEN_OPEN_STR: &str = "⟦";

/// Default number of distinct entities one session can bind. Larger than any
/// realistic entity count in one session; configurable via `session.capacity`.
pub const DEFAULT_SESSION_CAPACITY: u32 = 256;

/// The session has bound as many entities as its id pool holds. The request
/// that hit the limit fails; the process and its existing bindings survive.
/// Carries only the configured limit — never a raw value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionFull {
    pub capacity: u32,
}

impl std::fmt::Display for SessionFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "session pseudonym table is full (capacity {}); raise session.capacity or use session.scope = \"request\"",
            self.capacity
        )
    }
}

impl std::error::Error for SessionFull {}

/// One binding in the session mapping table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRecord {
    pub kind: EntityType,
    pub token: String,
    /// Type label inside the token.
    pub label: &'static str,
    /// Longest raw variant seen for this entity.
    pub value: String,
    pub occurrences: u64,
}

/// Snapshot of one binding for the encrypted handoff.
#[derive(Clone, Debug, Serialize)]
pub struct ExportRecord {
    pub token: String,
    pub value: String,
    pub occurrences: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replacement {
    pub start: usize,
    pub end: usize,
    pub token: String,
}

/// Result of merging one imported binding into a table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportStatus {
    Imported,
    Already,
    Conflict,
    Invalid,
}

impl ImportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ImportStatus::Imported => "imported",
            ImportStatus::Already => "already",
            ImportStatus::Conflict => "conflict",
            ImportStatus::Invalid => "invalid",
        }
    }
}

/// In-memory, session-scoped mapping table.
#[derive(Clone, Debug)]
pub struct PseudonymMap {
    pool: Vec<u32>,
    capacity: u32,
    records: Vec<(EntityType, String, TokenRecord)>,
    /// Every raw value ever assigned (NFKC keys). Consumed by the gateway's
    /// outbound leak gate; like the rest of the table it never leaves the
    /// process.
    seen: BTreeSet<String>,
}

impl Default for PseudonymMap {
    fn default() -> Self {
        Self::new()
    }
}

impl PseudonymMap {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_SESSION_CAPACITY)
    }

    /// Build a map whose id pool holds `capacity` distinct entities.
    pub fn with_capacity(capacity: u32) -> Self {
        let mut pool: Vec<u32> = (1..=capacity).collect();
        secure_shuffle(&mut pool);
        PseudonymMap {
            pool,
            capacity,
            records: Vec::new(),
            seen: BTreeSet::new(),
        }
    }

    /// Get-or-create the token for an entity occurrence. Only an exact value
    /// (NFKC-normalized) reuses a binding: containment is *not* unification
    /// ("田中" inside "田中町" is a different entity, and merging them would
    /// restore one raw value as the other).
    ///
    /// Returns [`SessionFull`] when every id is bound; the caller fails that
    /// request instead of panicking (a panic here used to poison the shared
    /// session mutex and take the whole gateway down).
    pub fn assign(
        &mut self,
        kind: EntityType,
        raw_value: &str,
    ) -> Result<TokenRecord, SessionFull> {
        let key_value = normalize_key(raw_value);
        self.seen.insert(key_value.clone());
        for (_, _, rec) in self.records.iter_mut() {
            if rec.kind != kind {
                continue;
            }
            if normalize_key(&rec.value) == key_value {
                rec.occurrences += 1;
                return Ok(rec.clone());
            }
        }
        let Some(token_id) = self.pool.pop() else {
            return Err(SessionFull {
                capacity: self.capacity,
            });
        };
        let label = kind.ja_label();
        let rec = TokenRecord {
            kind,
            token: format!("{TOKEN_OPEN}{label}{token_id}{TOKEN_CLOSE}"),
            label,
            value: raw_value.to_string(),
            occurrences: 1,
        };
        self.records.push((kind, key_value, rec.clone()));
        Ok(rec)
    }

    pub fn restore_value(&self, token: &str) -> Option<&str> {
        self.records
            .iter()
            .find(|(_, _, rec)| rec.token == token)
            .map(|(_, _, rec)| rec.value.as_str())
    }

    pub fn tokens(&self) -> Vec<String> {
        self.records
            .iter()
            .map(|(_, _, rec)| rec.token.clone())
            .collect()
    }

    /// NFKC-normalized raw values seen this session, variants included.
    pub fn raw_values(&self) -> Vec<String> {
        self.seen.iter().cloned().collect()
    }

    pub fn records(&self) -> Vec<TokenRecord> {
        self.records.iter().map(|(_, _, r)| r.clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Configured size of the id pool (mask#10's `session.capacity`).
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Ids never bound in this session: what `mask session` reports as the
    /// remaining pool. Same number `assign` fails against when it reaches 0.
    pub fn remaining(&self) -> usize {
        self.pool.len()
    }

    /// Snapshot of the table for the encrypted handoff. Contains raw values by
    /// definition; only ever leaves the process inside a sealed envelope.
    pub fn export_records(&self) -> Vec<ExportRecord> {
        self.records
            .iter()
            .map(|(_, _, rec)| ExportRecord {
                token: rec.token.clone(),
                value: rec.value.clone(),
                occurrences: rec.occurrences,
            })
            .collect()
    }

    /// Merge one exported binding into this table.
    ///
    /// Returns `Imported` | `Already` | `Conflict` | `Invalid`. On a token
    /// clash with a different value the local binding wins (`Conflict`): the
    /// token is never rebound, so restoring an imported artifact can never
    /// substitute the wrong person silently.
    pub fn import_record(&mut self, token: &str, value: &str, occurrences: u64) -> ImportStatus {
        let inner = token
            .strip_prefix(TOKEN_OPEN)
            .and_then(|rest| rest.strip_suffix(TOKEN_CLOSE))
            .unwrap_or("");
        let label = EntityType::ALL
            .into_iter()
            .map(|t| t.ja_label())
            .find(|label| {
                inner.strip_prefix(label).is_some_and(|rest| {
                    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
                })
            });
        let Some(label) = label else {
            return ImportStatus::Invalid;
        };
        if value.is_empty() {
            return ImportStatus::Invalid;
        }
        let kind = EntityType::from_ja_label(label).expect("label came from the table");
        for (_, _, rec) in self.records.iter() {
            if rec.token == token {
                if normalize_key(&rec.value) == normalize_key(value) {
                    return ImportStatus::Already;
                }
                return ImportStatus::Conflict;
            }
        }
        let key_value = normalize_key(value);
        self.seen.insert(key_value.clone());
        let digits = &inner[label.len()..];
        if let Ok(token_id) = digits.parse::<u32>() {
            if let Some(pos) = self.pool.iter().position(|&id| id == token_id) {
                self.pool.remove(pos);
            }
        }
        let mut key = key_value.clone();
        if self
            .records
            .iter()
            .any(|(k, v, _)| *k == kind && *v == key_value)
        {
            // value already known under another token: keep both bindings so
            // imported artifacts restore; the local token keeps winning in
            // assign() (records scan in insertion order)
            key = format!("{key_value}{token}");
        }
        self.records.push((
            kind,
            key,
            TokenRecord {
                kind,
                token: token.to_string(),
                label,
                value: value.to_string(),
                occurrences,
            },
        ));
        ImportStatus::Imported
    }
}

/// Map every detected entity span to its token (no text mutation here).
pub fn compute_replacements(
    result: &DetectionResult,
    pseudonyms: &mut PseudonymMap,
) -> Result<Vec<Replacement>, SessionFull> {
    let mut replacements = Vec::with_capacity(result.entities.len());
    for ent in &result.entities {
        let rec = pseudonyms.assign(ent.kind, &ent.text)?;
        replacements.push(Replacement {
            start: ent.start,
            end: ent.end,
            token: rec.token,
        });
    }
    Ok(replacements)
}

/// Build the masked text. Replacements are sorted so spans never shift.
pub fn apply_replacements(text: &str, mut replacements: Vec<Replacement>) -> String {
    replacements.sort_by_key(|r| r.start);
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for r in replacements {
        out.push_str(&text[cursor..r.start]);
        out.push_str(&r.token);
        cursor = r.end;
    }
    out.push_str(&text[cursor..]);
    out
}

pub fn mask_text(
    result: &DetectionResult,
    pseudonyms: &mut PseudonymMap,
) -> Result<String, SessionFull> {
    let replacements = compute_replacements(result, pseudonyms)?;
    Ok(apply_replacements(&result.text, replacements))
}

/// Fisher-Yates with a CSPRNG so token ids carry no positional meaning.
fn secure_shuffle(items: &mut [u32]) {
    let len = items.len();
    for i in (1..len).rev() {
        let j = secure_random_below((i + 1) as u64) as usize;
        items.swap(i, j);
    }
}

/// Uniform random value in `0..bound` from the OS CSPRNG (rejection sampling,
/// no modulo bias).
fn secure_random_below(bound: u64) -> u64 {
    debug_assert!(bound > 0);
    let zone = u64::MAX - (u64::MAX % bound);
    loop {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).expect("OS CSPRNG unavailable");
        let value = u64::from_le_bytes(buf);
        if value < zone {
            return value % bound;
        }
    }
}

/// Random hex string of `n` bytes (used for the per-response nonce).
pub fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG unavailable");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_session_refuses_only_new_values() {
        let mut map = PseudonymMap::with_capacity(2);
        let first = map.assign(EntityType::Person, "山田太郎").unwrap();
        let second = map.assign(EntityType::Person, "鈴木一郎").unwrap();
        assert_ne!(first.token, second.token);

        let full = map.assign(EntityType::Person, "佐藤次郎").unwrap_err();
        assert_eq!(full.capacity, 2);

        // Existing bindings keep working; the pool did not shrink on failure.
        assert_eq!(
            map.assign(EntityType::Person, "山田太郎").unwrap().token,
            first.token
        );
        assert_eq!(map.restore_value(&first.token), Some("山田太郎"));
    }
}
