//! Outbound leak gate: the last line of defense before anything leaves.
//!
//! Masking covers the request shapes the gateway knows about; the gate is a
//! positive control behind it. Every payload about to leave the gateway is
//! walked as a JSON structure and every string in it — object keys included —
//! is checked (NFKC-normalized, containment) against the raw entity values the
//! session has ever detected. A hit means a field the masking layer does not
//! cover carries real PII, so the request is refused before it reaches the
//! network (fail closed).
//!
//! What this guarantees: no value the session has detected can leave the
//! machine, on any field, path, or header — even where masking missed the spot
//! (unanticipated fields, detection misses on repeat mentions, client headers).
//! What it cannot catch: values never detected anywhere; that is the detection
//! layer's job, regression-gated by the canary corpus.
//!
//! Reporting is redacted by construction: a [`Leak`] keeps only a hash prefix
//! of the offending value and a structured path whose object keys are stored
//! as hashes. Logs and the block response are rendered from the same
//! [`Leak::path_string`], so neither can regress independently into printing a
//! raw key.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::normalize::normalize_key;

/// Shorter values are noise (single kana/kanji match everywhere).
pub const MIN_VALUE_LEN: usize = 2;

/// Bytes of sha256 shown in paths and value prefixes (8 hex chars).
const HASH_PREFIX_BYTES: usize = 4;

fn hash_prefix(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .take(HASH_PREFIX_BYTES)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// One segment of a leak path.
///
/// Object keys are *never* stored raw: `Key` holds the sha256 hex prefix of the
/// key, so `Debug`, logs and serialized responses cannot leak it. Array indices
/// and code-owned literals stay readable so "which field" remains diagnosable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathSeg {
    /// Object key, as its sha256 hex prefix.
    Key(String),
    /// Array index.
    Index(usize),
    /// Literal path component owned by the code (`header`, `(key)`).
    Field(&'static str),
}

/// Render a path from structured segments. The one renderer shared by the log
/// line and the HTTP error body.
pub fn render_path(segments: &[PathSeg]) -> String {
    if segments.is_empty() {
        return "<root>".to_string();
    }
    let mut out = String::new();
    for segment in segments {
        match segment {
            PathSeg::Key(hash) => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str("key#");
                out.push_str(hash);
            }
            PathSeg::Index(index) => {
                use std::fmt::Write;
                let _ = write!(out, "[{index}]");
            }
            PathSeg::Field(name) => {
                if !out.is_empty() && !name.starts_with(['(', '[']) {
                    out.push('.');
                }
                out.push_str(name);
            }
        }
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leak {
    /// sha256 hex prefix of the offending value; the value itself is dropped.
    pub value_sha256_prefix: String,
    /// Where in the payload it was found.
    pub path: Vec<PathSeg>,
}

impl Leak {
    pub fn path_string(&self) -> String {
        render_path(&self.path)
    }

    /// The single WARN line the gate emits. Built here so the log and the
    /// response share one redaction surface.
    pub fn log_line(&self, source: &str) -> String {
        format!(
            "leak gate: {source} {} (value sha256:{})",
            self.path_string(),
            self.value_sha256_prefix
        )
    }
}

fn candidates(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter(|v| v.chars().count() >= MIN_VALUE_LEN)
        .cloned()
        .collect()
}

/// Return known raw values found anywhere in a JSON-like structure.
///
/// `values` must be NFKC-normalized (the pseudonym table's `raw_values` is).
/// Matching is containment, so partial re-mentions are caught too.
pub fn find_leaks(payload: &Value, values: &[String]) -> Vec<Leak> {
    let candidates = candidates(values);
    if candidates.is_empty() {
        return Vec::new();
    }
    let mut leaks: Vec<Leak> = Vec::new();

    fn check(text: &str, path: &[PathSeg], candidates: &[String], leaks: &mut Vec<Leak>) {
        let hay = normalize_key(text);
        for value in candidates {
            if hay.contains(value.as_str()) {
                leaks.push(Leak {
                    value_sha256_prefix: hash_prefix(value.as_bytes()),
                    path: path.to_vec(),
                });
            }
        }
    }

    fn walk(node: &Value, path: &mut Vec<PathSeg>, candidates: &[String], leaks: &mut Vec<Leak>) {
        match node {
            Value::String(text) => check(text, path, candidates, leaks),
            Value::Object(map) => {
                for (key, child) in map {
                    path.push(PathSeg::Key(hash_prefix(key.as_bytes())));
                    path.push(PathSeg::Field("(key)"));
                    check(key, path, candidates, leaks);
                    path.pop();
                    walk(child, path, candidates, leaks);
                    path.pop();
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    path.push(PathSeg::Index(index));
                    walk(child, path, candidates, leaks);
                    path.pop();
                }
            }
            _ => {}
        }
    }

    let mut path = Vec::new();
    walk(payload, &mut path, &candidates, &mut leaks);
    leaks
}

/// Check forwarded header values; reported as `header.key#<hash>`.
pub fn find_header_leaks(headers: &[(String, String)], values: &[String]) -> Vec<Leak> {
    let candidates = candidates(values);
    if candidates.is_empty() {
        return Vec::new();
    }
    let mut leaks: Vec<Leak> = Vec::new();
    for (name, value) in headers {
        let hay = normalize_key(value);
        let path = vec![
            PathSeg::Field("header"),
            PathSeg::Key(hash_prefix(name.to_ascii_lowercase().as_bytes())),
        ];
        for candidate in &candidates {
            if hay.contains(candidate.as_str()) {
                leaks.push(Leak {
                    value_sha256_prefix: hash_prefix(candidate.as_bytes()),
                    path: path.clone(),
                });
            }
        }
    }
    leaks
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_hits_and_nested_values_never_render_raw_keys() {
        let values = vec!["山田太郎".to_string()];
        let payload = json!({"metadata": {"山田太郎": ["山田太郎"]}});
        let leaks = find_leaks(&payload, &values);
        // value-under-key and key-hit itself
        assert_eq!(leaks.len(), 2, "{leaks:?}");
        for leak in &leaks {
            let line = leak.log_line("v1/chat");
            assert!(!line.contains("山田太郎"), "{line}");
            assert!(!line.contains("metadata"), "{line}");
            assert!(line.contains("key#"), "{line}");
            assert_eq!(leak.value_sha256_prefix, "6b0e1c8c");
        }
        assert!(leaks.iter().any(|l| l.path_string().ends_with("(key)")));
        assert!(leaks.iter().any(|l| l.path_string().ends_with("[0]")));
    }

    #[test]
    fn root_value_renders_as_root() {
        let leaks = find_leaks(&json!("山田太郎"), &["山田太郎".to_string()]);
        assert_eq!(leaks[0].path_string(), "<root>");
    }

    #[test]
    fn header_names_are_hashed() {
        let headers = vec![("X-Title".to_string(), "taro@example.com".to_string())];
        let leaks = find_header_leaks(&headers, &["taro@example.com".to_string()]);
        assert_eq!(leaks.len(), 1);
        assert_eq!(
            leaks[0].path_string(),
            "header.key#ec4d3f7d",
            "header name hash"
        );
        assert!(!leaks[0].log_line("v1/chat").contains("X-Title"));
    }
}
