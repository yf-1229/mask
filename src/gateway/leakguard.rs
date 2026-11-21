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

use serde_json::Value;

use crate::normalize::normalize_key;

/// Shorter values are noise (single kana/kanji match everywhere).
pub const MIN_VALUE_LEN: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leak {
    /// NFKC-normalized raw value found.
    pub value: String,
    /// Where in the payload it was found.
    pub path: String,
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

    fn check(text: &str, path: &str, candidates: &[String], leaks: &mut Vec<Leak>) {
        let hay = normalize_key(text);
        for value in candidates {
            if hay.contains(value.as_str()) {
                leaks.push(Leak {
                    value: value.clone(),
                    path: path.to_string(),
                });
            }
        }
    }

    fn walk(node: &Value, path: &str, candidates: &[String], leaks: &mut Vec<Leak>) {
        match node {
            Value::String(text) => {
                check(
                    text,
                    if path.is_empty() { "<root>" } else { path },
                    candidates,
                    leaks,
                );
            }
            Value::Object(map) => {
                for (key, child) in map {
                    let child_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    check(key, &format!("{child_path}(key)"), candidates, leaks);
                    walk(child, &child_path, candidates, leaks);
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    let child_path = if path.is_empty() {
                        format!("[{index}]")
                    } else {
                        format!("{path}[{index}]")
                    };
                    walk(child, &child_path, candidates, leaks);
                }
            }
            _ => {}
        }
    }

    walk(payload, "", &candidates, &mut leaks);
    leaks
}

/// Check forwarded header values; reported as `header:<name>`.
pub fn find_header_leaks(headers: &[(String, String)], values: &[String]) -> Vec<Leak> {
    let candidates = candidates(values);
    if candidates.is_empty() {
        return Vec::new();
    }
    let mut leaks: Vec<Leak> = Vec::new();
    for (name, value) in headers {
        let hay = normalize_key(value);
        for candidate in &candidates {
            if hay.contains(candidate.as_str()) {
                leaks.push(Leak {
                    value: candidate.clone(),
                    path: format!("header:{}", name.to_ascii_lowercase()),
                });
            }
        }
    }
    leaks
}
