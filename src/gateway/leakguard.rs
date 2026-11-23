//! Outbound leak gate: the last line of defense before anything leaves.
//!
//! Masking covers the request shapes the gateway knows about; the gate is a
//! positive control behind it. Every payload about to leave the gateway is
//! walked as a JSON structure and every string in it — object keys included —
//! is checked (NFKC-normalized, whole-word) against the raw entity values the
//! session has ever detected. A hit means a field the masking layer does not
//! cover carries real PII, so the request is refused before it reaches the
//! network (fail closed).
//!
//! "Whole word" is where precision lives (issue #15). ASCII values must not
//! touch another ASCII word character (`taro@example.com` is not inside
//! `xtaro@example.com`). A CJK value followed by an administrative or
//! derivational suffix is part of a longer word, not a re-mention (`田中` in
//! `田中町`, `東京` in `東京都`) — titles are checked first so `山田市長` stays a
//! hit. A two-character value is judged in request body text only: keys,
//! headers and metadata fields (`model`, `stop`, `metadata`) are where two
//! Japanese characters collide with ordinary words and key names.
//!
//! What this guarantees: no value the session has detected can leave the
//! machine, on any field, path, or header — even where masking missed the spot
//! (unanticipated fields, detection misses on repeat mentions, client headers).
//! What it cannot catch: values never detected anywhere, and two-character
//! values outside body text; those are the precision trade the issue asked for
//! and are visible as `leak_false_positives` in the indicators.
//!
//! Reporting is redacted by construction: a [`Leak`] keeps only a hash prefix
//! of the offending value and a structured path whose object keys are stored
//! as hashes. Logs and the block response are rendered from the same
//! [`Leak::path_string`], so neither can regress independently into printing a
//! raw key.

use std::collections::HashSet;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::normalize::normalize_key;

/// Shorter values are noise (single kana/kanji match everywhere).
pub const MIN_VALUE_LEN: usize = 2;

/// Object keys whose string values are request body text the model reads. A
/// value of [`MIN_VALUE_LEN`] characters is judged here only: that is where a
/// re-mention can carry it, and metadata is where a short Japanese word
/// collides with a key or a stop sequence.
const BODY_TEXT_FIELDS: &[&str] = &[
    "content",
    "text",
    "prompt",
    "input",
    "system",
    "instructions",
    "query",
    "arguments",
    "document",
    "documents",
];

/// Administrative and derivational suffixes that turn a directly preceding
/// value into part of a longer word: `田中` in `田中町`, `東京` in `東京都`,
/// `根本` in `根本的`. The same collisions the detector's false-positive corpus
/// pins; kept conservative (a title character is not a compound here).
const COMPOUND_SUFFIXES: &[&str] = &[
    "町", "市", "区", "村", "郡", "県", "都", "府", "道", "駅", "線", "通", "沿", "的", "公園",
    "街道", "神社", "寺院", "城", "港", "空港", "庁",
];

/// Titles that start with a [`COMPOUND_SUFFIXES`] character (`山田市長` is a
/// person, not `山田市`). Checked first so the precision rule never swallows a
/// title; titles whose first character is not a compound suffix (`山田社長`)
/// need no special case.
const TITLES_AFTER_VALUE: &[&str] = &["市長", "区長", "町長", "村長", "知事", "駅長", "庁長"];

/// Bytes of sha256 shown in paths and value prefixes (8 hex chars).
const HASH_PREFIX_BYTES: usize = 4;

pub(crate) fn hash_prefix(bytes: &[u8]) -> String {
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

/// A value at [`MIN_VALUE_LEN`] characters collides with ordinary words and key
/// names, so it is judged in body text only.
fn is_short(value: &str) -> bool {
    value.chars().count() <= MIN_VALUE_LEN
}

fn is_body_text_field(name: &str) -> bool {
    BODY_TEXT_FIELDS
        .iter()
        .any(|field| field.eq_ignore_ascii_case(name))
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn is_ideograph(c: char) -> bool {
    matches!(
        c as u32,
        0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF | 0x20000..=0x2FA1F
    )
}

/// Whether `value` at `start` in `hay` is a whole word rather than a piece of a
/// longer token.
fn is_whole_word(hay: &str, value: &str, start: usize) -> bool {
    let end = start + value.len();
    let first = value.chars().next().expect("candidates are non-empty");
    let last = value.chars().next_back().expect("candidates are non-empty");
    if is_word_char(first) && hay[..start].chars().next_back().is_some_and(is_word_char) {
        return false;
    }
    if is_word_char(last) && hay[end..].chars().next().is_some_and(is_word_char) {
        return false;
    }
    if is_ideograph(last) {
        let rest = &hay[end..];
        let titled = TITLES_AFTER_VALUE
            .iter()
            .any(|title| rest.starts_with(title));
        if !titled
            && COMPOUND_SUFFIXES
                .iter()
                .any(|suffix| rest.starts_with(suffix))
        {
            return false;
        }
    }
    true
}

/// Every whole-word occurrence of a candidate in `hay`. Sorted so the longest
/// candidate wins at a start position (CJK has no spaces, so `田中町` must not
/// also report `田中`).
fn hits<'a>(hay: &str, candidates: &'a [String], body_text: bool) -> Vec<(usize, &'a String)> {
    let mut hits: Vec<(usize, &'a String)> = Vec::new();
    for value in candidates {
        if is_short(value) && !body_text {
            continue;
        }
        for (start, _) in hay.match_indices(value.as_str()) {
            if is_whole_word(hay, value, start) {
                hits.push((start, value));
            }
        }
    }
    hits.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.len().cmp(&a.1.len())));
    hits
}

/// Return known raw values found in a JSON-like structure.
///
/// `values` must be NFKC-normalized (the pseudonym table's `raw_values` is).
/// Matching is whole-word (see the module docs), so a partial re-mention of a
/// value still counts while the same characters inside a longer word do not.
pub fn find_leaks(payload: &Value, values: &[String]) -> Vec<Leak> {
    let candidates = candidates(values);
    if candidates.is_empty() {
        return Vec::new();
    }
    let mut leaks: Vec<Leak> = Vec::new();

    fn check(
        text: &str,
        path: &[PathSeg],
        candidates: &[String],
        body_text: bool,
        leaks: &mut Vec<Leak>,
    ) {
        let hay = normalize_key(text);
        let mut seen: HashSet<&str> = HashSet::new();
        let mut last_start: Option<usize> = None;
        for (start, value) in hits(&hay, candidates, body_text) {
            // A longer candidate at this position already reported or will.
            if last_start == Some(start) {
                continue;
            }
            last_start = Some(start);
            if seen.insert(value.as_str()) {
                leaks.push(Leak {
                    value_sha256_prefix: hash_prefix(value.as_bytes()),
                    path: path.to_vec(),
                });
            }
        }
    }

    fn walk(
        node: &Value,
        path: &mut Vec<PathSeg>,
        candidates: &[String],
        body_text: bool,
        leaks: &mut Vec<Leak>,
    ) {
        match node {
            Value::String(text) => check(text, path, candidates, body_text, leaks),
            Value::Object(map) => {
                for (key, child) in map {
                    // Keys are metadata: a short value in a key is not a leak.
                    path.push(PathSeg::Key(hash_prefix(key.as_bytes())));
                    path.push(PathSeg::Field("(key)"));
                    check(key, path, candidates, false, leaks);
                    path.pop();
                    // Body text is decided by the field name, never inherited from
                    // an enclosing object: `content` carries text, its `type` does not.
                    walk(child, path, candidates, is_body_text_field(key), leaks);
                    path.pop();
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    path.push(PathSeg::Index(index));
                    walk(child, path, candidates, body_text, leaks);
                    path.pop();
                }
            }
            _ => {}
        }
    }

    let mut path = Vec::new();
    // A bare string body is body text.
    walk(payload, &mut path, &candidates, true, &mut leaks);
    leaks
}

/// Check forwarded header values; reported as `header.key#<hash>`.
///
/// Headers are metadata, so a short value is never judged here.
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
        let mut seen: HashSet<&str> = HashSet::new();
        let mut last_start: Option<usize> = None;
        for (start, candidate) in hits(&hay, &candidates, false) {
            if last_start == Some(start) {
                continue;
            }
            last_start = Some(start);
            if seen.insert(candidate.as_str()) {
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

    #[test]
    fn value_inside_a_longer_word_is_not_a_leak() {
        let tanaka = vec!["田中".to_string()];
        assert!(find_leaks(&json!("田中町に住む。"), &tanaka).is_empty());
        assert!(find_leaks(&json!("田中駅で降りる。"), &tanaka).is_empty());
        let tokyo = vec!["東京".to_string()];
        assert!(find_leaks(&json!("東京都新宿区"), &tokyo).is_empty());
        let ne = vec!["根本".to_string()];
        assert!(find_leaks(&json!("根本的に違う"), &ne).is_empty());
    }

    #[test]
    fn whole_word_mentions_still_leak() {
        let tanaka = vec!["田中".to_string()];
        for text in ["田中さんの件", "「田中」", "田中", "担当は田中です"] {
            assert_eq!(find_leaks(&json!(text), &tanaka).len(), 1, "{text}");
        }
        // A title beats the compound-suffix rule: 山田市長 is a person.
        let yamada = vec!["山田".to_string()];
        for text in ["山田市長", "山田区長", "山田様", "山田社長", "山田さん"] {
            assert_eq!(find_leaks(&json!(text), &yamada).len(), 1, "{text}");
        }
    }

    #[test]
    fn ascii_values_match_whole_tokens_only() {
        let email = vec!["taro@example.com".to_string()];
        assert!(find_leaks(&json!("xtaro@example.com"), &email).is_empty());
        assert!(find_leaks(&json!("taro@example.comx"), &email).is_empty());
        assert_eq!(
            find_leaks(&json!("mail: taro@example.com."), &email).len(),
            1
        );
        let phone = vec!["090-1234".to_string()];
        assert!(find_leaks(&json!("090-12345"), &phone).is_empty());
        assert_eq!(find_leaks(&json!("tel 090-1234."), &phone).len(), 1);
    }

    #[test]
    fn short_values_are_judged_in_body_text_only() {
        let values = vec!["出口".to_string()];
        let metadata = json!({
            "model": "exit-出口",
            "stop": ["出口"],
            "metadata": {"出口": "note", "user": "出口"},
        });
        let leaked = find_leaks(&metadata, &values);
        assert!(leaked.is_empty(), "{leaked:?}");
        let body = json!({"messages": [{"role": "user", "content": "出口で待っています。"}]});
        assert_eq!(find_leaks(&body, &values).len(), 1);
        // A long value is still judged everywhere, keys included.
        let long = vec!["山田太郎".to_string()];
        assert_eq!(
            find_leaks(&json!({"metadata": {"山田太郎": "note"}}), &long).len(),
            1
        );
    }

    #[test]
    fn short_values_are_ignored_in_headers() {
        let headers = vec![("X-Note".to_string(), "出口".to_string())];
        assert!(find_header_leaks(&headers, &["出口".to_string()]).is_empty());
        let headers = vec![("X-Name".to_string(), "山田太郎".to_string())];
        assert_eq!(
            find_header_leaks(&headers, &["山田太郎".to_string()]).len(),
            1
        );
    }

    #[test]
    fn longest_candidate_wins_at_one_position() {
        let values = vec!["田中".to_string(), "田中町".to_string()];
        let leaks = find_leaks(&json!("田中町"), &values);
        assert_eq!(leaks.len(), 1, "{leaks:?}");
        assert_eq!(
            leaks[0].value_sha256_prefix,
            hash_prefix("田中町".as_bytes())
        );
    }

    #[test]
    fn unrelated_history_does_not_change_the_verdict() {
        let payload = json!({"messages": [{"role": "user", "content": "田中町に住む。"}]});
        let fresh = find_leaks(&payload, &[]);
        let with_history = find_leaks(&payload, &["田中".to_string()]);
        assert_eq!(fresh, with_history);
        assert!(with_history.is_empty());
    }
}
