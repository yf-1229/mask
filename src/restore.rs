//! Restore layer: token -> original value.
//!
//! Pipeline applied to LLM output:
//! 1. Exact regex replacement of well-formed tokens.
//! 2. Repair of mutated tokens over any remaining `⟦fragment⟧`s. Structural core
//!    match first — lost/mangled brackets and junk chars are tolerated as long
//!    as the (label, id) pair is recoverable; the ID must be exact so we never
//!    bind a token to the wrong entity. Then edit-distance match, only for
//!    bracket-bounded fragments whose inner text does not parse as (label, id):
//!    boundaries are unambiguous there, so replacing the fragment is safe.
//! 3. Anything unrecoverable stays verbatim + warning flag. We never invent a
//!    value, and a well-formed token with an unknown ID is never fuzzy-matched
//!    to a near-ID token (that would resurrect a different person's name).

use std::sync::LazyLock;

use regex::Regex;

use crate::normalize::normalize_key;
use crate::replace::{PseudonymMap, TOKEN_CLOSE, TOKEN_OPEN, TOKEN_OPEN_STR};
use crate::types::EntityType;

const FUZZY_MAX_DISTANCE: usize = 2;

fn token_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        let labels = EntityType::ALL
            .iter()
            .map(|t| t.ja_label())
            .collect::<Vec<_>>()
            .join("|");
        Regex::new(&format!(
            "{}({})(\\d+){}",
            regex::escape(TOKEN_OPEN_STR),
            labels,
            regex::escape(&TOKEN_CLOSE.to_string())
        ))
        .unwrap()
    });
    &RE
}

fn fragment_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(&format!(
            "{}[^{}\\n]*{}?",
            regex::escape(TOKEN_OPEN_STR),
            TOKEN_CLOSE,
            regex::escape(&TOKEN_CLOSE.to_string())
        ))
        .unwrap()
    });
    &RE
}

fn core_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        let labels = EntityType::ALL
            .iter()
            .map(|t| t.ja_label())
            .collect::<Vec<_>>()
            .join("|");
        Regex::new(&format!(
            "{}[^{}\\n\\d]{{0,3}}({})[^{}\\n\\d]{{0,3}}(\\d{{1,3}})({})?",
            regex::escape(TOKEN_OPEN_STR),
            TOKEN_CLOSE,
            labels,
            TOKEN_CLOSE,
            regex::escape(&TOKEN_CLOSE.to_string())
        ))
        .unwrap()
    });
    &RE
}

/// Row-reduced Levenshtein with early cap, over characters.
pub fn levenshtein(a: &str, b: &str, cap: usize) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len().abs_diff(b.len()) > cap {
        return cap + 1;
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        let mut row_min = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            let value = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
            cur.push(value);
            row_min = row_min.min(value);
        }
        if row_min > cap {
            return cap + 1;
        }
        prev = cur;
    }
    prev[b.len()]
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RestoreResult {
    pub text: String,
    pub restored: u64,
    pub fuzzy_repaired: u64,
    pub unresolved_tokens: Vec<String>,
    pub warnings: Vec<String>,
}

/// Split a streaming buffer into `(safe_to_emit, keep_back)`.
///
/// A token or its opening bracket at the buffer tail may still be completed by
/// the next chunk, so anything that could be a token prefix is held back.
pub fn restore_stream_buffer(buffer: &str) -> (String, String) {
    let Some(last_open) = buffer.rfind(TOKEN_OPEN) else {
        return (buffer.to_string(), String::new());
    };
    let tail = &buffer[last_open..];
    if let Some(close) = tail.find(TOKEN_CLOSE) {
        let end = last_open + close + TOKEN_CLOSE.len_utf8();
        return (buffer[..end].to_string(), buffer[end..].to_string());
    }
    // unterminated token candidate: hold back while it could still complete
    let plausible = 1 + 3 + 3 + 1 + 2; // open + label + digits + close + slack
    if tail.chars().count() <= plausible {
        return (buffer[..last_open].to_string(), tail.to_string());
    }
    (buffer.to_string(), String::new())
}

/// Restore all tokens in `text` using the session mapping table.
pub fn restore(text: &str, pseudonyms: &PseudonymMap) -> RestoreResult {
    let mut result = RestoreResult {
        text: String::new(),
        ..Default::default()
    };

    // 1. exact tokens
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for m in token_re().find_iter(text) {
        out.push_str(&text[cursor..m.start()]);
        let token = m.as_str();
        match pseudonyms.restore_value(token) {
            Some(value) => {
                out.push_str(value);
                result.restored += 1;
            }
            None => {
                result.unresolved_tokens.push(token.to_string());
                out.push_str(token);
            }
        }
        cursor = m.end();
    }
    out.push_str(&text[cursor..]);
    result.text = out;

    // 2. mutated tokens
    repair_fragments(&mut result, pseudonyms);
    result
}

fn repair_fragments(result: &mut RestoreResult, pseudonyms: &PseudonymMap) {
    let known = pseudonyms.tokens();
    let text = result.text.clone();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;

    for m in fragment_re().find_iter(&text) {
        out.push_str(&text[cursor..m.start()]);
        cursor = m.end();
        let frag = m.as_str();

        if token_re().is_match(frag) && token_re().find(frag).is_some_and(|t| t.as_str() == frag) {
            // well-formed but unmapped: already collected at exact-restore
            // step. Never fuzzy-match a valid token shape to another entity.
            result
                .warnings
                .push(format!("unmapped token kept verbatim: {frag}"));
            out.push_str(frag);
            continue;
        }

        if let Some(core) = core_re().captures(frag) {
            let label = core.get(1).unwrap().as_str();
            let digits = core.get(2).unwrap().as_str();
            let token = format!("{TOKEN_OPEN}{label}{digits}{TOKEN_CLOSE}");
            match pseudonyms.restore_value(&token) {
                Some(value) => {
                    let start = core.get(0).unwrap().start();
                    let end = core.get(0).unwrap().end();
                    // junk after the id is original text and survives
                    out.push_str(&frag[..start]);
                    out.push_str(value);
                    out.push_str(&frag[end..]);
                    result.fuzzy_repaired += 1;
                    result
                        .warnings
                        .push(format!("repaired mutated token {frag} via {token}"));
                }
                None => {
                    result.unresolved_tokens.push(frag.to_string());
                    result.warnings.push(format!(
                        "token {frag} has unknown id {digits}; kept verbatim"
                    ));
                    out.push_str(frag);
                }
            }
            continue;
        }

        // bracket-bounded junk: fall back to edit distance
        if frag.starts_with(TOKEN_OPEN) && frag.ends_with(TOKEN_CLOSE) {
            let mut best: Option<&str> = None;
            let mut best_d = FUZZY_MAX_DISTANCE + 1;
            for token in &known {
                let d = levenshtein(frag, token, FUZZY_MAX_DISTANCE);
                if d < best_d {
                    best = Some(token);
                    best_d = d;
                }
            }
            if let Some(token) = best {
                if best_d <= FUZZY_MAX_DISTANCE {
                    if let Some(value) = pseudonyms.restore_value(token) {
                        result.fuzzy_repaired += 1;
                        result.warnings.push(format!(
                            "fuzzy-repaired token {frag} -> {token} (distance {best_d})"
                        ));
                        out.push_str(value);
                        continue;
                    }
                }
            }
        }

        result.unresolved_tokens.push(frag.to_string());
        result
            .warnings
            .push(format!("unresolved token kept verbatim: {frag}"));
        out.push_str(frag);
    }
    out.push_str(&text[cursor..]);
    result.text = out;
}

/// Bidirectional post-restore check:
/// - no token-shaped residue remains in the restored text
/// - raw entity values do not appear more often than the tokens restored (an
///   extra occurrence means the model emitted PII directly, i.e. either a
///   hallucination or data the detection layer never masked).
///
/// Returns warnings (empty list = clean).
pub fn audit_output(text_before: &str, text_after: &str, pseudonyms: &PseudonymMap) -> Vec<String> {
    let mut warnings: Vec<String> = Vec::new();
    for m in fragment_re().find_iter(text_after) {
        warnings.push(format!("token residue in output: {}", m.as_str()));
    }
    let normalized_after = normalize_key(text_after);
    for rec in pseudonyms.records() {
        let restored_hits = text_before.matches(&rec.token).count();
        let value = normalize_key(&rec.value);
        if value.chars().count() < 2 {
            continue;
        }
        let leaked = normalized_after.matches(value.as_str()).count();
        if leaked > restored_hits {
            warnings.push(format!(
                "raw entity value beyond restored occurrences: {}",
                rec.value
            ));
        }
    }
    warnings
}
