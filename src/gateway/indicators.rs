//! Reliability indicators: process-wide counters surfaced at `/status` and in
//! `X-Mask-*` response headers.
//!
//! Design constraints:
//! - Counters only. No raw values, no tokens, no pseudonyms, no field paths —
//!   anything that lands here must be safe to display on a website. These
//!   numbers are never part of any handoff and never leave as anything but
//!   aggregate counts.
//! - Every number is monotonic per process; a restart resets the window.
//! - The "posture" (leak gate mode, scope, detector availability, token set) is
//!   what tells a user how much to trust the guarantees; the counters tell them
//!   what the gateway has actually done.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde_json::{json, Map, Value};

use crate::gateway::config::GatewayConfig;
use crate::replace::random_hex;
use crate::restore::RestoreResult;

/// Counter registry. Explicit so the snapshot shape is stable for client
/// parsers (CLI panel, website widget).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Count {
    RequestsTotal,
    RequestsBlocked,
    EntitiesMasked,
    TokensRestored,
    TokensFuzzyRepaired,
    TokensUnresolved,
    LeakBlocks,
    LeakWarnings,
    PathsDenied,
    AuthDenied,
    StreamRequests,
    HandoffExports,
    HandoffImports,
    HandoffLocks,
    HandoffExpired,
    HandoffConsumed,
    AdminGateRefusals,
    DictionaryReloads,
}

impl Count {
    pub const ALL: [Count; 18] = [
        Count::RequestsTotal,
        Count::RequestsBlocked,
        Count::EntitiesMasked,
        Count::TokensRestored,
        Count::TokensFuzzyRepaired,
        Count::TokensUnresolved,
        Count::LeakBlocks,
        Count::LeakWarnings,
        Count::PathsDenied,
        Count::AuthDenied,
        Count::StreamRequests,
        Count::HandoffExports,
        Count::HandoffImports,
        Count::HandoffLocks,
        Count::HandoffExpired,
        Count::HandoffConsumed,
        Count::AdminGateRefusals,
        Count::DictionaryReloads,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Count::RequestsTotal => "requests_total",
            Count::RequestsBlocked => "requests_blocked",
            Count::EntitiesMasked => "entities_masked",
            Count::TokensRestored => "tokens_restored",
            Count::TokensFuzzyRepaired => "tokens_fuzzy_repaired",
            Count::TokensUnresolved => "tokens_unresolved",
            Count::LeakBlocks => "leak_blocks",
            Count::LeakWarnings => "leak_warnings",
            Count::PathsDenied => "paths_denied",
            Count::AuthDenied => "auth_denied",
            Count::StreamRequests => "stream_requests",
            Count::HandoffExports => "handoff_exports",
            Count::HandoffImports => "handoff_imports",
            Count::HandoffLocks => "handoff_locks",
            Count::HandoffExpired => "handoff_expired",
            Count::HandoffConsumed => "handoff_consumed",
            Count::AdminGateRefusals => "admin_gate_refusals",
            Count::DictionaryReloads => "dictionary_reloads",
        }
    }

    fn index(self) -> usize {
        Count::ALL
            .iter()
            .position(|c| *c == self)
            .expect("counter in registry")
    }
}

/// Process-wide counter bag attached to the app state.
#[derive(Debug)]
pub struct Indicators {
    started_at: Instant,
    values: [AtomicU64; 18],
}

impl Default for Indicators {
    fn default() -> Self {
        Self::new()
    }
}

impl Indicators {
    pub fn new() -> Self {
        Indicators {
            started_at: Instant::now(),
            values: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    pub fn incr(&self, count: Count) {
        self.add(count, 1);
    }

    pub fn add(&self, count: Count, amount: u64) {
        self.values[count.index()].fetch_add(amount, Ordering::Relaxed);
    }

    pub fn get(&self, count: Count) -> u64 {
        self.values[count.index()].load(Ordering::Relaxed)
    }

    pub fn counts(&self) -> Map<String, Value> {
        let mut map = Map::new();
        for count in Count::ALL {
            map.insert(count.key().to_string(), json!(self.get(count)));
        }
        map
    }

    /// Static posture + live counters, ready for `/status`.
    pub fn snapshot(&self, posture: Value) -> Value {
        let uptime = self.started_at.elapsed().as_secs_f64();
        let uptime = (uptime * 10.0).round() / 10.0;
        json!({
            "status": "ok",
            "uptime_seconds": uptime,
            "posture": posture,
            "counts": Value::Object(self.counts()),
        })
    }
}

/// Per-request accumulation of the mask/restore-side indicators.
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestMeasure {
    pub masked: u64,
    pub restored: u64,
    pub fuzzy_repaired: u64,
    pub unresolved: u64,
}

impl RequestMeasure {
    pub fn observe_restore(&mut self, result: &RestoreResult) {
        self.restored += result.restored;
        self.fuzzy_repaired += result.fuzzy_repaired;
        self.unresolved += result.unresolved_tokens.len() as u64;
    }
}

/// Static posture derived from config — the trust-level part of the indicator
/// system. The mapping table size is a count, never contents.
pub fn build_posture(
    config: &GatewayConfig,
    mapping_records: usize,
    dictionary_terms: usize,
) -> Value {
    json!({
        "leak_gate": config.leak_gate.as_str(),
        "leak_gate_active": config.leak_gate.is_active(),
        "session_scope": config.session_scope.as_str(),
        "ner": config.use_ner,
        "dictionary_terms": dictionary_terms,
        "mapping_records": mapping_records,
        "gateway_token": !config.gateway_token.is_empty(),
        "admin_allow_remote": config.admin_allow_remote,
        "admin_channel": admin_channel(config),
        "agent_host_guard": config.agent_host_guard,
        "upstream": config.upstream_base_url,
    })
}

/// Whether the admin channel is open, closed, or opted out of.
///
/// A posture fact, not a secret: "human" means an operator token exists in this
/// process, "closed" means `/admin/*` refuses everything (no operator terminal,
/// no token, or no gateway token to begin with), "off" means
/// `gateway.admin_require_human = false`.
///
/// The gateway-token case matters: without it `admin_authorized` refuses before
/// the operator token is even consulted, so reporting "human" there would be a
/// green lamp on a dead channel.
fn admin_channel(config: &GatewayConfig) -> &'static str {
    if !config.admin_require_human {
        return "off";
    }
    if config.gateway_token.is_empty() {
        return "closed";
    }
    match config.admin_human_token.as_deref() {
        Some(token) if !token.is_empty() => "human",
        _ => "closed",
    }
}

/// `X-Mask-*` headers appended to every proxied response.
///
/// The client (an agent harness or a human in a shell) sees, per response, that
/// masking happened and how much was restored — with zero PII, zero request
/// ids, zero entropy beyond a per-response nonce proving the header was minted
/// for this response and not cached upstream of a middlebox.
pub fn request_headers(
    measure: &RequestMeasure,
    config: &GatewayConfig,
    entry: &str,
) -> Vec<(String, String)> {
    vec![
        ("X-Mask".to_string(), "on".to_string()),
        ("X-Mask-In".to_string(), entry.to_string()),
        (
            "X-Mask-Leak-Gate".to_string(),
            config.leak_gate.as_str().to_string(),
        ),
        ("X-Mask-Masked".to_string(), measure.masked.to_string()),
        ("X-Mask-Restored".to_string(), measure.restored.to_string()),
        (
            "X-Mask-Fuzzy-Repaired".to_string(),
            measure.fuzzy_repaired.to_string(),
        ),
        (
            "X-Mask-Unresolved".to_string(),
            measure.unresolved.to_string(),
        ),
        ("X-Mask-Nonce".to_string(), random_hex(6)),
    ]
}
