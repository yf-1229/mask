//! OpenAI-compatible gateway: mask on the way in, restore on the way out.
//!
//! The gateway sits between an LLM client ("harness") and the real LLM API:
//!
//! ```text
//! client --(OpenAI-compatible request)--> gateway --(masked)--> upstream
//! client <--(restored response)---------- gateway <--(pseudo)--- upstream
//! ```
//!
//! - `/v1/chat/completions`, non-streaming: full mask/restore.
//! - `/v1/chat/completions` with `stream=true`: each upstream text delta is
//!   restored as it arrives and forwarded immediately. A token split across
//!   network chunks is held in a tail buffer until the next chunk completes it
//!   (or the upstream ends and the tail is flushed).
//! - `tool_calls` function arguments are masked on the way in and restored on
//!   the way out (JSON strings are parsed, every string inside is masked or
//!   restored, then re-serialized) on both entrances and both paths.
//! - Every other path is refused unless allowlisted in gateway config (deny by
//!   default); allowlisted paths are forwarded but still pass the outbound leak
//!   gate.
//! - Before anything is sent, the outbound leak gate walks the payload and
//!   forwarded headers for raw values the session has detected; a hit refuses
//!   the request (fail closed). See [`leakguard`].

pub mod agent;
pub mod config;
pub mod guard;
pub mod indicators;
pub mod leakguard;
pub mod sharing;

pub use config::{GatewayConfig, LeakGate, SessionScope};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{Stream, StreamExt};
use serde_json::{json, Map, Value};
use subtle::ConstantTimeEq;

use crate::detect::dictionary::{MergeReport, UserDictionary};
use crate::gateway::agent::{
    anthropic_block_stop, anthropic_stream_end, anthropic_stream_start, anthropic_text_block_start,
    anthropic_text_delta, anthropic_to_openai, anthropic_tool_block, finish_reason,
    openai_to_anthropic, restored_strings,
};
use crate::gateway::indicators::{
    build_posture, request_headers, Count, Indicators, RequestMeasure,
};
use crate::gateway::leakguard::{find_header_leaks, find_leaks, hash_prefix, Leak};
use crate::gateway::sharing::{envelope_fingerprint, seal_with, unseal, Envelope, UnsealError};
use crate::replace::{PseudonymMap, SessionFull};
use crate::restore::restore_stream_buffer;
use crate::session::Session;

/// Request headers never forwarded upstream: the client's Authorization is a
/// dummy by design (the real key lives only in the gateway config). The
/// Anthropic-style slots (x-api-key / anthropic-* headers) are entry-protocol
/// headers: the gateway token rides in them, so they terminate here too.
const HOP_BY_HOP: &[&str] = &[
    "host",
    "authorization",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "accept-encoding",
    "x-api-key",
    "anthropic-version",
    "anthropic-beta",
];

/// Entry protocols served by the gateway; shown in the `X-Mask-In` header and
/// the `/status` snapshot so a user can see how agents and humans entered.
pub const ENTRY_OPENAI: &str = "v1/chat";
pub const ENTRY_ANTHROPIC: &str = "v1/messages";

/// Upper bound for a request body (32 MiB).
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// File-watch state for `[mask].dictionary`: the `(mtime, len)` of the file as
/// last applied. One `stat` per request is the whole price of live reload; it
/// keeps the guarantee honest for a request that arrives right after a write.
#[derive(Debug, Default)]
struct DictionaryWatch {
    /// `None` means "the file was not there when we last looked".
    stamp: Option<(SystemTime, u64)>,
}

fn file_stamp(path: &Path) -> Option<(SystemTime, u64)> {
    let metadata = std::fs::metadata(path).ok()?;
    let modified = metadata.modified().ok()?;
    Some((modified, metadata.len()))
}

/// Shared gateway state.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<GatewayConfig>,
    pub http: reqwest::Client,
    /// Live dictionary. `/status` reports its size only; `mask dict add` edits
    /// the file and the gateway merges additions without a restart.
    pub dictionary: Arc<RwLock<UserDictionary>>,
    dictionary_watch: Arc<Mutex<DictionaryWatch>>,
    pub indicators: Arc<Indicators>,
    /// `Some` in global scope: one table for the whole process.
    pub session: Option<Arc<Mutex<Session>>>,
    /// Operator token for `/admin/*`: minted at startup, printed to the
    /// gateway's own terminal, never persisted. `None` closes the admin
    /// channel (no terminal, or `gateway.admin_require_human = false`).
    pub admin_human_token: Option<Arc<str>>,
    /// Failed-passphrase attempts per envelope fingerprint.
    pub handoff_failures: Arc<Mutex<HashMap<String, u32>>>,
    /// Fingerprints of consumed (single-use) envelopes.
    pub handoff_consumed: Arc<Mutex<HashSet<String>>>,
}

impl AppState {
    /// Run `f` with the session for this request: the shared one in global
    /// scope, a fresh one in request scope.
    fn with_session<T>(&self, f: impl FnOnce(&mut Session) -> T) -> T {
        // Refresh before taking the session lock: a reload takes the dictionary
        // lock, then the session lock, and must not meet the reverse order.
        self.refresh_dictionary();
        match &self.session {
            Some(shared) => {
                // Recover a poisoned lock: one panic must not turn every later
                // request into a panic. The mappings are still usable; the
                // alternative is a process that never answers again.
                let mut guard = shared.lock().unwrap_or_else(|e| e.into_inner());
                f(&mut guard)
            }
            None => {
                let dictionary = self
                    .dictionary
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                let mut session = Session::with_capacity(
                    dictionary,
                    self.config.use_ner,
                    self.config.session_capacity,
                );
                f(&mut session)
            }
        }
    }

    /// Re-read the dictionary file when it changed.
    ///
    /// The merge is additive: a file edit can add terms or correct a type, but
    /// cannot remove detection coverage from a running process. Deleting the
    /// file reads as empty and changes nothing.
    fn refresh_dictionary(&self) {
        let Some(path) = self.config.dictionary_path.as_deref() else {
            return;
        };
        let mut watch = self
            .dictionary_watch
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let stamp = file_stamp(path);
        if stamp == watch.stamp {
            return;
        }
        let newer = match UserDictionary::load(path) {
            Ok(newer) => newer,
            Err(error) => {
                // Record the stamp anyway: the old table stays, and the file
                // gets another chance on its next change (or an explicit
                // /admin/dictionary/reload).
                watch.stamp = stamp;
                tracing::warn!(%error, "dictionary reload failed; keeping the loaded table");
                return;
            }
        };
        watch.stamp = stamp;
        drop(watch);
        self.merge_dictionary(&newer);
    }

    /// Merge `newer` into the live table and into a global session's copy.
    ///
    /// Counts only reach the log and the indicators; no term text does.
    fn merge_dictionary(&self, newer: &UserDictionary) -> MergeReport {
        let mut dictionary = self.dictionary.write().unwrap_or_else(|e| e.into_inner());
        let report = dictionary.merge_additive(newer);
        if report.changed() {
            self.indicators.incr(Count::DictionaryReloads);
            tracing::info!(
                added = report.added,
                updated = report.updated,
                kept = report.kept,
                terms = report.terms,
                "dictionary reloaded (additive; removals wait for a restart)"
            );
            if let Some(shared) = &self.session {
                let mut session = shared.lock().unwrap_or_else(|e| e.into_inner());
                session.dictionary = dictionary.clone();
            }
        }
        report
    }

    fn mapping_records(&self) -> usize {
        match &self.session {
            Some(shared) => shared
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pseudonyms
                .len(),
            None => 0,
        }
    }

    fn posture(&self) -> Value {
        let terms = self
            .dictionary
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .size();
        build_posture(&self.config, self.mapping_records(), terms)
    }
}

/// Build the gateway app.
///
/// The HTTP client is injectable so tests can point it at a mock upstream.
pub fn create_app(config: GatewayConfig, client: Option<reqwest::Client>) -> Router {
    crate::install_crypto_provider();

    // Stamp before loading: a write that lands in between is then seen as a
    // change by the first poll instead of being skipped.
    let dictionary_stamp = config.dictionary_path.as_deref().and_then(file_stamp);
    let dictionary = match &config.dictionary_path {
        Some(path) => UserDictionary::load(path).unwrap_or_else(|error| {
            tracing::error!(%error, "cannot load dictionary; continuing without it");
            UserDictionary::new()
        }),
        None => UserDictionary::new(),
    };
    let http = client.unwrap_or_else(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(600))
            .build()
            .unwrap_or_else(|error| {
                tracing::error!(%error, "cannot build HTTP client");
                reqwest::Client::new()
            })
    });
    let session = if config.session_scope == SessionScope::Global {
        Some(Arc::new(Mutex::new(Session::with_capacity(
            dictionary.clone(),
            config.use_ner,
            config.session_capacity,
        ))))
    } else {
        None
    };

    let state_admin_token: Option<Arc<str>> = config
        .admin_human_token
        .as_deref()
        .map(Arc::from)
        .filter(|token: &Arc<str>| !token.is_empty());
    let state = AppState {
        config: Arc::new(config),
        http,
        dictionary: Arc::new(RwLock::new(dictionary)),
        dictionary_watch: Arc::new(Mutex::new(DictionaryWatch {
            stamp: dictionary_stamp,
        })),
        indicators: Arc::new(Indicators::new()),
        session,
        admin_human_token: state_admin_token,
        handoff_failures: Arc::new(Mutex::new(HashMap::new())),
        handoff_consumed: Arc::new(Mutex::new(HashSet::new())),
    };

    Router::new()
        .route("/healthz", get(healthz))
        .route("/status", get(status))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/messages", post(messages))
        .route("/admin/export", post(admin_export))
        .route("/admin/import", post(admin_import))
        .route("/admin/session", get(admin_session))
        .route("/admin/dictionary/reload", post(admin_dictionary_reload))
        .route(
            "/admin/leak/false-positive",
            post(admin_leak_false_positive),
        )
        .fallback(passthrough)
        .with_state(state)
}

// --- response helpers --------------------------------------------------------

fn with_headers(mut response: Response, headers: &[(String, String)]) -> Response {
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

fn json_response(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(status, json!({"error": {"message": message, "code": code}}))
}

fn anthropic_error(status: StatusCode, etype: &str, message: &str, extra: Value) -> Response {
    let mut error = Map::new();
    error.insert("type".to_string(), json!(etype));
    error.insert("message".to_string(), json!(message));
    if let Value::Object(extra) = extra {
        for (key, value) in extra {
            error.insert(key, value);
        }
    }
    json_response(
        status,
        json!({"type": "error", "error": Value::Object(error)}),
    )
}

/// Answer the one request that could not be masked because the session's
/// pseudonym capacity is exhausted. Nothing is sent upstream; the process and
/// the existing bindings stay intact. The message carries the limit only.
fn session_full_response(full: SessionFull, anthropic: bool) -> Response {
    let message = format!("mask gateway: {full}; the request was not sent");
    if anthropic {
        anthropic_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            &message,
            json!({"mask_code": "mask_session_full", "mask_capacity": full.capacity}),
        )
    } else {
        json_response(
            StatusCode::BAD_REQUEST,
            json!({
                "error": {
                    "message": message,
                    "code": "mask_session_full",
                    "capacity": full.capacity,
                }
            }),
        )
    }
}

fn body_response(status: StatusCode, body: Bytes, content_type: Option<String>) -> Response {
    let mut builder = Response::builder().status(status);
    if let Some(content_type) = content_type {
        if let Ok(value) = HeaderValue::from_str(&content_type) {
            builder = builder.header(header::CONTENT_TYPE, value);
        }
    }
    builder
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// --- auth --------------------------------------------------------------------

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Gateway token check; unset token means no auth (localhost only).
///
/// The token may arrive as `Authorization: Bearer <token>` (OpenAI style) or as
/// `x-api-key: <token>` (Anthropic style): the same secret protects both
/// entrances. The comparison is constant-time: the token is a long-lived shared
/// secret, so no early-exit string comparison.
fn authorize(state: &AppState, request: &Request) -> Option<Response> {
    let expected = state.config.gateway_token.as_str();
    if expected.is_empty() {
        return None;
    }
    let headers = request.headers();
    let provided = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let api_key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mut ok = false;
    if let Some(token) = provided.strip_prefix("Bearer ") {
        ok = constant_time_eq(token, expected);
    }
    if !ok && !api_key.is_empty() {
        ok = constant_time_eq(api_key, expected);
    }
    if ok {
        return None;
    }
    state.indicators.incr(Count::AuthDenied);
    state.indicators.incr(Count::RequestsBlocked);
    Some(error_response(
        StatusCode::UNAUTHORIZED,
        "mask_unauthorized",
        "gateway token required (send it as the API key)",
    ))
}

fn is_loopback(addr: Option<SocketAddr>) -> bool {
    match addr {
        Some(addr) => addr.ip().is_loopback(),
        None => false,
    }
}

/// Admin endpoints: disabled without a token, loopback-only by default, and
/// gated on the operator's own terminal. The envelope file travels between
/// teammates; the admin API itself never needs to be reachable from the
/// network — nor reachable from whatever else happens to run on this machine.
///
/// Four checks, cheapest first, each with its own refusal code:
///
/// 1. `Host` must be a loopback name ([`guard::host_is_local`]): a rebinding
///    page cannot address the channel as `evil.example`.
/// 2. `gateway.token` must be set and match — the shared secret a client
///    already holds.
/// 3. The client must be loopback unless `gateway.admin_allow_remote`.
/// 4. With `gateway.admin_require_human` (the default), the request must carry
///    the operator token printed on the gateway's terminal. A process that
///    never had a terminal has no token to send, so the channel stays shut.
fn admin_authorized(state: &AppState, request: &Request) -> Option<Response> {
    if !guard::host_is_local(request.headers()) {
        state.indicators.incr(Count::AdminGateRefusals);
        state.indicators.incr(Count::RequestsBlocked);
        tracing::warn!("admin refused: Host header is not a loopback name");
        return Some(error_response(
            StatusCode::FORBIDDEN,
            "mask_admin_host",
            "admin endpoints answer to loopback names only (localhost, 127.0.0.1)",
        ));
    }
    if state.config.gateway_token.is_empty() {
        state.indicators.incr(Count::AdminGateRefusals);
        return Some(error_response(
            StatusCode::FORBIDDEN,
            "mask_admin_disabled",
            "admin endpoints require gateway.token to be set",
        ));
    }
    if !state.config.admin_allow_remote {
        let client = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0);
        if !is_loopback(client) {
            state.indicators.incr(Count::AdminGateRefusals);
            tracing::warn!(?client, "admin refused from non-loopback client");
            return Some(error_response(
                StatusCode::FORBIDDEN,
                "mask_admin_local_only",
                "admin endpoints accept loopback clients only (set gateway.admin_allow_remote to override)",
            ));
        }
    }
    let denied = authorize(state, request);
    if denied.is_some() {
        return denied;
    }
    if state.config.admin_require_human {
        let Some(expected) = state.admin_human_token.as_deref() else {
            state.indicators.incr(Count::AdminGateRefusals);
            state.indicators.incr(Count::RequestsBlocked);
            tracing::warn!("admin refused: no operator terminal, so no operator token exists");
            return Some(error_response(
                StatusCode::FORBIDDEN,
                "mask_admin_closed",
                "admin channel closed: this gateway has no operator terminal. Start `mask serve` from an interactive terminal, or set gateway.admin_require_human = false to opt out",
            ));
        };
        let provided = request
            .headers()
            .get(guard::ADMIN_TOKEN_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        if !constant_time_eq(provided, expected) {
            state.indicators.incr(Count::AdminGateRefusals);
            state.indicators.incr(Count::RequestsBlocked);
            tracing::warn!("admin refused: operator token missing or wrong");
            return Some(error_response(
                StatusCode::UNAUTHORIZED,
                "mask_admin_no_human",
                "admin endpoints require the operator token printed on the gateway's terminal, sent as x-mask-admin",
            ));
        }
    }
    None
}

// --- request plumbing --------------------------------------------------------

// axum's `Response` is the error type on purpose: handlers here are written as
// `Result<_, Response>` so a rejection can be returned without rewriting it.
#[allow(clippy::result_large_err)]
async fn read_json_body(request: Request) -> Result<Value, Response> {
    let bytes = axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES)
        .await
        .map_err(|_| {
            error_response(
                StatusCode::BAD_REQUEST,
                "mask_bad_request",
                "cannot read request body",
            )
        })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "mask_bad_request",
            "malformed JSON body",
        )
    })
}

/// Client headers that may be forwarded upstream (hop-by-hop removed, real key
/// injected).
fn forwarded_headers(config: &GatewayConfig, headers: &HeaderMap) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (name, value) in headers.iter() {
        let name = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        if let Ok(value) = value.to_str() {
            out.push((name, value.to_string()));
        }
    }
    if !config.upstream_api_key.is_empty() {
        out.retain(|(name, _)| name != "authorization");
        out.push((
            "authorization".to_string(),
            format!("Bearer {}", config.upstream_api_key),
        ));
    }
    out
}

fn header_map(headers: &[(String, String)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            map.insert(name, value);
        }
    }
    map
}

#[allow(clippy::result_large_err)]
async fn send_upstream(
    state: &AppState,
    method: Method,
    url: &str,
    headers: &[(String, String)],
    body: Option<&Value>,
    raw_body: Option<Bytes>,
) -> Result<reqwest::Response, Response> {
    let mut builder = state.http.request(method, url).headers(header_map(headers));
    if let Some(body) = body {
        builder = builder.json(body);
    } else if let Some(raw) = raw_body {
        builder = builder.body(raw);
    }
    builder.send().await.map_err(|error| {
        tracing::error!(%error, %url, "upstream request failed");
        error_response(
            StatusCode::BAD_GATEWAY,
            "mask_upstream_unreachable",
            "upstream request failed",
        )
    })
}

// --- masking / restoring -----------------------------------------------------

fn mask_text_value(
    text: &str,
    session: &mut Session,
    measure: &mut RequestMeasure,
) -> Result<String, SessionFull> {
    let (masked, result) = session.masked(text)?;
    measure.masked += result.entities.len() as u64;
    if !result.entities.is_empty() {
        let mut types: Vec<&str> = result.entities.iter().map(|e| e.kind.as_str()).collect();
        types.sort_unstable();
        types.dedup();
        tracing::info!(
            count = result.entities.len(),
            types = types.join(","),
            "masked entities"
        );
    }
    Ok(masked)
}

fn mask_content(
    content: &Value,
    session: &mut Session,
    measure: &mut RequestMeasure,
) -> Result<Value, SessionFull> {
    match content {
        Value::String(text) => Ok(Value::String(mask_text_value(text, session, measure)?)),
        Value::Array(parts) => {
            let mut out = Vec::with_capacity(parts.len());
            for part in parts {
                out.push(match part {
                    Value::Object(map) if map.get("text").is_some_and(|t| t.is_string()) => {
                        let text = map.get("text").and_then(Value::as_str).unwrap_or("");
                        let mut map = map.clone();
                        map.insert(
                            "text".to_string(),
                            Value::String(mask_text_value(text, session, measure)?),
                        );
                        Value::Object(map)
                    }
                    other => other.clone(),
                });
            }
            Ok(Value::Array(out))
        }
        other => Ok(other.clone()),
    }
}

/// Mask every string inside a parsed JSON argument blob.
fn mask_strings(
    node: &Value,
    session: &mut Session,
    measure: &mut RequestMeasure,
) -> Result<Value, SessionFull> {
    match node {
        Value::String(text) => Ok(Value::String(mask_text_value(text, session, measure)?)),
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k.clone(), mask_strings(v, session, measure)?);
            }
            Ok(Value::Object(out))
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(mask_strings(item, session, measure)?);
            }
            Ok(Value::Array(out))
        }
        other => Ok(other.clone()),
    }
}

/// Mask a JSON-encoded string; non-JSON strings are masked as text.
fn mask_json_string(
    raw: &str,
    session: &mut Session,
    measure: &mut RequestMeasure,
) -> Result<String, SessionFull> {
    match serde_json::from_str::<Value>(raw) {
        Ok(parsed) => {
            let masked = mask_strings(&parsed, session, measure)?;
            Ok(serde_json::to_string(&masked).unwrap_or_else(|_| raw.to_string()))
        }
        Err(_) => mask_text_value(raw, session, measure),
    }
}

/// Mask PII inside `tool_calls[*].function.arguments`.
fn mask_tool_calls(
    tool_calls: &Value,
    session: &mut Session,
    measure: &mut RequestMeasure,
) -> Result<Value, SessionFull> {
    let Value::Array(items) = tool_calls else {
        return Ok(tool_calls.clone());
    };
    let mut out = Vec::with_capacity(items.len());
    for call in items {
        let Some(call_map) = call.as_object() else {
            out.push(call.clone());
            continue;
        };
        let Some(function) = call_map.get("function").and_then(Value::as_object) else {
            out.push(call.clone());
            continue;
        };
        let Some(arguments) = function.get("arguments").and_then(Value::as_str) else {
            out.push(call.clone());
            continue;
        };
        let mut call_map = call_map.clone();
        let mut function = function.clone();
        function.insert(
            "arguments".to_string(),
            Value::String(mask_json_string(arguments, session, measure)?),
        );
        call_map.insert("function".to_string(), Value::Object(function));
        out.push(Value::Object(call_map));
    }
    Ok(Value::Array(out))
}

/// Return a copy of the request body with PII in messages replaced.
///
/// `Err(SessionFull)` means this session ran out of token ids; the caller
/// answers that request with `mask_session_full` and leaves the process (and
/// every existing binding) intact.
pub fn mask_chat_request(
    body: &Value,
    session: &mut Session,
    measure: &mut RequestMeasure,
) -> Result<Value, SessionFull> {
    let mut masked = body.as_object().cloned().unwrap_or_default();
    if let Some(Value::Array(messages)) = masked.get("messages").cloned() {
        let mut out: Vec<Value> = Vec::with_capacity(messages.len());
        for message in &messages {
            let Some(message_map) = message.as_object() else {
                out.push(message.clone());
                continue;
            };
            let mut message_map = message_map.clone();
            let content = message_map.get("content").cloned().unwrap_or(Value::Null);
            message_map.insert(
                "content".to_string(),
                mask_content(&content, session, measure)?,
            );
            if let Some(tool_calls) = message_map.get("tool_calls").cloned() {
                message_map.insert(
                    "tool_calls".to_string(),
                    mask_tool_calls(&tool_calls, session, measure)?,
                );
            }
            out.push(Value::Object(message_map));
        }
        masked.insert("messages".to_string(), Value::Array(out));
    }
    Ok(Value::Object(masked))
}

fn restore_text(text: &str, session: &Session, measure: &mut RequestMeasure) -> String {
    let restored = session.unmasked(text);
    measure.observe_restore(&restored);
    for warning in &restored.warnings {
        tracing::warn!("restore: {warning}");
    }
    restored.text
}

/// Restore tokens inside one OpenAI tool call's `function.arguments`.
///
/// The arguments are a JSON document carried as a string, so the tokens hide
/// inside its values: parse, restore every string, re-serialize. Invalid JSON
/// is returned byte-for-byte — rewriting it would hand the local tool a
/// different argument than the model emitted — and logged as a warning.
fn restore_arguments_json(
    raw: &str,
    session: &mut Session,
    measure: &mut RequestMeasure,
) -> String {
    let Ok(args) = serde_json::from_str::<Value>(raw) else {
        tracing::warn!("restore: tool call arguments are not valid JSON; kept verbatim");
        return raw.to_string();
    };
    serde_json::to_string(&restored_strings(&args, session, measure)).unwrap_or_else(|error| {
        tracing::warn!(%error, "restore: cannot re-serialize tool call arguments");
        raw.to_string()
    })
}

/// Restore `tool_calls[*].function.arguments` in place.
///
/// Shared by the non-streaming response path and the SSE collector so the two
/// cannot drift; a token that survives one path must not survive the other.
fn restore_tool_calls(calls: &mut [Value], session: &mut Session, measure: &mut RequestMeasure) {
    for call in calls {
        let Some(arguments) = call
            .get_mut("function")
            .and_then(Value::as_object_mut)
            .and_then(|function| function.get_mut("arguments"))
        else {
            continue;
        };
        let Value::String(raw) = arguments else {
            continue;
        };
        *arguments = Value::String(restore_arguments_json(raw, session, measure));
    }
}

/// Restore pseudonyms in `choices[*].message.content` and tool arguments, in
/// place.
pub fn restore_chat_response(
    data: &mut Value,
    session: &mut Session,
    measure: &mut RequestMeasure,
) {
    let Some(choices) = data.get_mut("choices").and_then(Value::as_array_mut) else {
        return;
    };
    for choice in choices {
        let Some(message) = choice.get_mut("message") else {
            continue;
        };
        if !message.is_object() {
            continue;
        }
        if let Some(content) = message.get("content").and_then(Value::as_str) {
            let restored = restore_text(content, session, measure);
            message["content"] = Value::String(restored);
        }
        if let Some(Value::Array(calls)) = message.get_mut("tool_calls") {
            restore_tool_calls(calls, session, measure);
        }
    }
}

fn record_measure(state: &AppState, measure: &RequestMeasure) {
    state.indicators.add(Count::EntitiesMasked, measure.masked);
    state
        .indicators
        .add(Count::TokensRestored, measure.restored);
    state
        .indicators
        .add(Count::TokensFuzzyRepaired, measure.fuzzy_repaired);
    state
        .indicators
        .add(Count::TokensUnresolved, measure.unresolved);
}

// --- leak gate ---------------------------------------------------------------

/// Refuse the request if a known raw value would leave the process.
///
/// Neither the log line nor the client-facing error carries a raw value or a
/// raw object key: both are rendered from the structured [`Leak`] path (keys as
/// `key#<sha256-prefix>`) plus a value hash prefix. The local opt-in that
/// reveals raw values is `mask check --explain`; this path is always redacted.
fn gate(
    state: &AppState,
    session: &Session,
    payload: &Value,
    headers: &[(String, String)],
    source: &str,
) -> Option<Response> {
    let values = session.pseudonyms.raw_values();
    if values.is_empty() {
        return None;
    }
    let mut leaks: Vec<Leak> = find_leaks(payload, &values);
    leaks.extend(find_header_leaks(headers, &values));
    if leaks.is_empty() {
        return None;
    }
    for leak in &leaks {
        tracing::warn!("{}", leak.log_line(source));
    }
    if state.config.leak_gate == LeakGate::Warn {
        state.indicators.incr(Count::LeakWarnings);
        return None;
    }
    state.indicators.incr(Count::LeakBlocks);
    state.indicators.incr(Count::RequestsBlocked);
    let fields: Vec<String> = leaks.iter().map(Leak::path_string).collect();
    let leaks_view: Vec<GateLeak> = leaks
        .iter()
        .map(|leak| GateLeak {
            path: leak.path_string(),
            value_sha256_prefix: leak.value_sha256_prefix.clone(),
        })
        .collect();
    let mut response = json_response(
        StatusCode::BAD_REQUEST,
        json!({
            "error": {
                "message": "mask gateway: unmasked PII detected in the request; nothing was sent to the upstream",
                "code": "mask_leak_blocked",
                "fields": &fields,
                "leaks": &leaks_view,
            }
        }),
    );
    response
        .headers_mut()
        .insert("X-Mask-Leak-Blocked", HeaderValue::from_static("true"));
    response.extensions_mut().insert(GateDetails {
        message:
            "mask gateway: unmasked PII detected in the request; nothing was sent to the upstream"
                .to_string(),
        code: "mask_leak_blocked".to_string(),
        fields,
        leaks: leaks_view,
    });
    Some(response)
}

// --- handlers ----------------------------------------------------------------

async fn healthz(State(state): State<AppState>) -> Response {
    json_response(
        StatusCode::OK,
        json!({
            "status": "ok",
            "upstream": state.config.upstream_base_url,
            "session_scope": state.config.session_scope.as_str(),
        }),
    )
}

/// Reliability indicators: posture + live counters.
///
/// Counts only — the response is designed to be publishable (website widget,
/// clipboard, chat). Gated by the gateway token like the proxy entrances when
/// one is set — unless `gateway.status_public = true` explicitly opts into
/// publishing: the snapshot is PII-free by construction, and opting into
/// publishing means exactly that.
async fn status(State(state): State<AppState>, request: Request) -> Response {
    if !state.config.status_public {
        if let Some(denied) = authorize(&state, &request) {
            return denied;
        }
    }
    let snapshot = state.indicators.snapshot(state.posture());
    let mut response = json_response(StatusCode::OK, snapshot);
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if state.config.status_public {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
    }
    response
}

async fn chat_completions(State(state): State<AppState>, request: Request) -> Response {
    if let Some(denied) = authorize(&state, &request) {
        return denied;
    }
    state.indicators.incr(Count::RequestsTotal);
    let headers = forwarded_headers(&state.config, request.headers());
    let body = match read_json_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };

    let mut measure = RequestMeasure::default();
    let (masked, blocked) = match state.with_session(|session| {
        let masked = mask_chat_request(&body, session, &mut measure)?;
        let blocked = gate(&state, session, &masked, &headers, "chat/completions");
        Ok::<_, SessionFull>((masked, blocked))
    }) {
        Ok(value) => value,
        Err(full) => return session_full_response(full, false),
    };
    if let Some(blocked) = blocked {
        return blocked;
    }

    let url = state.config.upstream_url("chat/completions");
    if body.get("stream").and_then(Value::as_bool).unwrap_or(false) {
        state.indicators.incr(Count::StreamRequests);
        return proxy_streaming(&state, &masked, &headers, &url, ENTRY_OPENAI, measure).await;
    }

    let upstream =
        match send_upstream(&state, Method::POST, &url, &headers, Some(&masked), None).await {
            Ok(response) => response,
            Err(response) => return response,
        };
    let status = upstream.status();
    let content_type = upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = match upstream.bytes().await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!(%error, "cannot read upstream body");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "mask_upstream_error",
                "cannot read upstream response",
            );
        }
    };
    if !status.is_success() {
        return body_response(
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            bytes,
            content_type,
        );
    }
    let mut data: Value = match serde_json::from_slice(&bytes) {
        Ok(data) => data,
        Err(error) => {
            tracing::error!(%error, "upstream returned invalid JSON");
            return body_response(status, bytes, content_type);
        }
    };
    state.with_session(|session| restore_chat_response(&mut data, session, &mut measure));
    record_measure(&state, &measure);
    let response = json_response(StatusCode::OK, data);
    with_headers(
        response,
        &request_headers(&measure, &state.config, ENTRY_OPENAI),
    )
}

async fn messages(State(state): State<AppState>, request: Request) -> Response {
    if let Some(denied) = authorize(&state, &request) {
        return denied;
    }
    state.indicators.incr(Count::RequestsTotal);
    let headers = forwarded_headers(&state.config, request.headers());

    let bytes = match axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return anthropic_error(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "cannot read request body",
                json!({}),
            )
        }
    };
    let body: Value = match serde_json::from_slice(&bytes) {
        Ok(body) => body,
        Err(_) => {
            return anthropic_error(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                "malformed JSON body",
                json!({}),
            )
        }
    };
    if !body.is_object() {
        return anthropic_error(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "invalid body",
            json!({}),
        );
    }

    let mut measure = RequestMeasure::default();
    let (openai_body, masked, blocked) = match state.with_session(|session| {
        let openai_body = anthropic_to_openai(&body);
        let masked = mask_chat_request(&openai_body, session, &mut measure)?;
        let blocked = gate(&state, session, &masked, &headers, "v1/messages");
        Ok::<_, SessionFull>((openai_body, masked, blocked))
    }) {
        Ok(value) => value,
        Err(full) => return session_full_response(full, true),
    };
    if let Some(blocked) = blocked {
        // Re-wrap the gate decision in the Anthropic error envelope.
        let err = blocked_error(&blocked);
        return anthropic_error(
            blocked_status(&blocked),
            "invalid_request_error",
            err.0.as_str(),
            json!({"mask_code": err.1, "mask_fields": err.2, "mask_leaks": err.3}),
        );
    }

    let url = state.config.upstream_url("chat/completions");
    if openai_body
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        state.indicators.incr(Count::StreamRequests);
        return proxy_streaming(&state, &masked, &headers, &url, ENTRY_ANTHROPIC, measure).await;
    }

    let upstream =
        match send_upstream(&state, Method::POST, &url, &headers, Some(&masked), None).await {
            Ok(response) => response,
            Err(response) => return response,
        };
    let status = upstream.status();
    let payload: Value = match upstream.json().await {
        Ok(payload) => payload,
        Err(error) => {
            tracing::error!(%error, "upstream returned invalid JSON");
            return anthropic_error(
                StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
                "api_error",
                "upstream error",
                json!({}),
            );
        }
    };
    if !status.is_success() {
        let message = payload
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("upstream error");
        return anthropic_error(
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            "api_error",
            message,
            json!({}),
        );
    }

    let content = payload
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let out = state.with_session(|session| {
        let restored_text = if content.is_empty() {
            String::new()
        } else {
            restore_text(&content, session, &mut measure)
        };
        openai_to_anthropic(&payload, &restored_text, session, &mut measure)
    });
    record_measure(&state, &measure);
    let response = json_response(StatusCode::OK, out);
    with_headers(
        response,
        &request_headers(&measure, &state.config, ENTRY_ANTHROPIC),
    )
}

async fn admin_export(State(state): State<AppState>, request: Request) -> Response {
    if let Some(denied) = admin_authorized(&state, &request) {
        return denied;
    }
    if state.config.session_scope != SessionScope::Global {
        return error_response(
            StatusCode::CONFLICT,
            "mask_scope_unsupported",
            "admin endpoints require session.scope = 'global'",
        );
    }
    let body = match read_json_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let passphrase = body
        .get("passphrase")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if passphrase.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "mask_bad_request",
            "passphrase required",
        );
    }
    let ttl = match body.get("ttl_seconds") {
        None | Some(Value::Null) => state.config.handoff_ttl_seconds,
        Some(value) => match value.as_i64() {
            Some(ttl) if ttl > 0 => ttl,
            _ => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "mask_bad_request",
                    "ttl_seconds must be a positive integer",
                )
            }
        },
    };

    let records = state.with_session(|session| session.pseudonyms.export_records());
    let count = records.len();
    let payload = json!({"v": 1, "records": records});
    let envelope = match seal_with(&payload, passphrase, ttl, state.config.handoff_kdf()) {
        Ok(envelope) => envelope,
        Err(error) => {
            tracing::error!(%error, "seal failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "mask_seal_failed",
                "cannot seal the mapping table",
            );
        }
    };
    state.indicators.incr(Count::HandoffExports);
    tracing::info!(count, "admin export: records sealed");
    json_response(
        StatusCode::OK,
        json!({
            "count": count,
            "expires_at": envelope.exp,
            "envelope": envelope,
        }),
    )
}

async fn admin_import(State(state): State<AppState>, request: Request) -> Response {
    if let Some(denied) = admin_authorized(&state, &request) {
        return denied;
    }
    if state.config.session_scope != SessionScope::Global {
        return error_response(
            StatusCode::CONFLICT,
            "mask_scope_unsupported",
            "admin endpoints require session.scope = 'global'",
        );
    }
    let body = match read_json_body(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let Some(envelope_value) = body.get("envelope").filter(|v| v.is_object()) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "mask_bad_request",
            "passphrase and envelope required",
        );
    };
    let Some(passphrase) = body.get("passphrase").and_then(Value::as_str) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "mask_bad_request",
            "passphrase and envelope required",
        );
    };
    let malformed = || {
        error_response(
            StatusCode::BAD_REQUEST,
            "mask_bad_request",
            "malformed envelope",
        )
    };
    let envelope: Envelope = match serde_json::from_value(envelope_value.clone()) {
        Ok(envelope) => envelope,
        Err(_) => return malformed(),
    };
    if envelope.kdf.salt.is_empty() || envelope.boxed.is_empty() {
        return malformed();
    }

    let fingerprint = envelope_fingerprint(&envelope);
    let short_fp = &fingerprint[..12];
    let consumed = state
        .handoff_consumed
        .lock()
        .map(|set| set.contains(&fingerprint))
        .unwrap_or(false);
    if consumed {
        tracing::warn!("admin import: envelope consumed (fp {short_fp})");
        state.indicators.incr(Count::HandoffConsumed);
        return error_response(
            StatusCode::GONE,
            "mask_envelope_consumed",
            "envelope already imported; single use — request a fresh export",
        );
    }
    let failures = state
        .handoff_failures
        .lock()
        .map(|map| map.get(&fingerprint).copied().unwrap_or(0))
        .unwrap_or(0);
    if failures >= state.config.handoff_max_attempts {
        tracing::warn!("admin import: envelope locked (fp {short_fp})");
        state.indicators.incr(Count::HandoffLocks);
        return error_response(
            StatusCode::LOCKED,
            "mask_envelope_locked",
            "envelope locked after too many failed attempts; request a fresh export",
        );
    }

    let payload = match unseal(&envelope, passphrase) {
        Ok(payload) => payload,
        Err(UnsealError::Expired) => {
            tracing::warn!("admin import: envelope expired (fp {short_fp})");
            state.indicators.incr(Count::HandoffExpired);
            return error_response(
                StatusCode::GONE,
                "mask_envelope_expired",
                "envelope expired; request a fresh export",
            );
        }
        Err(error) => {
            let attempts = {
                let mut map = state
                    .handoff_failures
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let entry = map.entry(fingerprint.clone()).or_insert(0);
                *entry += 1;
                *entry
            };
            let remaining = state.config.handoff_max_attempts.saturating_sub(attempts);
            tracing::warn!(
                "admin import: unseal failed (fp {short_fp}, attempt {attempts}, {remaining} remaining): {error}"
            );
            if remaining == 0 {
                state.indicators.incr(Count::HandoffLocks);
                return error_response(
                    StatusCode::LOCKED,
                    "mask_envelope_locked",
                    "envelope locked after too many failed attempts; request a fresh export",
                );
            }
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({
                    "error": {
                        "message": "wrong passphrase or corrupted envelope",
                        "code": "mask_unseal_failed",
                        "attempts_remaining": remaining,
                    }
                }),
            );
        }
    };

    if let Ok(mut map) = state.handoff_failures.lock() {
        map.remove(&fingerprint);
    }
    let records = payload.get("records").and_then(Value::as_array);
    if payload.get("v").and_then(Value::as_i64) != Some(1) || records.is_none() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "mask_bad_request",
            "envelope payload has no records",
        );
    }

    let mut imported = 0u64;
    let mut already = 0u64;
    let mut conflict = 0u64;
    let mut invalid = 0u64;
    let mut conflicts: Vec<String> = Vec::new();
    state.with_session(|session| {
        for record in records.into_iter().flatten() {
            let (Some(token), Some(value)) = (
                record.get("token").and_then(Value::as_str),
                record.get("value").and_then(Value::as_str),
            ) else {
                invalid += 1;
                continue;
            };
            let occurrences = record
                .get("occurrences")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            match session.pseudonyms.import_record(token, value, occurrences) {
                crate::replace::ImportStatus::Imported => imported += 1,
                crate::replace::ImportStatus::Already => already += 1,
                crate::replace::ImportStatus::Conflict => {
                    conflict += 1;
                    conflicts.push(token.to_string());
                }
                crate::replace::ImportStatus::Invalid => invalid += 1,
            }
        }
    });

    // single use: this envelope will never import again
    if let Ok(mut set) = state.handoff_consumed.lock() {
        set.insert(fingerprint);
    }
    state.indicators.incr(Count::HandoffImports);
    tracing::info!(
        imported,
        already,
        conflict,
        invalid,
        "admin import complete"
    );
    json_response(
        StatusCode::OK,
        json!({
            "result": {
                "imported": imported,
                "already": already,
                "conflict": conflict,
                "invalid": invalid,
            },
            "conflicts": conflicts,
        }),
    )
}

/// Re-read `[mask].dictionary` now instead of waiting for the watcher.
///
/// The merge is additive, exactly like the hot path: this endpoint can add
/// terms or correct a type, never remove one, so it cannot be used to quiet
/// detection mid-session. The response is counts only — no term ever appears.
async fn admin_dictionary_reload(State(state): State<AppState>, request: Request) -> Response {
    if let Some(denied) = admin_authorized(&state, &request) {
        return denied;
    }
    let Some(path) = state.config.dictionary_path.clone() else {
        return error_response(
            StatusCode::CONFLICT,
            "mask_no_dictionary",
            "no [mask].dictionary is configured; nothing to reload",
        );
    };
    // Stamp first, then load: a write that lands between the two leaves a
    // different stamp behind, so the next poll reloads instead of skipping.
    let stamp = file_stamp(&path);
    let newer = match UserDictionary::load(&path) {
        Ok(newer) => newer,
        Err(error) => {
            tracing::error!(%error, "admin dictionary reload: cannot read the file");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "mask_dictionary_unreadable",
                "cannot read the dictionary file",
            );
        }
    };
    let report = state.merge_dictionary(&newer);
    {
        let mut watch = state
            .dictionary_watch
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        watch.stamp = stamp;
    }
    json_response(
        StatusCode::OK,
        json!({
            "added": report.added,
            "updated": report.updated,
            "kept": report.kept,
            "terms": report.terms,
        }),
    )
}

/// Count a leak-gate block the operator judged wrong.
///
/// Only a human can know a block was a false positive, so this is a manual
/// counter, not an inference: the operator sees a block, decides it was wrong,
/// and bumps `leak_false_positives` through the same admin gate as every other
/// operator action. `/status` publishes the running total with the other
/// counts.
async fn admin_leak_false_positive(State(state): State<AppState>, request: Request) -> Response {
    if let Some(denied) = admin_authorized(&state, &request) {
        return denied;
    }
    state.indicators.incr(Count::LeakFalsePositives);
    let total = state.indicators.get(Count::LeakFalsePositives);
    tracing::info!(
        leak_false_positives = total,
        "operator counted a false block"
    );
    json_response(StatusCode::OK, json!({"leak_false_positives": total}))
}

/// Read the live session's mapping table: what has this process masked?
///
/// Raw values are the reason this endpoint is not `/status`. It is therefore
/// local-only *regardless* of `gateway.admin_allow_remote` (403 otherwise),
/// and it sits behind the same operator gate as export/import. Values are
/// hashed unless the caller explicitly asks with `?values=true`; even then
/// only this response carries them — the log line is counts only.
async fn admin_session(State(state): State<AppState>, request: Request) -> Response {
    if let Some(denied) = session_authorized(&state, &request) {
        return denied;
    }
    let reveal_values = query_flag(request.uri().query(), "values");
    let snapshot = match &state.session {
        Some(shared) => {
            let session = shared.lock().unwrap_or_else(|e| e.into_inner());
            session_snapshot(Some(&session.pseudonyms), &state.config, reveal_values)
        }
        None => session_snapshot(None, &state.config, reveal_values),
    };
    tracing::info!(
        scope = state.config.session_scope.as_str(),
        records = snapshot["records"].as_u64().unwrap_or(0),
        values = reveal_values,
        "admin session snapshot"
    );
    json_response(StatusCode::OK, snapshot)
}

/// The session view is private to this machine: loopback client, then the
/// normal operator gate. Every refusal is a 403 so the response does not
/// distinguish "remote" from "missing token"; the body code still names why.
fn session_authorized(state: &AppState, request: &Request) -> Option<Response> {
    let client = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    if !is_loopback(client) {
        state.indicators.incr(Count::AdminGateRefusals);
        state.indicators.incr(Count::RequestsBlocked);
        tracing::warn!(?client, "session view refused from non-loopback client");
        return Some(error_response(
            StatusCode::FORBIDDEN,
            "mask_session_local_only",
            "the session view is local-only: connect over loopback",
        ));
    }
    let denied = admin_authorized(state, request)?;
    let (mut parts, body) = denied.into_parts();
    if parts.status == StatusCode::UNAUTHORIZED {
        parts.status = StatusCode::FORBIDDEN;
    }
    Some(Response::from_parts(parts, body))
}

fn query_flag(query: Option<&str>, name: &str) -> bool {
    query.is_some_and(|query| {
        query.split('&').any(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            key == name && matches!(value, "true" | "1")
        })
    })
}

/// Machine-readable session table. Stable keys: `session_scope`, `capacity`,
/// `remaining`, `records`, `total_occurrences`, and one `entries` object per
/// binding (`kind`, `token`, `occurrences`, `value_sha256_prefix`, and `value`
/// only when the operator asked for it).
fn session_snapshot(map: Option<&PseudonymMap>, config: &GatewayConfig, values: bool) -> Value {
    let scope = config.session_scope.as_str();
    let Some(map) = map else {
        return json!({
            "session_scope": scope,
            "capacity": Value::Null,
            "remaining": Value::Null,
            "records": 0,
            "total_occurrences": 0,
            "entries": [],
        });
    };
    let records = map.records();
    let total_occurrences: u64 = records.iter().map(|record| record.occurrences).sum();
    let entries: Vec<Value> = records
        .iter()
        .map(|record| {
            let mut entry = json!({
                "kind": record.kind.as_str(),
                "token": record.token,
                "occurrences": record.occurrences,
                "value_sha256_prefix": hash_prefix(record.value.as_bytes()),
            });
            if values {
                entry["value"] = json!(record.value);
            }
            entry
        })
        .collect();
    json!({
        "session_scope": scope,
        "capacity": map.capacity(),
        "remaining": map.remaining(),
        "records": records.len(),
        "total_occurrences": total_occurrences,
        "entries": entries,
    })
}

fn blocked_status(response: &Response) -> StatusCode {
    response.status()
}

fn blocked_error(response: &Response) -> (String, Value, Value, Value) {
    response
        .extensions()
        .get::<GateDetails>()
        .map(|details| {
            (
                details.message.clone(),
                json!(details.code),
                json!(details.fields),
                json!(details.leaks),
            )
        })
        .unwrap_or((
            "blocked by the mask gateway".to_string(),
            Value::Null,
            Value::Null,
            Value::Null,
        ))
}

/// One blocked leak in the client-facing shape. Paths carry hashed keys and a
/// value hash prefix; the raw value never appears.
#[derive(Clone, Debug, serde::Serialize)]
pub struct GateLeak {
    pub path: String,
    pub value_sha256_prefix: String,
}

/// Details attached to a leak-block response so the Anthropic entrance can
/// re-wrap them without re-reading the body.
#[derive(Clone, Debug)]
pub struct GateDetails {
    pub message: String,
    pub code: String,
    pub fields: Vec<String>,
    pub leaks: Vec<GateLeak>,
}

/// Forward allowlisted paths verbatim; refuse everything else.
///
/// Deny by default: only paths in `gateway.passthrough_allowlist` reach the
/// upstream. Allowlisted bodies are not masked (their schemas are not OpenAI
/// chat), but they still pass the outbound leak gate, so a known raw value
/// refuses the request instead of leaving the machine. The local `/v1` prefix
/// is stripped because `upstream_base_url` already carries the version segment.
async fn passthrough(State(state): State<AppState>, request: Request) -> Response {
    if let Some(denied) = authorize(&state, &request) {
        return denied;
    }
    state.indicators.incr(Count::RequestsTotal);
    let route = request.uri().path().to_string();
    if !state.config.passthrough_allowlist.contains(&route) {
        tracing::warn!("passthrough denied: {route}");
        state.indicators.incr(Count::PathsDenied);
        state.indicators.incr(Count::RequestsBlocked);
        return error_response(
            StatusCode::FORBIDDEN,
            "mask_path_blocked",
            &format!(
                "path {route} is not allowlisted; add it to gateway.passthrough_allowlist if it must pass"
            ),
        );
    }

    let method = request.method().clone();
    let headers = forwarded_headers(&state.config, request.headers());
    let body = match axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "mask_bad_request",
                "cannot read request body",
            )
        }
    };

    let blocked = if state.session.is_some() {
        let payload = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).to_string()))
        };
        state.with_session(|session| gate(&state, session, &payload, &headers, &route))
    } else {
        None
    };
    if let Some(blocked) = blocked {
        return blocked;
    }

    let forward = route.strip_prefix("/v1/").unwrap_or(&route).to_string();
    let url = state.config.upstream_url(&forward);
    let upstream = match send_upstream(&state, method, &url, &headers, None, Some(body)).await {
        Ok(response) => response,
        Err(response) => return response,
    };
    let status = upstream.status();
    let mut out_headers: Vec<(String, String)> = Vec::new();
    for (name, value) in upstream.headers().iter() {
        let name = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        if let Ok(value) = value.to_str() {
            out_headers.push((name, value.to_string()));
        }
    }
    let bytes = match upstream.bytes().await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!(%error, "cannot read upstream body");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "mask_upstream_error",
                "cannot read upstream response",
            );
        }
    };
    let response = body_response(status, bytes, None);
    with_headers(response, &out_headers)
}

// --- streaming ---------------------------------------------------------------

/// Incremental restorer for one upstream OpenAI SSE stream.
///
/// Both entrances translate to OpenAI chat for the upstream; this state
/// machine reads whatever byte boundaries the network gives it, restores the
/// text deltas, and renders the downstream protocol as it goes. The undecided
/// tail lives in `pending`: [`restore_stream_buffer`] returns only the prefix
/// that cannot be part of a token completed by a later chunk. At upstream EOF
/// [`Self::finish`] flushes it and emits the terminal events.
struct StreamRestorer {
    app: AppState,
    upstream: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
    byte_buf: Vec<u8>,
    pending: String,
    session: Session,
    measure: RequestMeasure,
    /// `true` renders Anthropic events; `false` renders OpenAI SSE chunks.
    anthropic: bool,
    /// Fallback model for `message_start` when the upstream omits it.
    model: String,
    meta: Map<String, Value>,
    tool_calls: BTreeMap<i64, Value>,
    finish_reason: Option<String>,
    /// Whether the OpenAI role delta / Anthropic text block has been opened.
    started: bool,
    message_started: bool,
    text_block_open: bool,
    done: bool,
}

impl StreamRestorer {
    fn into_body(self) -> Body {
        let stream = futures_util::stream::unfold(self, |mut restorer| async move {
            loop {
                if restorer.done {
                    return None;
                }
                match restorer.upstream.next().await {
                    Some(Ok(bytes)) => {
                        let out = restorer.on_bytes(&bytes);
                        if !out.is_empty() {
                            return Some((Ok::<Bytes, std::io::Error>(Bytes::from(out)), restorer));
                        }
                    }
                    Some(Err(error)) => {
                        // The status line is long gone; the honest signal is a
                        // truncated body (no finish event), not a 502 after 200.
                        tracing::error!(%error, "cannot read upstream stream");
                        restorer.done = true;
                        let out = restorer.flush_pending();
                        if out.is_empty() {
                            return None;
                        }
                        return Some((Ok(Bytes::from(out)), restorer));
                    }
                    None => {
                        restorer.done = true;
                        let out = restorer.finish();
                        if out.is_empty() {
                            return None;
                        }
                        return Some((Ok(Bytes::from(out)), restorer));
                    }
                }
            }
        });
        Body::from_stream(stream)
    }

    fn on_bytes(&mut self, bytes: &[u8]) -> String {
        self.byte_buf.extend_from_slice(bytes);
        let mut out = String::new();
        while let Some(line) = take_line(&mut self.byte_buf) {
            self.on_line(&line, &mut out);
        }
        out
    }

    fn on_line(&mut self, line: &str, out: &mut String) {
        let Some(payload) = line.strip_prefix("data:") else {
            return;
        };
        let payload = payload.trim();
        if payload == "[DONE]" {
            return;
        }
        let Ok(chunk) = serde_json::from_str::<Value>(payload) else {
            return;
        };
        self.on_chunk(&chunk, out);
    }

    fn on_chunk(&mut self, chunk: &Value, out: &mut String) {
        for key in ["id", "object", "created", "model", "system_fingerprint"] {
            if let Some(value) = chunk.get(key) {
                if !value.is_null() {
                    self.meta
                        .entry(key.to_string())
                        .or_insert_with(|| value.clone());
                }
            }
        }
        if let Some(choices) = chunk.get("choices").and_then(Value::as_array) {
            for choice in choices {
                if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                    if !reason.is_empty() {
                        self.finish_reason = Some(reason.to_string());
                    }
                }
                let Some(delta) = choice.get("delta") else {
                    continue;
                };
                if let Some(content) = delta.get("content").and_then(Value::as_str) {
                    self.feed_text(content, out);
                }
                if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
                    merge_tool_deltas(&mut self.tool_calls, calls);
                }
            }
        }
        self.ensure_message_start(out);
    }

    fn feed_text(&mut self, text: &str, out: &mut String) {
        self.pending.push_str(text);
        let (safe, keep) = restore_stream_buffer(&self.pending);
        self.pending = keep;
        self.emit_masked(&safe, out);
    }

    fn flush_pending(&mut self) -> String {
        let mut out = String::new();
        let pending = std::mem::take(&mut self.pending);
        self.emit_masked(&pending, &mut out);
        out
    }

    fn emit_masked(&mut self, masked: &str, out: &mut String) {
        if masked.is_empty() {
            return;
        }
        let restored = self.session.unmasked(masked);
        self.measure.observe_restore(&restored);
        for warning in &restored.warnings {
            tracing::warn!("restore: {warning}");
        }
        if restored.text.is_empty() {
            return;
        }
        if self.anthropic {
            self.emit_anthropic_text(&restored.text, out);
        } else {
            self.emit_openai_text(&restored.text, out);
        }
    }

    fn emit_openai_text(&mut self, text: &str, out: &mut String) {
        let delta = if self.started {
            json!({"content": text})
        } else {
            self.started = true;
            json!({"role": "assistant", "content": text})
        };
        out.push_str(&self.openai_chunk(delta, Value::Null));
    }

    fn emit_anthropic_text(&mut self, text: &str, out: &mut String) {
        self.ensure_message_start(out);
        if !self.text_block_open {
            self.text_block_open = true;
            out.push_str(&anthropic_text_block_start(0));
        }
        out.push_str(&anthropic_text_delta(0, text));
    }

    fn ensure_message_start(&mut self, out: &mut String) {
        if !self.anthropic || self.message_started {
            return;
        }
        self.message_started = true;
        let id = self
            .meta
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("msg_mask")
            .to_string();
        let model = self
            .meta
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or(&self.model)
            .to_string();
        out.push_str(&anthropic_stream_start(&id, &model));
    }

    fn openai_chunk(&self, delta: Value, finish: Value) -> String {
        let mut chunk = self.meta.clone();
        chunk.insert("object".to_string(), json!("chat.completion.chunk"));
        chunk.insert(
            "choices".to_string(),
            json!([{"index": 0, "delta": delta, "finish_reason": finish}]),
        );
        sse_line(Value::Object(chunk))
    }

    fn finish(&mut self) -> String {
        let mut out = String::new();
        if !self.byte_buf.is_empty() {
            let tail = std::mem::take(&mut self.byte_buf);
            let line = String::from_utf8_lossy(&tail)
                .trim_end_matches(['\r', '\n'])
                .to_string();
            self.on_line(&line, &mut out);
        }
        out.push_str(&self.flush_pending());
        if self.anthropic {
            self.finish_anthropic(&mut out);
        } else {
            self.finish_openai(&mut out);
        }
        out
    }

    fn finish_openai(&mut self, out: &mut String) {
        let mut calls = merged_tool_calls(&self.tool_calls);
        let has_calls = !calls.is_empty();
        if !self.started {
            self.started = true;
            out.push_str(
                &self.openai_chunk(json!({"role": "assistant", "content": ""}), Value::Null),
            );
        }
        if has_calls {
            restore_tool_calls(&mut calls, &mut self.session, &mut self.measure);
            out.push_str(&self.openai_chunk(json!({"tool_calls": calls}), Value::Null));
        }
        let reason = self
            .finish_reason
            .clone()
            .unwrap_or_else(|| if has_calls { "tool_calls" } else { "stop" }.to_string());
        out.push_str(&self.openai_chunk(json!({}), json!(reason)));
        out.push_str("data: [DONE]\n\n");
    }

    fn finish_anthropic(&mut self, out: &mut String) {
        self.ensure_message_start(out);
        let mut index = 0usize;
        if self.text_block_open {
            self.text_block_open = false;
            out.push_str(&anthropic_block_stop(0));
            index = 1;
        }
        let calls = merged_tool_calls(&self.tool_calls);
        let tool_uses: Vec<Value> = calls
            .iter()
            .map(|call| restored_tool_use(call, &mut self.session, &mut self.measure))
            .collect();
        for call in &tool_uses {
            out.push_str(&anthropic_tool_block(index, call));
            index += 1;
        }
        let mut stop = finish_reason(self.finish_reason.as_deref());
        if !tool_uses.is_empty() {
            stop = "tool_use";
        }
        out.push_str(&anthropic_stream_end(
            stop,
            json!({"input_tokens": 0, "output_tokens": 0}),
        ));
    }
}

impl Drop for StreamRestorer {
    fn drop(&mut self) {
        // Headers were already sent, so the cumulative indicator counters are
        // the only place where the tail's restore counts can land. This also
        // runs when the client disconnects mid-stream.
        record_measure(&self.app, &self.measure);
    }
}

fn take_line(buf: &mut Vec<u8>) -> Option<String> {
    let newline = buf.iter().position(|&b| b == b'\n')?;
    let line: Vec<u8> = buf.drain(..=newline).collect();
    Some(
        String::from_utf8_lossy(&line)
            .trim_end_matches(['\r', '\n'])
            .to_string(),
    )
}

fn merge_tool_deltas(tool_calls: &mut BTreeMap<i64, Value>, calls: &[Value]) {
    for call in calls {
        let index = call.get("index").and_then(Value::as_i64).unwrap_or(0);
        let entry = tool_calls
            .entry(index)
            .or_insert_with(|| json!({"id": "", "type": "function", "function": {}}));
        if let Some(id) = call.get("id").and_then(Value::as_str) {
            entry["id"] = json!(id);
        }
        let Some(function) = call.get("function") else {
            continue;
        };
        if let Some(name) = function.get("name").and_then(Value::as_str) {
            entry["function"]["name"] = json!(name);
        }
        if let Some(arguments) = function.get("arguments").and_then(Value::as_str) {
            let existing = entry["function"]
                .get("arguments")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            entry["function"]["arguments"] = json!(format!("{existing}{arguments}"));
        }
    }
}

fn merged_tool_calls(tool_calls: &BTreeMap<i64, Value>) -> Vec<Value> {
    tool_calls
        .values()
        .filter(|call| {
            call["function"].get("name").is_some() || call["function"].get("arguments").is_some()
        })
        .cloned()
        .collect()
}

/// Restore a stitched OpenAI tool call into an Anthropic `tool_use` block.
fn restored_tool_use(call: &Value, session: &mut Session, measure: &mut RequestMeasure) -> Value {
    let function = call.get("function").cloned().unwrap_or(Value::Null);
    let raw_args = function
        .get("arguments")
        .and_then(Value::as_str)
        .unwrap_or("{}");
    let args: Value = serde_json::from_str(raw_args).unwrap_or_else(|_| json!({"_raw": raw_args}));
    json!({
        "id": call.get("id").cloned().unwrap_or_else(|| json!("toolu_mask")),
        "name": function.get("name").cloned().unwrap_or_else(|| json!("")),
        "input": restored_strings(&args, session, measure),
    })
}

fn sse_line(payload: Value) -> String {
    format!("data: {payload}\n\n")
}

/// Stream one upstream SSE response, restoring text as it arrives.
///
/// HTTP status is settled before the body is handed downstream: a non-success
/// upstream is still a normal error response with its body, and an unreachable
/// upstream is still a 502. Only a body-read failure after the 200 is reported
/// by truncating the stream (the status can no longer be rewritten).
async fn proxy_streaming(
    state: &AppState,
    masked_body: &Value,
    headers: &[(String, String)],
    url: &str,
    entry: &'static str,
    measure: RequestMeasure,
) -> Response {
    let upstream =
        match send_upstream(state, Method::POST, url, headers, Some(masked_body), None).await {
            Ok(upstream) => upstream,
            Err(response) => return response,
        };
    let status = upstream.status();
    let content_type = upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    if !status.is_success() {
        let bytes = match upstream.bytes().await {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::error!(%error, "cannot read upstream stream");
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    "mask_upstream_error",
                    "cannot read upstream stream",
                );
            }
        };
        return body_response(
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            bytes,
            content_type,
        );
    }

    // One session snapshot for the whole stream: the mapping table cannot
    // change under a response, and a request-scoped session must not be
    // re-created per chunk.
    let session = state.with_session(|session| session.clone());
    let model = masked_body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let upstream: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>> =
        Box::pin(upstream.bytes_stream());
    let restorer = StreamRestorer {
        app: state.clone(),
        upstream,
        byte_buf: Vec::new(),
        pending: String::new(),
        session,
        measure,
        anthropic: entry == ENTRY_ANTHROPIC,
        model,
        meta: Map::new(),
        tool_calls: BTreeMap::new(),
        finish_reason: None,
        started: false,
        message_started: false,
        text_block_open: false,
        done: false,
    };
    let response_headers = request_headers(&restorer.measure, &state.config, entry);
    let body = restorer.into_body();
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    with_headers(response, &response_headers)
}

// --- server ------------------------------------------------------------------

/// Run the gateway until Ctrl-C.
pub async fn serve(mut config: GatewayConfig) -> anyhow::Result<()> {
    crate::install_crypto_provider();
    // Bind before announcing anything: a token printed for a gateway that then
    // fails to start is a token the human has written down for nothing.
    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|error| anyhow::anyhow!("cannot bind {addr}: {error}"))?;
    if config.admin_require_human && config.admin_human_token.is_none() {
        match guard::mint_admin_token() {
            Some(token) if guard::announce_operator_channel(&token) => {
                // The token itself never reaches a log: only this line does.
                tracing::info!("admin channel open (operator token printed to the terminal)");
                config.admin_human_token = Some(token);
            }
            Some(_) => tracing::warn!(
                "admin channel closed: no controlling terminal. Run `mask serve` from an \
                 interactive terminal, or set gateway.admin_require_human = false"
            ),
            None => tracing::warn!(
                "admin channel closed: the OS CSPRNG is unavailable, so no token could be minted"
            ),
        }
    }
    let app = create_app(config.clone(), None);
    let bound = listener.local_addr().unwrap_or_else(|_| {
        addr.parse()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], config.port)))
    });
    tracing::info!(
        "mask gateway listening on http://{bound} (upstream {}, scope {:?})",
        config.upstream_base_url,
        config.session_scope
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collects tracing output so a test can assert a warning was emitted.
    #[derive(Clone, Default)]
    struct LogBuffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
        type Writer = LogBuffer;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Broken arguments must reach the tool byte-for-byte and be reported, not
    /// silently rewritten into some other JSON value.
    #[test]
    fn invalid_tool_arguments_are_kept_verbatim_with_a_warning() {
        let mut session = Session::new(UserDictionary::new(), false);
        let mut measure = RequestMeasure::default();
        let raw = r#"{"who": "⟦人名1⟧""#;
        let log = LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(log.clone())
            .finish();
        let restored = tracing::subscriber::with_default(subscriber, || {
            restore_arguments_json(raw, &mut session, &mut measure)
        });
        assert_eq!(restored, raw);
        let logged = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("not valid JSON"), "{logged}");
    }

    /// A panic while the session lock was held used to poison it, and every
    /// later request then panicked in `with_session`. It must recover.
    #[test]
    fn poisoned_session_mutex_still_serves_requests() {
        crate::install_crypto_provider();
        let dictionary = UserDictionary::new();
        let shared = Arc::new(Mutex::new(Session::new(dictionary.clone(), false)));
        let state = AppState {
            config: Arc::new(GatewayConfig::default()),
            http: reqwest::Client::new(),
            dictionary: Arc::new(RwLock::new(dictionary)),
            dictionary_watch: Arc::new(Mutex::new(DictionaryWatch::default())),
            indicators: Arc::new(Indicators::new()),
            session: Some(shared.clone()),
            admin_human_token: None,
            handoff_failures: Arc::new(Mutex::new(HashMap::new())),
            handoff_consumed: Arc::new(Mutex::new(HashSet::new())),
        };

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = shared.lock().unwrap();
            panic!("simulated panic while the session lock was held");
        }));
        assert!(shared.is_poisoned());

        let capacity = state.with_session(|session| session.pseudonyms.len());
        assert_eq!(capacity, 0);
    }
}
