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
//! - `/v1/chat/completions` with `stream=true`: the upstream SSE stream is
//!   buffered to completion, restored as a whole, and returned as a single SSE
//!   chunk. Correct but not incremental; incremental restore is future work.
//! - `tool_calls` function arguments are masked (JSON strings are parsed and
//!   every string inside is masked).
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
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::detect::dictionary::UserDictionary;
use crate::gateway::agent::{
    anthropic_stream_events, anthropic_to_openai, openai_to_anthropic, restored_strings,
};
use crate::gateway::indicators::{
    build_posture, request_headers, Count, Indicators, RequestMeasure,
};
use crate::gateway::leakguard::{find_header_leaks, find_leaks, Leak};
use crate::gateway::sharing::{envelope_fingerprint, seal_with, unseal, Envelope, UnsealError};
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

/// Shared gateway state.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<GatewayConfig>,
    pub http: reqwest::Client,
    pub dictionary: Arc<UserDictionary>,
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
        match &self.session {
            Some(shared) => {
                let mut guard = shared.lock().expect("session mutex poisoned");
                f(&mut guard)
            }
            None => {
                let mut session = Session::new((*self.dictionary).clone(), self.config.use_ner);
                f(&mut session)
            }
        }
    }

    fn mapping_records(&self) -> usize {
        match &self.session {
            Some(shared) => shared
                .lock()
                .map(|guard| guard.pseudonyms.len())
                .unwrap_or(0),
            None => 0,
        }
    }

    fn posture(&self) -> Value {
        build_posture(&self.config, self.mapping_records(), self.dictionary.size())
    }
}

/// Build the gateway app.
///
/// The HTTP client is injectable so tests can point it at a mock upstream.
pub fn create_app(config: GatewayConfig, client: Option<reqwest::Client>) -> Router {
    crate::install_crypto_provider();

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
        Some(Arc::new(Mutex::new(Session::new(
            dictionary.clone(),
            config.use_ner,
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
        dictionary: Arc::new(dictionary),
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

fn mask_text_value(text: &str, session: &mut Session, measure: &mut RequestMeasure) -> String {
    let (masked, result) = session.masked(text);
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
    masked
}

fn mask_content(content: &Value, session: &mut Session, measure: &mut RequestMeasure) -> Value {
    match content {
        Value::String(text) => Value::String(mask_text_value(text, session, measure)),
        Value::Array(parts) => Value::Array(
            parts
                .iter()
                .map(|part| match part {
                    Value::Object(map) if map.get("text").is_some_and(|t| t.is_string()) => {
                        let text = map.get("text").and_then(Value::as_str).unwrap_or("");
                        let mut map = map.clone();
                        map.insert(
                            "text".to_string(),
                            Value::String(mask_text_value(text, session, measure)),
                        );
                        Value::Object(map)
                    }
                    other => other.clone(),
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Mask every string inside a parsed JSON argument blob.
fn mask_strings(node: &Value, session: &mut Session, measure: &mut RequestMeasure) -> Value {
    match node {
        Value::String(text) => Value::String(mask_text_value(text, session, measure)),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), mask_strings(v, session, measure)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| mask_strings(v, session, measure))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Mask a JSON-encoded string; non-JSON strings are masked as text.
fn mask_json_string(raw: &str, session: &mut Session, measure: &mut RequestMeasure) -> String {
    match serde_json::from_str::<Value>(raw) {
        Ok(parsed) => {
            let masked = mask_strings(&parsed, session, measure);
            serde_json::to_string(&masked).unwrap_or_else(|_| raw.to_string())
        }
        Err(_) => mask_text_value(raw, session, measure),
    }
}

/// Mask PII inside `tool_calls[*].function.arguments`.
fn mask_tool_calls(
    tool_calls: &Value,
    session: &mut Session,
    measure: &mut RequestMeasure,
) -> Value {
    let Value::Array(items) = tool_calls else {
        return tool_calls.clone();
    };
    Value::Array(
        items
            .iter()
            .map(|call| {
                let Some(call_map) = call.as_object() else {
                    return call.clone();
                };
                let Some(function) = call_map.get("function").and_then(Value::as_object) else {
                    return call.clone();
                };
                let Some(arguments) = function.get("arguments").and_then(Value::as_str) else {
                    return call.clone();
                };
                let mut call_map = call_map.clone();
                let mut function = function.clone();
                function.insert(
                    "arguments".to_string(),
                    Value::String(mask_json_string(arguments, session, measure)),
                );
                call_map.insert("function".to_string(), Value::Object(function));
                Value::Object(call_map)
            })
            .collect(),
    )
}

/// Return a copy of the request body with PII in messages replaced.
pub fn mask_chat_request(
    body: &Value,
    session: &mut Session,
    measure: &mut RequestMeasure,
) -> Value {
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
                mask_content(&content, session, measure),
            );
            if let Some(tool_calls) = message_map.get("tool_calls").cloned() {
                message_map.insert(
                    "tool_calls".to_string(),
                    mask_tool_calls(&tool_calls, session, measure),
                );
            }
            out.push(Value::Object(message_map));
        }
        masked.insert("messages".to_string(), Value::Array(out));
    }
    Value::Object(masked)
}

fn restore_text(text: &str, session: &Session, measure: &mut RequestMeasure) -> String {
    let restored = session.unmasked(text);
    measure.observe_restore(&restored);
    for warning in &restored.warnings {
        tracing::warn!("restore: {warning}");
    }
    restored.text
}

/// Restore pseudonyms in `choices[*].message.content`, in place.
pub fn restore_chat_response(data: &mut Value, session: &Session, measure: &mut RequestMeasure) {
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
        let Some(content) = message.get("content").and_then(Value::as_str) else {
            continue;
        };
        let restored = restore_text(content, session, measure);
        message["content"] = Value::String(restored);
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
/// The client-facing error echoes the offending values: the client is the
/// trusted local user and sent them in the first place. Logs carry only field
/// paths and a value hash, never the raw value.
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
        let digest = Sha256::digest(leak.value.as_bytes());
        let hash: String = digest.iter().take(6).map(|b| format!("{b:02x}")).collect();
        tracing::warn!("leak gate: {source} {} (value sha256:{hash})", leak.path);
    }
    if state.config.leak_gate == LeakGate::Warn {
        state.indicators.incr(Count::LeakWarnings);
        return None;
    }
    state.indicators.incr(Count::LeakBlocks);
    state.indicators.incr(Count::RequestsBlocked);
    let fields: Vec<String> = leaks.iter().map(|l| l.path.clone()).collect();
    let values: Vec<String> = leaks.iter().map(|l| l.value.clone()).collect();
    let mut response = json_response(
        StatusCode::BAD_REQUEST,
        json!({
            "error": {
                "message": "mask gateway: unmasked PII detected in the request; nothing was sent to the upstream",
                "code": "mask_leak_blocked",
                "fields": fields,
                "values": values,
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
        values,
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
    let (masked, blocked) = state.with_session(|session| {
        let masked = mask_chat_request(&body, session, &mut measure);
        let blocked = gate(&state, session, &masked, &headers, "chat/completions");
        (masked, blocked)
    });
    if let Some(blocked) = blocked {
        return blocked;
    }

    let url = state.config.upstream_url("chat/completions");
    if body.get("stream").and_then(Value::as_bool).unwrap_or(false) {
        state.indicators.incr(Count::StreamRequests);
        return proxy_streaming(&state, &masked, &headers, &url, ENTRY_OPENAI).await;
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
    let (openai_body, masked, blocked) = state.with_session(|session| {
        let openai_body = anthropic_to_openai(&body);
        let masked = mask_chat_request(&openai_body, session, &mut measure);
        let blocked = gate(&state, session, &masked, &headers, "v1/messages");
        (openai_body, masked, blocked)
    });
    if let Some(blocked) = blocked {
        // Re-wrap the gate decision in the Anthropic error envelope.
        let err = blocked_error(&blocked);
        return anthropic_error(
            blocked_status(&blocked),
            "invalid_request_error",
            err.0.as_str(),
            json!({"mask_code": err.1, "mask_fields": err.2, "mask_values": err.3}),
        );
    }

    let url = state.config.upstream_url("chat/completions");
    if openai_body
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        state.indicators.incr(Count::StreamRequests);
        let chunks = match collect_chat_stream(&state, &masked, &headers, &url).await {
            Ok(Collected::Chunks(chunks)) => chunks,
            Ok(Collected::Error {
                status,
                body,
                content_type,
            }) => return body_response(status, body, content_type),
            Err(response) => return response,
        };
        let restored_text =
            state.with_session(|session| restore_text(&chunks.text, session, &mut measure));
        let tool_uses: Vec<Value> = state.with_session(|session| {
            chunks
                .tool_calls
                .iter()
                .map(|call| {
                    let function = call.get("function").cloned().unwrap_or(Value::Null);
                    let raw_args = function
                        .get("arguments")
                        .and_then(Value::as_str)
                        .unwrap_or("{}");
                    let args: Value = serde_json::from_str(raw_args)
                        .unwrap_or_else(|_| json!({"_raw": raw_args}));
                    let input = restored_strings(&args, session, &mut measure);
                    let mut use_block = Map::new();
                    use_block.insert(
                        "id".to_string(),
                        call.get("id")
                            .cloned()
                            .unwrap_or_else(|| json!("toolu_mask")),
                    );
                    use_block.insert(
                        "name".to_string(),
                        function.get("name").cloned().unwrap_or_else(|| json!("")),
                    );
                    use_block.insert("input".to_string(), input);
                    Value::Object(use_block)
                })
                .collect()
        });
        let stop_reason = if tool_uses.is_empty() {
            "end_turn"
        } else {
            "tool_use"
        };
        let message = json!({
            "id": chunks.meta.get("id").cloned().unwrap_or_else(|| json!("msg_mask")),
            "type": "message",
            "role": "assistant",
            "model": chunks.meta.get("model").cloned()
                .or_else(|| body.get("model").cloned())
                .unwrap_or_else(|| json!("")),
            "content": [],
            "stop_reason": stop_reason,
            "stop_sequence": Value::Null,
            "usage": {"input_tokens": 0, "output_tokens": 0},
        });
        record_measure(&state, &measure);
        let events = anthropic_stream_events(&message, &restored_text, &tool_uses);
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from(events))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        response = with_headers(
            response,
            &request_headers(&measure, &state.config, ENTRY_ANTHROPIC),
        );
        return response;
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
                    .expect("handoff failure mutex poisoned");
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
                json!(details.values),
            )
        })
        .unwrap_or((
            "blocked by the mask gateway".to_string(),
            Value::Null,
            Value::Null,
            Value::Null,
        ))
}

/// Details attached to a leak-block response so the Anthropic entrance can
/// re-wrap them without re-reading the body.
#[derive(Clone, Debug)]
pub struct GateDetails {
    pub message: String,
    pub code: String,
    pub fields: Vec<String>,
    pub values: Vec<String>,
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

/// Metadata + restored payload collected from a buffered upstream SSE stream.
pub struct Chunks {
    pub meta: Map<String, Value>,
    pub text: String,
    pub tool_calls: Vec<Value>,
}

pub enum Collected {
    Chunks(Chunks),
    Error {
        status: StatusCode,
        body: Bytes,
        content_type: Option<String>,
    },
}

/// Buffer an upstream OpenAI SSE stream to completion.
///
/// Tool-call fragments are stitched by index so the merged arguments JSON
/// survives chunk boundaries; masking already happened upstream of this.
#[allow(clippy::result_large_err)]
async fn collect_chat_stream(
    state: &AppState,
    masked_body: &Value,
    headers: &[(String, String)],
    url: &str,
) -> Result<Collected, Response> {
    let upstream =
        send_upstream(state, Method::POST, url, headers, Some(masked_body), None).await?;
    let status = upstream.status();
    let content_type = upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = upstream.bytes().await.map_err(|error| {
        tracing::error!(%error, "cannot read upstream stream");
        error_response(
            StatusCode::BAD_GATEWAY,
            "mask_upstream_error",
            "cannot read upstream stream",
        )
    })?;
    if !status.is_success() {
        return Ok(Collected::Error {
            status: StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            body: bytes,
            content_type,
        });
    }

    let mut meta: Map<String, Value> = Map::new();
    let mut text = String::new();
    let mut tool_calls: BTreeMap<i64, Value> = BTreeMap::new();

    let raw = String::from_utf8_lossy(&bytes);
    for line in raw.split('\n') {
        let line = line.trim_end_matches('\r');
        let Some(payload) = line.strip_prefix("data:") else {
            continue;
        };
        let payload = payload.trim();
        if payload == "[DONE]" {
            break;
        }
        let Ok(chunk) = serde_json::from_str::<Value>(payload) else {
            continue;
        };
        for key in ["id", "object", "created", "model", "system_fingerprint"] {
            if let Some(value) = chunk.get(key) {
                if !value.is_null() {
                    meta.entry(key.to_string()).or_insert_with(|| value.clone());
                }
            }
        }
        if let Some(choices) = chunk.get("choices").and_then(Value::as_array) {
            for choice in choices {
                let Some(delta) = choice.get("delta") else {
                    continue;
                };
                if let Some(content) = delta.get("content").and_then(Value::as_str) {
                    text.push_str(content);
                }
                let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) else {
                    continue;
                };
                for call in calls {
                    let index = call.get("index").and_then(Value::as_i64).unwrap_or(0);
                    let entry = tool_calls
                        .entry(index)
                        .or_insert_with(|| json!({"id": "", "type": "function", "function": {}}));
                    if let Some(id) = call.get("id").and_then(Value::as_str) {
                        entry["id"] = json!(id);
                    }
                    if let Some(function) = call.get("function") {
                        if let Some(name) = function.get("name").and_then(Value::as_str) {
                            entry["function"]["name"] = json!(name);
                        }
                        if let Some(arguments) = function.get("arguments").and_then(Value::as_str) {
                            let existing = entry["function"]
                                .get("arguments")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                            entry["function"]["arguments"] =
                                json!(format!("{existing}{arguments}"));
                        }
                    }
                }
            }
        }
    }

    let merged: Vec<Value> = tool_calls
        .into_values()
        .filter(|call| {
            call["function"].get("name").is_some() || call["function"].get("arguments").is_some()
        })
        .collect();

    Ok(Collected::Chunks(Chunks {
        meta,
        text,
        tool_calls: merged,
    }))
}

fn sse_line(payload: Value) -> String {
    format!("data: {payload}\n\n")
}

/// Buffer the upstream SSE stream, restore it whole, emit OpenAI chunks.
async fn proxy_streaming(
    state: &AppState,
    masked_body: &Value,
    headers: &[(String, String)],
    url: &str,
    entry: &str,
) -> Response {
    let mut measure = RequestMeasure::default();
    let collected = match collect_chat_stream(state, masked_body, headers, url).await {
        Ok(collected) => collected,
        Err(response) => return response,
    };
    let chunks = match collected {
        Collected::Chunks(chunks) => chunks,
        Collected::Error {
            status,
            body,
            content_type,
        } => return body_response(status, body, content_type),
    };

    let restored = state.with_session(|session| restore_text(&chunks.text, session, &mut measure));
    record_measure(state, &measure);

    let mut meta = chunks.meta.clone();
    meta.insert("object".to_string(), json!("chat.completion.chunk"));
    let finish_reason = if chunks.tool_calls.is_empty() {
        "stop"
    } else {
        "tool_calls"
    };
    let mut delta = Map::new();
    delta.insert("role".to_string(), json!("assistant"));
    delta.insert("content".to_string(), json!(restored));
    if !chunks.tool_calls.is_empty() {
        delta.insert(
            "tool_calls".to_string(),
            Value::Array(chunks.tool_calls.clone()),
        );
    }
    let mut first = meta.clone();
    first.insert(
        "choices".to_string(),
        json!([{"index": 0, "delta": delta, "finish_reason": Value::Null}]),
    );
    let mut last = meta;
    last.insert(
        "choices".to_string(),
        json!([{"index": 0, "delta": {}, "finish_reason": finish_reason}]),
    );

    let mut body = String::new();
    body.push_str(&sse_line(Value::Object(first)));
    body.push_str(&sse_line(Value::Object(last)));
    body.push_str("data: [DONE]\n\n");

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    response = with_headers(response, &request_headers(&measure, &state.config, entry));
    response
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
