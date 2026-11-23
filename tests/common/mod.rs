#![allow(dead_code)]
//! Shared test harness: a real (loopback) mock upstream and a real gateway.
//!
//! Tests exercise the actual binary path — HTTP in, HTTP out — rather than
//! calling handlers directly, so masking, the leak gate, header forwarding and
//! the SSE buffering are all covered end to end.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use mask::gateway::config::{GatewayConfig, LeakGate, SessionScope};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MockKind {
    /// Echo the masked text back; 401 when the request carried no content.
    Echo,
    /// Echo text, and emit a tool_call echoing the first token when the
    /// request declares tools (agent flow).
    Agent,
    /// Streaming split after the opening token bracket (`⟦`).
    SplitAfterOpen,
    /// Streaming split in the middle of the first token.
    SplitInside,
    /// Streaming split immediately before the closing token bracket (`⟧`).
    SplitBeforeClose,
    /// Streaming, first token-sized chunk then a delayed second chunk. Used to
    /// prove the gateway does not wait for upstream completion.
    SlowStream,
    /// Streaming tool call whose JSON arguments are split across two deltas,
    /// with the boundary inside a pseudonym token.
    StreamToolCalls,
}

#[derive(Clone, Debug)]
pub struct CapturedRequest {
    pub path: String,
    pub headers: HeaderMap,
    pub body: Value,
    pub raw_body: String,
}

pub struct MockUpstream {
    pub base_url: String,
    pub captured: Arc<Mutex<Option<CapturedRequest>>>,
    _handle: JoinHandle<()>,
}

impl MockUpstream {
    pub fn last(&self) -> Option<CapturedRequest> {
        self.captured.lock().unwrap().clone()
    }

    pub fn sent(&self) -> Value {
        self.last().expect("upstream received no request").body
    }

    pub fn sent_raw(&self) -> String {
        self.last().expect("upstream received no request").raw_body
    }
}

pub struct Harness {
    pub base_url: String,
    pub upstream: MockUpstream,
    pub config: GatewayConfig,
    pub client: reqwest::Client,
    _handle: JoinHandle<()>,
}

impl Harness {
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    pub async fn post_json(&self, path: &str, body: Value) -> reqwest::Response {
        self.client
            .post(self.url(path))
            .json(&body)
            .send()
            .await
            .expect("gateway request failed")
    }

    pub async fn post_json_auth(&self, path: &str, body: Value, token: &str) -> reqwest::Response {
        self.client
            .post(self.url(path))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .expect("gateway request failed")
    }

    pub async fn get(&self, path: &str) -> reqwest::Response {
        self.client
            .get(self.url(path))
            .send()
            .await
            .expect("gateway request failed")
    }

    pub async fn get_auth(&self, path: &str, token: &str) -> reqwest::Response {
        self.client
            .get(self.url(path))
            .bearer_auth(token)
            .send()
            .await
            .expect("gateway request failed")
    }
}

pub fn base_config() -> GatewayConfig {
    GatewayConfig {
        // replaced by the harness with the mock upstream's address
        upstream_base_url: "http://127.0.0.1:1/v1".to_string(),
        upstream_api_key: "sk-real".to_string(),
        use_ner: false,
        session_scope: SessionScope::Global,
        leak_gate: LeakGate::Block,
        // The operator-terminal gate is exercised on its own in tests/guard.rs;
        // the rest of the suite drives /admin directly, like a human's curl.
        admin_require_human: false,
        ..GatewayConfig::default()
    }
}

/// Start a mock upstream and a gateway wired to it.
pub async fn start_with(config: GatewayConfig, kind: MockKind) -> Harness {
    mask::install_crypto_provider();
    let upstream = start_upstream(kind).await;
    let config = GatewayConfig {
        upstream_base_url: upstream.base_url.clone(),
        ..config
    };
    let app = mask::gateway::create_app(config.clone(), Some(reqwest::Client::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    Harness {
        base_url: format!("http://{addr}"),
        upstream,
        config,
        client: reqwest::Client::new(),
        _handle: handle,
    }
}

pub async fn start(kind: MockKind) -> Harness {
    start_with(base_config(), kind).await
}

/// A gateway with a dictionary (and NER off, so detection is deterministic).
pub async fn start_with_dict<S: AsRef<str>, T: AsRef<str>>(terms: &[(S, T)]) -> Harness {
    let config = GatewayConfig {
        dictionary_path: Some(dict_file(terms)),
        ..base_config()
    };
    start_with(config, MockKind::Echo).await
}

async fn start_upstream(kind: MockKind) -> MockUpstream {
    // reqwest clients must not be built before the rustls provider exists
    mask::install_crypto_provider();
    let captured: Arc<Mutex<Option<CapturedRequest>>> = Arc::new(Mutex::new(None));
    let state = (kind, captured.clone());
    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(
                |State((kind, captured)): State<(
                    MockKind,
                    Arc<Mutex<Option<CapturedRequest>>>,
                )>,
                 headers: HeaderMap,
                 body: axum::body::Bytes| async move {
                    let raw_body = String::from_utf8_lossy(&body).to_string();
                    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    let response = upstream_response(kind, &parsed).into_response();
                    *captured.lock().unwrap() = Some(CapturedRequest {
                        path: "/v1/chat/completions".to_string(),
                        headers,
                        body: parsed,
                        raw_body,
                    });
                    response
                },
            ),
        )
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    MockUpstream {
        base_url: format!("http://{addr}/v1"),
        captured,
        _handle: handle,
    }
}

fn message_texts(body: &Value) -> Vec<String> {
    body.get("messages")
        .and_then(Value::as_array)
        .map(|messages| {
            messages
                .iter()
                .filter_map(|m| m.get("content").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn sse_line(delta: &Value, model: &str) -> String {
    let chunk = json!({
        "id": "chatcmpl-1",
        "object": "chat.completion.chunk",
        "created": 1,
        "model": model,
        "choices": [{"index": 0, "delta": delta, "finish_reason": Value::Null}],
    });
    format!("data: {chunk}\n\n")
}

fn sse(chunks: &[Value], model: &str) -> Response {
    let mut body = String::new();
    for delta in chunks {
        body.push_str(&sse_line(delta, model));
    }
    body.push_str("data: [DONE]\n\n");
    (
        StatusCode::OK,
        [("content-type", "text/event-stream")],
        body,
    )
        .into_response()
}

/// One delayed event after the first: enough for two separate reads on the
/// gateway's upstream connection, which is what makes the split real.
fn sse_delayed(chunks: Vec<Value>, model: &str, delay: std::time::Duration) -> Response {
    let mut parts: Vec<String> = chunks.iter().map(|d| sse_line(d, model)).collect();
    parts.push("data: [DONE]\n\n".to_string());
    let stream = futures_util::stream::unfold((parts, 0usize), move |(parts, index)| async move {
        if index >= parts.len() {
            return None;
        }
        if index == 1 {
            tokio::time::sleep(delay).await;
        }
        let out = parts[index].clone();
        Some((
            Ok::<_, std::io::Error>(axum::body::Bytes::from(out)),
            (parts, index + 1),
        ))
    });
    (
        StatusCode::OK,
        [("content-type", "text/event-stream")],
        axum::body::Body::from_stream(stream),
    )
        .into_response()
}

/// Byte offset to split the masked streamed content at, for the split mocks.
fn split_point(content: &str, kind: MockKind) -> usize {
    let open = content.find('⟦');
    let close = content.find('⟧');
    match (kind, open, close) {
        (MockKind::SplitAfterOpen, Some(open), _) => open + '⟦'.len_utf8(),
        (MockKind::SplitBeforeClose, _, Some(close)) => close,
        (MockKind::SplitInside, Some(open), Some(close)) => {
            let inner = &content[open..close];
            inner
                .char_indices()
                .nth(2)
                .map(|(offset, _)| open + offset)
                .unwrap_or(close)
        }
        _ => content
            .char_indices()
            .nth(1)
            .map(|(offset, _)| offset)
            .unwrap_or(content.len()),
    }
}

fn upstream_response(kind: MockKind, body: &Value) -> Response {
    let texts = message_texts(body);
    if kind == MockKind::Echo && texts.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": {"message": "bad key", "code": "invalid_api_key"}})),
        )
            .into_response();
    }
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("gpt")
        .to_string();
    let content = if texts.is_empty() {
        "(echo)".to_string()
    } else {
        texts.join(" ")
    };

    if body.get("stream").and_then(Value::as_bool).unwrap_or(false) {
        if kind == MockKind::StreamToolCalls {
            let token = first_token(&content).unwrap_or_default();
            let arguments = json!({"who": token, "note": "折返し"}).to_string();
            // Split just before the closing bracket: the two deltas only form
            // a complete token (and a complete JSON document) once joined.
            let split = arguments.find('⟧').unwrap_or(arguments.len());
            let (head, tail) = arguments.split_at(split);
            return sse(
                &[
                    json!({"role": "assistant", "content": Value::Null, "tool_calls": [
                        {"index": 0, "id": "call_1", "type": "function",
                         "function": {"name": "lookup", "arguments": ""}}
                    ]}),
                    json!({"tool_calls": [
                        {"index": 0, "function": {"arguments": head}}
                    ]}),
                    json!({"tool_calls": [
                        {"index": 0, "function": {"arguments": tail}}
                    ]}),
                ],
                &model,
            );
        }
        let (head, tail) = match kind {
            MockKind::SplitAfterOpen | MockKind::SplitInside | MockKind::SplitBeforeClose => {
                let at = split_point(&content, kind);
                (content[..at].to_string(), content[at..].to_string())
            }
            MockKind::SlowStream => {
                // Split at the first complete token so the first chunk is
                // immediately restorable and the delay proves incremental send.
                let at = content
                    .find('⟧')
                    .map(|index| index + '⟧'.len_utf8())
                    .unwrap_or_else(|| content.len());
                (content[..at].to_string(), content[at..].to_string())
            }
            _ => {
                let head: String = content.chars().take(3).collect();
                let tail: String = content.chars().skip(3).collect();
                return sse(
                    &[
                        json!({"role": "assistant", "content": head}),
                        json!({"content": tail}),
                    ],
                    &model,
                );
            }
        };
        let chunks = vec![
            json!({"role": "assistant", "content": head}),
            json!({"content": tail}),
        ];
        return match kind {
            MockKind::SlowStream => sse_delayed(chunks, &model, std::time::Duration::from_secs(2)),
            _ => sse_delayed(chunks, &model, std::time::Duration::from_millis(20)),
        };
    }

    if kind == MockKind::Agent && body.get("tools").is_some() {
        let last_role = body
            .get("messages")
            .and_then(Value::as_array)
            .and_then(|m| m.last())
            .and_then(|m| m.get("role"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if let Some(token) = first_token(&content) {
            if last_role != "tool" {
                return Json(json!({
                    "id": "chatcmpl-1",
                    "object": "chat.completion",
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": Value::Null,
                            "tool_calls": [{
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "lookup",
                                    "arguments": json!({"who": token}).to_string(),
                                },
                            }],
                        },
                        "finish_reason": "tool_calls",
                    }],
                    "usage": {"prompt_tokens": 7, "completion_tokens": 9},
                }))
                .into_response();
            }
        }
    }

    Json(json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 7, "completion_tokens": 9},
    }))
    .into_response()
}

fn first_token(text: &str) -> Option<String> {
    let start = text.find('⟦')?;
    let end = text[start..].find('⟧')? + start + '⟧'.len_utf8();
    Some(text[start..end].to_string())
}

/// Write a temporary file and return its path.
pub fn temp_file(name: &str, content: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    path.push(format!("mask-test-{}-{nanos}-{name}", std::process::id()));
    std::fs::write(&path, content).expect("cannot write temp file");
    path
}

/// Distinguishes calls that land in the same clock tick. Windows'
/// `SystemTime::now()` resolution is coarse enough that parallel tests have
/// seen the same nanosecond; pid+nanos alone then made two tests share one
/// temporary dictionary, and the later write won (`dictionary_terms` 1
/// instead of 2).
static DICT_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

fn dict_file_path(nanos: u128) -> PathBuf {
    let seq = DICT_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "mask-test-{}-{nanos}-{seq}.tsv",
        std::process::id()
    ));
    path
}

/// Write a temporary dictionary file (TSV) and return its path.
pub fn dict_file<S: AsRef<str>, T: AsRef<str>>(terms: &[(S, T)]) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = dict_file_path(nanos);
    let content = terms
        .iter()
        .map(|(term, kind)| format!("{}\t{}", term.as_ref(), kind.as_ref()))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&name, content).expect("cannot write dictionary");
    name
}

pub fn chat_body(content: &str) -> Value {
    json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": content}],
    })
}

pub fn text_of(response: &Value) -> String {
    response
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

// --- canary corpus -----------------------------------------------------------

use std::sync::OnceLock;

use mask::types::EntityType;

/// Known-PII Japanese samples for recall/restore regression, loaded from
/// `tests/corpus/canary.txt`. Each sample lists the entities that MUST be found
/// (recall gate). The corpus is data, not code: adding a case needs no Rust.
pub struct Canary {
    pub name: String,
    pub text: String,
    pub expected: Vec<(EntityType, String)>,
}

static CORPUS: OnceLock<Vec<Canary>> = OnceLock::new();

pub fn canaries() -> &'static [Canary] {
    CORPUS.get_or_init(|| parse_corpus(include_str!("../corpus/canary.txt")))
}

/// Parse the block format:
///
/// ```text
/// # case: name
/// text: the sentence
/// person: 山田太郎
/// phone: 090-1234-5678
/// ```
///
/// Blank lines and `#` comments are ignored; `key: value` splits at the first
/// colon, so `text:` may itself contain colons.
pub fn parse_corpus(source: &str) -> Vec<Canary> {
    let mut cases: Vec<Canary> = Vec::new();
    let mut current: Option<Canary> = None;
    for (index, raw) in source.lines().enumerate() {
        let line = raw.trim();
        let line_number = index + 1;
        if line.is_empty() || (line.starts_with('#') && !line.starts_with("# case:")) {
            continue;
        }
        if let Some(name) = line.strip_prefix("# case:") {
            if let Some(case) = current.take() {
                cases.push(case);
            }
            let name = name.trim();
            assert!(!name.is_empty(), "line {line_number}: empty case name");
            current = Some(Canary {
                name: name.to_string(),
                text: String::new(),
                expected: Vec::new(),
            });
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            panic!("line {line_number}: expected `key: value`");
        };
        let key = key.trim();
        let value = value.trim();
        let case = current
            .as_mut()
            .unwrap_or_else(|| panic!("line {line_number}: entry before a `# case:` header"));
        if key == "text" {
            case.text = value.to_string();
            continue;
        }
        let kind = EntityType::from_name(key)
            .unwrap_or_else(|| panic!("line {line_number}: unknown type {key:?}"));
        case.expected.push((kind, value.to_string()));
    }
    if let Some(case) = current.take() {
        cases.push(case);
    }
    cases
}

/// `(type, value)` pairs for a dictionary that makes the canary corpus
/// deterministic regardless of detection quality.
pub fn canary_terms() -> Vec<(String, String)> {
    canaries()
        .iter()
        .flat_map(|c| c.expected.iter())
        .map(|(kind, value)| (value.to_string(), kind.as_str().to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dict_file_paths_differ_within_the_same_clock_tick() {
        // Two calls with the same clock reading must not share a path; the
        // counter is what keeps parallel tests from overwriting each other.
        assert_ne!(dict_file_path(1), dict_file_path(1));
    }
}
