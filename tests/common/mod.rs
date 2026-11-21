#![allow(dead_code)]
//! Shared test harness: a real (loopback) mock upstream and a real gateway.
//!
//! Tests exercise the actual binary path — HTTP in, HTTP out — rather than
//! calling handlers directly, so masking, the leak gate, header forwarding and
//! the SSE buffering are all covered end to end.

use std::net::SocketAddr;
use std::path::PathBuf;
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

fn sse(chunks: &[Value], model: &str) -> Response {
    let mut lines: Vec<String> = Vec::new();
    for delta in chunks {
        let chunk = json!({
            "id": "chatcmpl-1",
            "object": "chat.completion.chunk",
            "created": 1,
            "model": model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": Value::Null}],
        });
        lines.push(format!("data: {chunk}"));
    }
    lines.push("data: [DONE]".to_string());
    let body = format!("{}\n\n", lines.join("\n\n"));
    (
        StatusCode::OK,
        [("content-type", "text/event-stream")],
        body,
    )
        .into_response()
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

/// Write a temporary dictionary file (TSV) and return its path.
pub fn dict_file<S: AsRef<str>, T: AsRef<str>>(terms: &[(S, T)]) -> PathBuf {
    let mut name = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    name.push(format!("mask-test-{}-{nanos}.tsv", std::process::id()));
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

use mask::types::EntityType;

/// Known-PII Japanese samples for recall/restore regression. Each sample lists
/// the entities that MUST be found (recall gate).
pub struct Canary {
    pub name: &'static str,
    pub text: &'static str,
    pub expected: &'static [(EntityType, &'static str)],
}

pub fn canaries() -> &'static [Canary] {
    &[
        Canary {
            name: "basic_contact",
            text: "お問い合わせは 山田太郎 (yamada.taro@example.co.jp, 090-1234-5678) まで。fax は 03-1234-5678 です。",
            expected: &[
                (EntityType::Person, "山田太郎"),
                (EntityType::Email, "yamada.taro@example.co.jp"),
                (EntityType::Phone, "090-1234-5678"),
                (EntityType::Phone, "03-1234-5678"),
            ],
        },
        Canary {
            name: "address_full",
            text: "配送先は 〒160-0022 東京都新宿区新宿三丁目1番1号 サカエビル203 です。山田太郎様あて。",
            expected: &[
                (EntityType::Address, "〒160-0022 東京都新宿区新宿三丁目1番1号"),
                (EntityType::Person, "山田太郎"),
            ],
        },
        Canary {
            name: "address_ward_only",
            text: "詳細住所は港区赤坂一丁目2番3号のマンション103号室です。",
            expected: &[(EntityType::Address, "港区赤坂一丁目2番3号")],
        },
        Canary {
            name: "bank_account",
            text: "お振込みは 佐藤花子 (08098761234) の 三菱UFJ銀行 新宿支店 普通 1234567 にお願いします。カード番号は 4242 4242 4242 4242 です。",
            expected: &[
                (EntityType::Person, "佐藤花子"),
                (EntityType::Phone, "08098761234"),
                (EntityType::Account, "普通 1234567"),
                (EntityType::Account, "4242 4242 4242 4242"),
            ],
        },
        Canary {
            name: "multiple_people",
            text: "山田太郎と佐藤花子が契約者である。山田太郎の勤務先は株式会社ACMEで、連絡先は tanaka@acme.example.jp。",
            expected: &[
                (EntityType::Person, "山田太郎"),
                (EntityType::Person, "佐藤花子"),
                (EntityType::Org, "株式会社ACME"),
                (EntityType::Email, "tanaka@acme.example.jp"),
            ],
        },
        Canary {
            name: "fullwidth",
            text: "連絡先は ０９０‐１２３４‐５６７８。住所は大阪市北区梅田１丁目２番３号。",
            expected: &[
                (EntityType::Phone, "０９０‐１２３４‐５６７８"),
                (EntityType::Address, "大阪市北区梅田１丁目２番３号"),
            ],
        },
    ]
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
