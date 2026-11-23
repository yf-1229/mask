//! Gateway tests: masking, restoring, streaming, leak gate, deny-by-default
//! passthrough, gateway token.
//!
//! Everything runs against a real loopback mock upstream that records what it
//! receives, so the negative property this tool exists for — a known raw value
//! never reaches the model — is asserted on the bytes that actually left.

mod common;

use common::{base_config, chat_body, start, start_with, start_with_dict, text_of, MockKind};
use serde_json::{json, Value};
use std::time::Duration;

// --- masking / restoring -----------------------------------------------------

#[tokio::test]
async fn request_is_masked_and_upstream_sees_pseudonyms() {
    let h = start_with_dict(&[("山田太郎", "person")]).await;
    let response = h
        .post_json(
            "/v1/chat/completions",
            chat_body("山田太郎さんと090-1234-5678の件"),
        )
        .await;
    assert_eq!(response.status(), 200);

    let sent = h.upstream.sent();
    let text = sent["messages"][0]["content"].as_str().unwrap().to_string();
    assert!(
        !text.contains("山田太郎"),
        "raw name reached upstream: {text}"
    );
    assert!(
        !text.contains("090-1234-5678"),
        "raw phone reached upstream: {text}"
    );
    assert!(text.contains('⟦') && text.contains('⟧'), "{text}");

    // the real upstream key is injected; the client's own key is not forwarded
    let headers = h.upstream.last().unwrap().headers;
    assert_eq!(headers.get("authorization").unwrap(), "Bearer sk-real");
}

#[tokio::test]
async fn client_api_key_is_replaced_with_the_upstream_key() {
    let h = start_with_dict(&[("山田太郎", "person")]).await;
    let response = h
        .client
        .post(h.url("/v1/chat/completions"))
        .bearer_auth("sk-client-dummy")
        .json(&chat_body("山田太郎さんの件"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let headers = h.upstream.last().unwrap().headers;
    assert_eq!(headers.get("authorization").unwrap(), "Bearer sk-real");
}

#[tokio::test]
async fn response_is_restored_for_the_user() {
    let h = start_with_dict(&[("山田太郎", "person")]).await;
    let response = h
        .post_json(
            "/v1/chat/completions",
            chat_body("山田太郎さんと090-1234-5678の件"),
        )
        .await;
    let body: Value = response.json().await.unwrap();
    let content = text_of(&body);
    assert!(content.contains("山田太郎"), "{content}");
    assert!(content.contains("090-1234-5678"), "{content}");
    assert!(!content.contains('⟦'), "{content}");
}

#[tokio::test]
async fn streaming_request_gets_restored_sse() {
    let h = start_with_dict(&[("山田太郎", "person")]).await;
    let mut body = chat_body("山田太郎さんの件");
    body["stream"] = json!(true);
    let response = h.post_json("/v1/chat/completions", body).await;
    assert_eq!(response.status(), 200);
    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        content_type.starts_with("text/event-stream"),
        "{content_type}"
    );
    let text = response.text().await.unwrap();
    assert!(text.contains("data: [DONE]"), "{text}");
    assert!(text.contains("山田太郎"), "{text}");
    assert!(!text.contains('⟦'), "{text}");
}

async fn start_with_dict_kind(kind: MockKind) -> common::Harness {
    let config = mask::gateway::config::GatewayConfig {
        dictionary_path: Some(common::dict_file(&[("山田太郎", "person")])),
        ..common::base_config()
    };
    start_with(config, kind).await
}

fn streamed_json(text: &str) -> Vec<Value> {
    text.lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter_map(|data| serde_json::from_str::<Value>(data).ok())
        .collect()
}

async fn assert_split_token_is_restored(kind: MockKind) {
    let h = start_with_dict_kind(kind).await;
    let mut body = chat_body("山田太郎さんの件");
    body["stream"] = json!(true);
    let response = h.post_json("/v1/chat/completions", body).await;
    assert_eq!(response.status(), 200);
    let text = response.text().await.unwrap();
    let restored: String = streamed_json(&text)
        .iter()
        .filter_map(|chunk| {
            chunk
                .pointer("/choices/0/delta/content")
                .and_then(Value::as_str)
        })
        .collect();
    assert_eq!(restored, "山田太郎さんの件");
    assert!(
        !restored.contains('⟦'),
        "token leaked to client: {restored}"
    );
    let finish = streamed_json(&text)
        .iter()
        .filter_map(|chunk| {
            chunk
                .pointer("/choices/0/finish_reason")
                .and_then(Value::as_str)
        })
        .next_back()
        .map(str::to_string);
    assert_eq!(finish.as_deref(), Some("stop"), "{text}");
}

#[tokio::test]
async fn stream_token_split_after_open_is_restored() {
    assert_split_token_is_restored(MockKind::SplitAfterOpen).await;
}

#[tokio::test]
async fn stream_token_split_inside_is_restored() {
    assert_split_token_is_restored(MockKind::SplitInside).await;
}

#[tokio::test]
async fn stream_token_split_before_close_is_restored() {
    assert_split_token_is_restored(MockKind::SplitBeforeClose).await;
}

#[tokio::test]
async fn first_restored_text_arrives_before_the_upstream_finishes() {
    let h = start_with_dict_kind(MockKind::SlowStream).await;
    let mut body = chat_body("山田太郎さんの件");
    body["stream"] = json!(true);
    let started = std::time::Instant::now();
    let mut response = h.post_json("/v1/chat/completions", body).await;
    assert_eq!(response.status(), 200);
    let first = tokio::time::timeout(Duration::from_millis(1500), response.chunk())
        .await
        .expect("first chunk was withheld until the upstream finished")
        .expect("stream ended before its first chunk")
        .unwrap();
    let first = String::from_utf8_lossy(&first).to_string();
    assert!(first.contains("山田太郎"), "first chunk: {first}");
    assert!(!first.contains('⟦'), "first chunk: {first}");
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "first chunk took {:?}",
        started.elapsed()
    );
    let rest = response.text().await.unwrap();
    assert!(rest.contains("さん"), "rest: {rest}");
}

#[tokio::test]
async fn upstream_error_passes_through() {
    let h = start(MockKind::Echo).await;
    let response = h
        .post_json(
            "/v1/chat/completions",
            json!({"model": "gpt", "messages": []}),
        )
        .await;
    assert_eq!(response.status(), 401);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_api_key");
}

#[tokio::test]
async fn global_scope_keeps_tokens_stable_across_requests() {
    let h = start_with_dict(&[("山田太郎", "person")]).await;
    let mut seen: Vec<String> = Vec::new();
    for _ in 0..2 {
        let response = h
            .post_json("/v1/chat/completions", chat_body("山田太郎さんの件"))
            .await;
        assert_eq!(response.status(), 200);
        seen.push(
            h.upstream.sent()["messages"][0]["content"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    assert_eq!(seen[0], seen[1]);
}

#[tokio::test]
async fn request_scope_gets_a_fresh_table_per_request() {
    let config = mask::gateway::config::GatewayConfig {
        session_scope: mask::gateway::config::SessionScope::Request,
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;
    let mut seen: Vec<String> = Vec::new();
    for _ in 0..2 {
        let response = h
            .post_json("/v1/chat/completions", chat_body("090-1234-5678の件"))
            .await;
        assert_eq!(response.status(), 200);
        seen.push(
            h.upstream.sent()["messages"][0]["content"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    // the phone number was masked in both, and each request drew from its own
    // freshly shuffled pool (request scope keeps no table between requests)
    assert!(!seen[0].contains("090-1234-5678"));
    assert!(!seen[1].contains("090-1234-5678"));
    assert!(seen[0].contains('⟦') && seen[1].contains('⟦'));
    assert_ne!(seen[0], seen[1], "request scope must not reuse a table");
}

// --- outbound leak gate ------------------------------------------------------

#[tokio::test]
async fn pii_in_unmasked_field_is_blocked_before_sending() {
    let h = start_with_dict(&[("山田太郎", "person")]).await;
    let mut body = chat_body("山田太郎さんの件");
    body["user"] = json!("山田太郎");
    let response = h.post_json("/v1/chat/completions", body).await;
    assert_eq!(response.status(), 400);
    let payload: Value = response.json().await.unwrap();
    let error = &payload["error"];
    assert_eq!(error["code"], "mask_leak_blocked");
    assert_eq!(error["fields"], json!(["key#04f8996d"]));
    assert!(
        error.get("values").is_none(),
        "raw values in response: {error}"
    );
    assert_eq!(
        error["leaks"],
        json!([{
            "path": "key#04f8996d",
            "value_sha256_prefix": "6b0e1c8c",
        }])
    );
    assert!(!payload.to_string().contains("山田太郎"), "{payload}");
    assert!(h.upstream.last().is_none(), "request left the process");
}

#[tokio::test]
async fn key_leak_is_hashed_in_the_log_and_the_response() {
    let h = start_with_dict(&[("山田太郎", "person")]).await;
    let mut body = chat_body("山田太郎さんの件");
    body["metadata"] = json!({"山田太郎": "note"});
    let response = h.post_json("/v1/chat/completions", body).await;
    assert_eq!(response.status(), 400);
    let payload: Value = response.json().await.unwrap();
    let error = &payload["error"];
    assert_eq!(error["code"], "mask_leak_blocked");
    // the raw key appears nowhere in the client-visible error
    assert!(!payload.to_string().contains("山田太郎"), "{payload}");
    assert!(error.get("values").is_none(), "{error}");
    assert!(
        error["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field.as_str().unwrap().ends_with("(key)")),
        "the key hit must stay visible as a hashed path: {error}"
    );

    // the log line is rendered from the same structured path; this is the
    // shape the gate walked (the masked request keeps the unknown key)
    let values = vec!["山田太郎".to_string()];
    let leaks =
        mask::gateway::leakguard::find_leaks(&json!({"metadata": {"山田太郎": "note"}}), &values);
    assert_eq!(leaks.len(), 1, "{leaks:?}");
    let line = leaks[0].log_line("v1/chat");
    assert!(!line.contains("山田太郎"), "{line}");
    assert!(!line.contains("metadata"), "{line}");
    assert!(line.contains("key#") && line.contains("(key)"), "{line}");
    assert!(line.contains("sha256:6b0e1c8c"), "{line}");
}

#[tokio::test]
async fn leak_gate_warn_mode_sends_anyway() {
    let config = mask::gateway::config::GatewayConfig {
        leak_gate: mask::gateway::config::LeakGate::Warn,
        dictionary_path: Some(common::dict_file(&[("山田太郎", "person")])),
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;
    let mut body = chat_body("山田太郎さんの件");
    body["user"] = json!("山田太郎");
    let response = h.post_json("/v1/chat/completions", body).await;
    assert_eq!(response.status(), 200);
    assert!(h.upstream.last().is_some());
}

#[tokio::test]
async fn fullwidth_variant_in_unmasked_field_is_blocked() {
    let h = start_with_dict(&[("090-1234-5678", "phone")]).await;
    let mut body = chat_body("090-1234-5678に電話して");
    body["user"] = json!("０９０－１２３４－５６７８");
    let response = h.post_json("/v1/chat/completions", body).await;
    assert_eq!(response.status(), 400);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "mask_leak_blocked");
    assert!(h.upstream.last().is_none());
}

#[tokio::test]
async fn pii_in_forwarded_header_is_blocked() {
    let h = start_with_dict(&[("taro@example.com", "email")]).await;
    let response = h
        .client
        .post(h.url("/v1/chat/completions"))
        .header("X-Title", "about taro@example.com")
        .json(&chat_body("taro@example.com に送って"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "mask_leak_blocked");
    let fields = payload["error"]["fields"].as_array().unwrap().clone();
    // the header name is a key too: hashed, never printed raw
    assert!(
        fields.contains(&json!("header.key#ec4d3f7d")),
        "fields: {fields:?}"
    );
    assert!(
        !payload.to_string().contains("taro@example.com"),
        "{payload}"
    );
    assert!(h.upstream.last().is_none());
}

#[tokio::test]
async fn allowlisted_passthrough_is_leak_gated() {
    let config = mask::gateway::config::GatewayConfig {
        dictionary_path: Some(common::dict_file(&[("山田太郎", "person")])),
        passthrough_allowlist: vec!["/v1/embeddings".to_string()],
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;
    // seed the session table
    let response = h
        .post_json("/v1/chat/completions", chat_body("山田太郎さんの件"))
        .await;
    assert_eq!(response.status(), 200);
    let response = h
        .post_json("/v1/embeddings", json!({"input": "山田太郎", "model": "e"}))
        .await;
    assert_eq!(response.status(), 400);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "mask_leak_blocked");
}

#[tokio::test]
async fn compound_place_name_passes_with_and_without_session_history() {
    use mask::gateway::config::GatewayConfig;
    // NER detects 田中 from the honorific on turn one; 田中町 is a place, not a
    // person, so turn two must pass whether or not the session has history.
    let config = GatewayConfig {
        use_ner: true,
        ..base_config()
    };
    let warm = start_with(config.clone(), MockKind::Echo).await;
    let response = warm
        .post_json(
            "/v1/chat/completions",
            chat_body("田中さんに確認してください。"),
        )
        .await;
    assert_eq!(response.status(), 200);

    let review = chat_body("田中町に住む。");
    let response = warm.post_json("/v1/chat/completions", review.clone()).await;
    assert_eq!(
        response.status(),
        200,
        "session history turned 田中町 into a leak"
    );
    assert!(
        warm.upstream.sent_raw().contains("田中町"),
        "the town name must reach the upstream unmasked"
    );

    // Same body, no history: the verdict must not depend on the session.
    let fresh = start_with(config, MockKind::Echo).await;
    let response = fresh.post_json("/v1/chat/completions", review).await;
    assert_eq!(response.status(), 200);
    assert_eq!(fresh.upstream.sent(), warm.upstream.sent());
}

#[tokio::test]
async fn short_value_in_metadata_is_not_a_leak() {
    let h = start_with_dict(&[("出口", "person")]).await;
    let mut body = chat_body("よろしくお願いします。");
    body["metadata"] = json!({"出口": "note"});
    body["stop"] = json!(["出口"]);
    let response = h.post_json("/v1/chat/completions", body).await;
    assert_eq!(response.status(), 200);
    assert!(h.upstream.last().is_some());
}

#[tokio::test]
async fn short_value_is_still_blocked_in_body_text() {
    use mask::gateway::config::GatewayConfig;
    let config = GatewayConfig {
        use_ner: true,
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;
    // 出口 is detected with an honorific (a person)...
    let response = h
        .post_json("/v1/chat/completions", chat_body("出口さんに聞く。"))
        .await;
    assert_eq!(response.status(), 200);
    // ...and the everyday word in body text is still a re-mention: fail closed.
    let response = h
        .post_json("/v1/chat/completions", chat_body("出口で待っています。"))
        .await;
    assert_eq!(response.status(), 400);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"]["code"],
        "mask_leak_blocked"
    );
    assert!(
        !h.upstream.sent_raw().contains("出口で待っています"),
        "the blocked request reached the upstream"
    );
}

// --- tool_calls masking ------------------------------------------------------

#[tokio::test]
async fn tool_call_arguments_are_masked() {
    let h = start_with_dict(&[("山田太郎", "person")]).await;
    let arguments = json!({"name": "山田太郎", "note": "よろしく"}).to_string();
    let response = h
        .post_json(
            "/v1/chat/completions",
            json!({
                "model": "gpt",
                "messages": [
                    {"role": "user", "content": "山田太郎さんに折返し電話"},
                    {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [
                            {
                                "id": "call-1",
                                "type": "function",
                                "function": {"name": "dial", "arguments": arguments},
                            }
                        ],
                    },
                ],
            }),
        )
        .await;
    assert_eq!(response.status(), 200);
    let sent = h.upstream.sent();
    let got = sent["messages"][1]["tool_calls"][0]["function"]["arguments"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!got.contains("山田太郎"), "{got}");
    assert!(got.contains('⟦'), "{got}");
    let parsed: Value = serde_json::from_str(&got).unwrap();
    assert_eq!(parsed["note"], "よろしく");
}

// --- tool_calls restoration --------------------------------------------------

#[tokio::test]
async fn tool_call_arguments_are_restored_in_streamed_response() {
    let h = start_with_dict_kind(MockKind::StreamToolCalls).await;
    let mut body = chat_body("山田太郎さんの件");
    body["stream"] = json!(true);
    let response = h.post_json("/v1/chat/completions", body).await;
    assert_eq!(response.status(), 200);
    let text = response.text().await.unwrap();
    let arguments: String = streamed_json(&text)
        .iter()
        .filter_map(|chunk| {
            chunk
                .pointer("/choices/0/delta/tool_calls/0/function/arguments")
                .and_then(Value::as_str)
        })
        .collect();
    assert!(
        !arguments.contains('⟦'),
        "token leaked to client: {arguments}"
    );
    let parsed: Value = serde_json::from_str(&arguments).unwrap();
    assert_eq!(parsed["who"], "山田太郎", "{arguments}");
    assert_eq!(parsed["note"], "折返し", "{arguments}");
}

#[tokio::test]
async fn tool_call_arguments_are_restored_in_non_streamed_response() {
    let h = start_with_dict_kind(MockKind::Agent).await;
    let response = h
        .post_json(
            "/v1/chat/completions",
            json!({
                "model": "gpt",
                "messages": [{"role": "user", "content": "山田太郎さんの件"}],
                "tools": [{"type": "function", "function": {"name": "lookup"}}],
            }),
        )
        .await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    let arguments = body
        .pointer("/choices/0/message/tool_calls/0/function/arguments")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no arguments in {body}"));
    assert!(
        !arguments.contains('⟦'),
        "token leaked to client: {arguments}"
    );
    let parsed: Value = serde_json::from_str(arguments).unwrap();
    assert_eq!(parsed["who"], "山田太郎", "{arguments}");
}

// --- deny-by-default passthrough ---------------------------------------------

#[tokio::test]
async fn unknown_path_is_denied_by_default() {
    let h = start(MockKind::Echo).await;
    let response = h
        .post_json("/v1/embeddings", json!({"input": "山田太郎", "model": "e"}))
        .await;
    assert_eq!(response.status(), 403);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "mask_path_blocked");
    assert!(h.upstream.last().is_none());
}

#[tokio::test]
async fn allowlisted_models_endpoint_is_forwarded() {
    let h = start(MockKind::Echo).await;
    let response = h.get("/v1/models").await;
    // the mock upstream has no such route: forwarded, then 404 -- never 403
    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn allowlisted_passthrough_forwards_the_body() {
    let config = mask::gateway::config::GatewayConfig {
        passthrough_allowlist: vec!["/v1/embeddings".to_string()],
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;
    let response = h
        .post_json("/v1/embeddings", json!({"input": "hello", "model": "e"}))
        .await;
    assert_eq!(response.status(), 404); // mocked upstream has no such route
}

// --- gateway token -----------------------------------------------------------

#[tokio::test]
async fn gateway_token_is_required() {
    let config = mask::gateway::config::GatewayConfig {
        gateway_token: "team-secret".to_string(),
        dictionary_path: Some(common::dict_file(&[("山田太郎", "person")])),
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;

    let denied = h
        .post_json("/v1/chat/completions", chat_body("山田太郎さんの件"))
        .await;
    assert_eq!(denied.status(), 401);
    let payload: Value = denied.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "mask_unauthorized");

    let ok = h
        .post_json_auth(
            "/v1/chat/completions",
            chat_body("山田太郎さんの件"),
            "team-secret",
        )
        .await;
    assert_eq!(ok.status(), 200);

    // Anthropic-style header works on the OpenAI entrance too
    let ok = h
        .client
        .post(h.url("/v1/chat/completions"))
        .header("x-api-key", "team-secret")
        .json(&chat_body("山田太郎さんの件"))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
}

#[tokio::test]
async fn gateway_token_protects_passthrough_too() {
    let config = mask::gateway::config::GatewayConfig {
        gateway_token: "team-secret".to_string(),
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;
    let response = h.get("/v1/models").await;
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn wrong_token_is_rejected_and_never_sends() {
    let config = mask::gateway::config::GatewayConfig {
        gateway_token: "team-secret".to_string(),
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;
    let response = h
        .client
        .post(h.url("/v1/chat/completions"))
        .bearer_auth("wrong")
        .json(&chat_body("hello"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert!(h.upstream.last().is_none());
}

// --- canary end-to-end proof -------------------------------------------------

#[tokio::test]
async fn canary_corpus_never_reaches_upstream() {
    let config = mask::gateway::config::GatewayConfig {
        dictionary_path: Some(common::dict_file(&common::canary_terms())),
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;
    for canary in common::canaries() {
        let response = h
            .post_json("/v1/chat/completions", chat_body(&canary.text))
            .await;
        assert_eq!(response.status(), 200, "{}", canary.name);
        let raw = h.upstream.sent_raw();
        for (_, value) in &canary.expected {
            assert!(
                !raw.contains(value.as_str()),
                "{}: {value:?} reached upstream",
                canary.name
            );
        }
    }
}

#[tokio::test]
async fn unreachable_upstream_is_a_clean_gateway_error() {
    mask::install_crypto_provider();
    let config = mask::gateway::config::GatewayConfig {
        upstream_base_url: "http://127.0.0.1:1/v1".to_string(),
        ..base_config()
    };
    let app = mask::gateway::create_app(config, Some(reqwest::Client::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let response = reqwest::Client::new()
        .post(format!("http://{addr}/v1/chat/completions"))
        .json(&chat_body("hello"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "mask_upstream_unreachable");
}

/// Regression for #10: 300 distinct entities overflow the default 256-id pool.
/// That request fails with `mask_session_full` — nothing reaches the upstream —
/// and the gateway (and its poisoned-prone session mutex) keeps serving.
#[tokio::test]
async fn session_capacity_exhaustion_fails_one_request_and_recovers() {
    let terms: Vec<(String, &str)> = (0..300)
        .map(|i| (format!("用語{i:03}"), "person"))
        .collect();
    let h = start_with_dict(&terms).await;

    let text = terms
        .iter()
        .map(|(term, _)| term.as_str())
        .collect::<Vec<_>>()
        .join("、");
    let response = h.post_json("/v1/chat/completions", chat_body(&text)).await;
    assert_eq!(response.status(), 400);
    let error: Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "mask_session_full");
    assert_eq!(error["error"]["capacity"], 256);
    let rendered = error.to_string();
    assert!(
        !rendered.contains("用語"),
        "the error must not echo raw values: {rendered}"
    );
    assert!(
        h.upstream.last().is_none(),
        "a request that could not be fully masked must not be sent upstream"
    );

    // The process still answers, and an already-bound value keeps its token.
    let response = h
        .post_json("/v1/chat/completions", chat_body("用語000"))
        .await;
    assert_eq!(response.status(), 200);
    let sent = h.upstream.sent();
    let masked = sent["messages"][0]["content"].as_str().unwrap().to_string();
    assert!(masked.contains('⟦'), "{masked}");
    assert!(!masked.contains("用語000"), "{masked}");
}
