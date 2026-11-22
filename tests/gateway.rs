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
    assert_eq!(error["fields"], json!(["user"]));
    assert_eq!(error["values"], json!(["山田太郎"]));
    assert!(h.upstream.last().is_none(), "request left the process");
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
    assert!(
        fields.contains(&json!("header:x-title")),
        "fields: {fields:?}"
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
