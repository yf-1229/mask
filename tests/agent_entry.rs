//! Agent entrance tests: the Anthropic-protocol `/v1/messages` proxy.
//!
//! Claude Code and friends enter here. The canary property must hold on this
//! entrance exactly as on the OpenAI one: nothing the session detected ever
//! reaches the upstream, while the client sees real values again.

mod common;

use common::{base_config, start_with, start_with_dict, MockKind};
use mask::gateway::config::GatewayConfig;
use serde_json::{json, Value};

fn messages_body(text: &str) -> Value {
    json!({
        "model": "claude-x",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": [{"type": "text", "text": text}]}],
    })
}

fn tools() -> Value {
    json!([{"name": "lookup", "description": "d", "input_schema": {"type": "object"}}])
}

#[tokio::test]
async fn messages_request_is_masked_and_restored() {
    let h = start_with_dict(&[("山田太郎", "person")]).await;
    let mut body = messages_body("山田太郎さんの件");
    body["system"] = json!("丁寧に");
    let response = h.post_json("/v1/messages", body).await;
    assert_eq!(response.status(), 200);

    // the raw name never travelled; the translation + masking did
    let raw = h.upstream.sent_raw();
    assert!(!raw.contains("山田"), "raw name reached upstream: {raw}");
    let sent = h.upstream.sent();
    assert_eq!(sent["messages"][0]["role"], "system");
    assert!(sent["messages"][1]["content"]
        .as_str()
        .unwrap()
        .starts_with("⟦人名"));

    let data: Value = response.json().await.unwrap();
    assert_eq!(data["type"], "message");
    assert_eq!(data["role"], "assistant");
    let texts: Vec<&str> = data["content"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|block| block["type"] == "text")
        .map(|block| block["text"].as_str().unwrap())
        .collect();
    assert!(texts[0].contains("山田太郎"), "{texts:?}");
    assert_eq!(data["stop_reason"], "end_turn");
    assert_eq!(data["usage"]["input_tokens"], 7);
}

#[tokio::test]
async fn messages_response_carries_indicator_headers() {
    let h = start_with_dict(&[("山田太郎", "person")]).await;
    let response = h
        .post_json("/v1/messages", messages_body("山田太郎さんの件"))
        .await;
    assert_eq!(response.status(), 200);
    let headers = response.headers();
    assert_eq!(headers.get("X-Mask-In").unwrap(), "v1/messages");
    assert_eq!(headers.get("X-Mask-Masked").unwrap(), "1");
    assert_eq!(headers.get("X-Mask-Restored").unwrap(), "1");
}

#[tokio::test]
async fn messages_tool_use_round_trip() {
    // tools run locally, so tool_use arguments are restored on the way out
    let h = start_with(
        GatewayConfig {
            dictionary_path: Some(common::dict_file(&[("山田太郎", "person")])),
            ..base_config()
        },
        MockKind::Agent,
    )
    .await;
    let mut body = messages_body("山田太郎さんの件");
    body["tools"] = tools();
    let response = h.post_json("/v1/messages", body).await;
    assert_eq!(response.status(), 200);
    let data: Value = response.json().await.unwrap();
    let tool_blocks: Vec<&Value> = data["content"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|block| block["type"] == "tool_use")
        .collect();
    assert!(!tool_blocks.is_empty(), "{data}");
    assert_eq!(tool_blocks[0]["name"], "lookup");
    assert_eq!(tool_blocks[0]["input"]["who"], "山田太郎");
    assert_eq!(data["stop_reason"], "tool_use");
    // the upstream only ever saw the token
    assert!(h.upstream.sent_raw().contains("⟦人名"));
}

#[tokio::test]
async fn messages_translates_tool_results_and_uses_tools() {
    let h = start_with(
        GatewayConfig {
            dictionary_path: Some(common::dict_file(&[("山田太郎", "person")])),
            ..base_config()
        },
        MockKind::Agent,
    )
    .await;
    // turn 1 establishes the mapping
    let response = h
        .post_json("/v1/messages", messages_body("山田太郎さんの連絡先"))
        .await;
    assert_eq!(response.status(), 200);

    // turn 2: the harness sends a tool_result back, as Claude Code does
    let body = json!({
        "model": "claude-x",
        "max_tokens": 100,
        "tools": tools(),
        "messages": [
            {"role": "user", "content": "山田太郎さんの連絡先"},
            {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "id": "toolu_1", "name": "lookup",
                     "input": {"who": "山田太郎"}}
                ],
            },
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1",
                     "content": "山田太郎の電話は090-1234-5678"}
                ],
            },
        ],
    });
    let response = h.post_json("/v1/messages", body).await;
    assert_eq!(response.status(), 200);
    let sent = h.upstream.sent();
    let roles: Vec<&str> = sent["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["role"].as_str().unwrap())
        .collect();
    assert!(roles.contains(&"tool"), "{roles:?}");
    let tool_message = sent["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["role"] == "tool")
        .unwrap();
    assert_eq!(tool_message["tool_call_id"], "toolu_1");
    // the tool result was masked on the way in
    let content = tool_message["content"].as_str().unwrap();
    assert!(!content.contains("090-1234-5678"), "{content}");
    // tools were translated to the OpenAI shape
    assert_eq!(sent["tools"][0]["type"], "function");
}

#[tokio::test]
async fn messages_leak_gate_is_wrapped_in_an_anthropic_error() {
    let h = start_with_dict(&[("山田太郎", "person")]).await;
    let body = json!({
        "model": "claude-x",
        "max_tokens": 10,
        // stop_sequences is translated but not masked: a known raw value here
        // is exactly what the gate exists for
        "stop_sequences": ["山田太郎"],
        "messages": [{"role": "user", "content": "山田太郎さんの件"}],
    });
    let response = h.post_json("/v1/messages", body).await;
    assert_eq!(response.status(), 400);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(payload["type"], "error");
    assert_eq!(payload["error"]["mask_code"], "mask_leak_blocked");
    assert!(payload["error"].get("mask_values").is_none(), "{payload}");
    let leaks = payload["error"]["mask_leaks"].as_array().unwrap();
    assert_eq!(leaks.len(), 1, "{payload}");
    assert_eq!(leaks[0]["value_sha256_prefix"], json!("6b0e1c8c"));
    assert!(!payload.to_string().contains("山田太郎"), "{payload}");
    assert!(h.upstream.last().is_none(), "request left the process");
}

#[tokio::test]
async fn messages_stream_emits_the_anthropic_event_sequence() {
    let h = start_with_dict(&[("山田太郎", "person")]).await;
    let mut body = messages_body("山田太郎さん");
    body["stream"] = json!(true);
    let response = h.post_json("/v1/messages", body).await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers().get("X-Mask-In").unwrap(), "v1/messages");
    let text = response.text().await.unwrap();
    for event in [
        "message_start",
        "content_block_start",
        "content_block_delta",
        "content_block_stop",
        "message_delta",
        "message_stop",
    ] {
        assert!(text.contains(&format!("event: {event}")), "missing {event}");
    }
    assert!(text.contains("山田太郎"), "{text}");
    let delta: Value = text
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter_map(|data| serde_json::from_str::<Value>(data).ok())
        .find(|value| value["type"] == "content_block_delta")
        .expect("content_block_delta");
    assert_eq!(delta["delta"]["type"], "text_delta");
    assert!(delta["delta"]["text"]
        .as_str()
        .unwrap()
        .contains("山田太郎"));
}

#[tokio::test]
async fn messages_stream_restores_a_token_split_across_chunks() {
    let config = GatewayConfig {
        dictionary_path: Some(common::dict_file(&[("山田太郎", "person")])),
        ..base_config()
    };
    let h = start_with(config, MockKind::SplitInside).await;
    let mut body = messages_body("山田太郎さん");
    body["stream"] = json!(true);
    let response = h.post_json("/v1/messages", body).await;
    assert_eq!(response.status(), 200);
    let text = response.text().await.unwrap();
    assert!(text.contains("山田太郎"), "{text}");
    assert!(!text.contains('⟦'), "{text}");
    let events: Vec<Value> = text
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter_map(|data| serde_json::from_str::<Value>(data).ok())
        .collect();
    let delta = events
        .iter()
        .find(|value| value["type"] == "content_block_delta")
        .expect("content_block_delta");
    assert!(delta["delta"]["text"]
        .as_str()
        .unwrap()
        .contains("山田太郎"));
    let stop = events
        .iter()
        .find(|value| value["type"] == "message_delta")
        .expect("message_delta");
    assert_eq!(stop["delta"]["stop_reason"], "end_turn");
    assert!(text.contains("event: message_stop"), "{text}");
}

#[tokio::test]
async fn messages_gateway_token_via_x_api_key() {
    let config = GatewayConfig {
        gateway_token: "team-secret".to_string(),
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;
    let body = json!({
        "model": "m",
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "hi"}],
    });
    let denied = h.post_json("/v1/messages", body.clone()).await;
    assert_eq!(denied.status(), 401);

    let ok = h
        .client
        .post(h.url("/v1/messages"))
        .header("x-api-key", "team-secret")
        .header("anthropic-version", "2023-06-01")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    // the anthropic key slot and version headers never travel upstream
    let headers = h.upstream.last().unwrap().headers;
    assert!(headers.get("x-api-key").is_none());
    assert!(headers.get("anthropic-version").is_none());
    assert_eq!(headers.get("authorization").unwrap(), "Bearer sk-real");
}

#[tokio::test]
async fn messages_upstream_error_is_an_anthropic_api_error() {
    let h = start_with(common::base_config(), MockKind::Echo).await;
    let body = json!({"model": "m", "max_tokens": 1, "messages": []});
    let response = h.post_json("/v1/messages", body).await;
    assert_eq!(response.status(), 401);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(payload["type"], "error");
    assert_eq!(payload["error"]["type"], "api_error");
}
