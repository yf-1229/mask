//! Indicator tests: `/status`, `X-Mask-*` headers, posture snapshot.
//!
//! The point of the indicators is reliability visibility, so these pin the
//! contract: counts only (never contents), stable shape, monotonic across
//! request types, and the same PII-free snapshot the website widget reads.

mod common;

use common::{base_config, chat_body, start, start_with, start_with_dict, MockKind};
use mask::gateway::config::GatewayConfig;
use serde_json::{json, Value};

fn config_with(terms: &[(&str, &str)]) -> GatewayConfig {
    GatewayConfig {
        dictionary_path: Some(common::dict_file(terms)),
        ..base_config()
    }
}

#[tokio::test]
async fn status_reports_posture_and_counts() {
    let h = start_with_dict(&[("山田太郎", "person")]).await;
    let response = h
        .post_json("/v1/chat/completions", chat_body("山田太郎さんの件"))
        .await;
    assert_eq!(response.status(), 200);

    let status: Value = h.get("/status").await.json().await.unwrap();
    assert_eq!(status["status"], "ok");
    let posture = &status["posture"];
    assert_eq!(posture["leak_gate"], "block");
    assert_eq!(posture["leak_gate_active"], true);
    assert_eq!(posture["session_scope"], "global");
    assert_eq!(posture["ner"], false);
    assert_eq!(posture["dictionary_terms"], 1);
    assert_eq!(posture["mapping_records"], 1);
    assert_eq!(posture["gateway_token"], false);

    let counts = &status["counts"];
    assert_eq!(counts["requests_total"], 1);
    assert_eq!(counts["entities_masked"], 1);
    assert_eq!(counts["tokens_restored"], 1); // the upstream echoed it back
    assert_eq!(counts["leak_blocks"], 0);
    assert_eq!(counts["tokens_unresolved"], 0);
}

#[tokio::test]
async fn uptime_is_a_number() {
    let h = start(MockKind::Echo).await;
    let status: Value = h.get("/status").await.json().await.unwrap();
    assert!(status["uptime_seconds"].is_number());
}

#[tokio::test]
async fn status_counts_are_counts_only() {
    let h = start_with_dict(&[("山田太郎", "person"), ("090-1234-5678", "phone")]).await;
    let response = h
        .post_json(
            "/v1/chat/completions",
            chat_body("山田太郎と090-1234-5678の件"),
        )
        .await;
    assert_eq!(response.status(), 200);
    let raw = h.get("/status").await.text().await.unwrap();
    assert!(!raw.contains("山田"), "{raw}");
    assert!(!raw.contains("090-"), "{raw}");
    assert!(!raw.contains('⟦'), "{raw}");
}

#[tokio::test]
async fn blocked_requests_show_up_in_counts() {
    let config = GatewayConfig {
        gateway_token: "tok".to_string(),
        dictionary_path: Some(common::dict_file(&[("山田太郎", "person")])),
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;

    // no token -> auth denied
    let response = h
        .post_json("/v1/chat/completions", json!({"messages": []}))
        .await;
    assert_eq!(response.status(), 401);

    // known PII in an unmasked field -> leak block
    let response = h
        .post_json_auth(
            "/v1/chat/completions",
            json!({
                "model": "m",
                "messages": [{"role": "user", "content": "山田太郎さんの件"}],
                "user": "山田太郎",
            }),
            "tok",
        )
        .await;
    assert_eq!(response.status(), 400);

    // non-allowlisted path -> 403
    let response = h
        .post_json_auth("/v1/embeddings", json!({"input": "x"}), "tok")
        .await;
    assert_eq!(response.status(), 403);

    let status: Value = h.get_auth("/status", "tok").await.json().await.unwrap();
    let counts = status["counts"].clone();
    assert_eq!(counts["auth_denied"], 1);
    assert_eq!(counts["leak_blocks"], 1);
    assert_eq!(counts["paths_denied"], 1);
    assert_eq!(counts["requests_blocked"], 3);
}

#[tokio::test]
async fn status_requires_gateway_token_when_set() {
    let config = GatewayConfig {
        gateway_token: "team-secret".to_string(),
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;
    assert_eq!(h.get("/status").await.status(), 401);

    let ok = h.get_auth("/status", "team-secret").await;
    assert_eq!(ok.status(), 200);

    // Anthropic-style header works too
    let ok = h
        .client
        .get(h.url("/status"))
        .header("x-api-key", "team-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
}

#[tokio::test]
async fn status_public_adds_cors() {
    let private = start(MockKind::Echo).await;
    let response = private.get("/status").await;
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());

    let config = GatewayConfig {
        status_public: true,
        ..base_config()
    };
    let public = start_with(config, MockKind::Echo).await;
    let response = public.get("/status").await;
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "*"
    );
}

#[tokio::test]
async fn status_public_skips_token_when_opted_in() {
    let closed = start_with(
        GatewayConfig {
            gateway_token: "team-secret".to_string(),
            status_public: false,
            ..base_config()
        },
        MockKind::Echo,
    )
    .await;
    assert_eq!(closed.get("/status").await.status(), 401);
    assert_eq!(
        closed.get_auth("/status", "team-secret").await.status(),
        200
    );

    let open = start_with(
        GatewayConfig {
            gateway_token: "team-secret".to_string(),
            status_public: true,
            ..base_config()
        },
        MockKind::Echo,
    )
    .await;
    let response = open
        .client
        .get(open.url("/status"))
        .header("Origin", "http://site.test")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "*"
    );
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn chat_response_carries_indicator_headers() {
    let h = start_with_dict(&[("山田太郎", "person")]).await;
    let response = h
        .post_json("/v1/chat/completions", chat_body("山田太郎さんの件"))
        .await;
    assert_eq!(response.status(), 200);
    let headers = response.headers();
    assert_eq!(headers.get("X-Mask").unwrap(), "on");
    assert_eq!(headers.get("X-Mask-In").unwrap(), "v1/chat");
    assert_eq!(headers.get("X-Mask-Leak-Gate").unwrap(), "block");
    assert_eq!(headers.get("X-Mask-Masked").unwrap(), "1");
    assert_eq!(headers.get("X-Mask-Restored").unwrap(), "1");
    assert_eq!(headers.get("X-Mask-Unresolved").unwrap(), "0");
    assert_eq!(headers.get("X-Mask-Fuzzy-Repaired").unwrap(), "0");
    assert_eq!(headers.get("X-Mask-Nonce").unwrap().len(), 12);
}

#[tokio::test]
async fn leak_blocked_response_is_marked() {
    let h = start_with_dict(&[("山田太郎", "person")]).await;
    let response = h
        .post_json(
            "/v1/chat/completions",
            json!({
                "model": "m",
                "messages": [{"role": "user", "content": "山田太郎さんの件"}],
                "user": "山田太郎",
            }),
        )
        .await;
    assert_eq!(response.status(), 400);
    assert_eq!(
        response.headers().get("X-Mask-Leak-Blocked").unwrap(),
        "true"
    );
}

#[tokio::test]
async fn healthz_reports_upstream_and_scope() {
    let h = start(MockKind::Echo).await;
    let body: Value = h.get("/healthz").await.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["session_scope"], "global");
    assert!(body["upstream"].as_str().unwrap().contains("127.0.0.1"));
}

#[tokio::test]
async fn ner_posture_reflects_the_config() {
    let h = start_with(
        GatewayConfig {
            use_ner: true,
            ..base_config()
        },
        MockKind::Echo,
    )
    .await;
    let status: Value = h.get("/status").await.json().await.unwrap();
    assert_eq!(status["posture"]["ner"], true);
}

#[tokio::test]
async fn dictionary_terms_indicator_counts_entries() {
    let h = start_with(
        config_with(&[("山田太郎", "person"), ("○○銀行", "org")]),
        MockKind::Echo,
    )
    .await;
    let status: Value = h.get("/status").await.json().await.unwrap();
    assert_eq!(status["posture"]["dictionary_terms"], 2);
}

#[tokio::test]
async fn operator_can_count_leak_false_positives() {
    let config = GatewayConfig {
        gateway_token: "tok".to_string(),
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;

    // The counter is an operator action: same admin gate as export/import.
    let denied = h.post_json("/admin/leak/false-positive", json!({})).await;
    assert_eq!(denied.status(), 401);

    let ok = h
        .post_json_auth("/admin/leak/false-positive", json!({}), "tok")
        .await;
    assert_eq!(ok.status(), 200);
    let body: Value = ok.json().await.unwrap();
    assert_eq!(body["leak_false_positives"], 1);

    let status: Value = h.get_auth("/status", "tok").await.json().await.unwrap();
    assert_eq!(status["counts"]["leak_false_positives"], 1);
}
