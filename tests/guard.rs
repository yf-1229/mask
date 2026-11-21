//! Operator guards: the admin channel belongs to the human at the terminal.
//!
//! `/admin/export` hands out the live mapping table — the one thing mask exists
//! to keep in one place. These tests pin the four refusals that stand between an
//! agent (or a rebinding page) and that table, and the indicator that counts
//! them.

use axum::http::HeaderValue;
use serde_json::json;

mod common;

use common::{start_with, MockKind};
use mask::gateway::config::GatewayConfig;

/// A gateway that requires the operator token, as `mask serve` would leave it.
async fn guarded(token: Option<&str>) -> common::Harness {
    let config = GatewayConfig {
        gateway_token: "client-token".to_string(),
        admin_require_human: true,
        admin_human_token: token.map(str::to_string),
        ..common::base_config()
    };
    start_with(config, MockKind::Echo).await
}

fn export_body() -> serde_json::Value {
    json!({"passphrase": "correct horse battery staple"})
}

#[tokio::test]
async fn export_without_the_operator_token_is_refused() {
    let harness = guarded(Some("operator-token")).await;
    let response = harness
        .post_json_auth("/admin/export", export_body(), "client-token")
        .await;
    assert_eq!(response.status(), 401);
    let body: serde_json::Value = response.json().await.expect("json");
    assert_eq!(body["error"]["code"], "mask_admin_no_human");
}

#[tokio::test]
async fn export_with_a_wrong_operator_token_is_refused() {
    let harness = guarded(Some("operator-token")).await;
    let response = harness
        .client
        .post(harness.url("/admin/export"))
        .bearer_auth("client-token")
        .header("x-mask-admin", "not-the-token")
        .json(&export_body())
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn export_with_the_operator_token_succeeds() {
    let harness = guarded(Some("operator-token")).await;
    let response = harness
        .client
        .post(harness.url("/admin/export"))
        .bearer_auth("client-token")
        .header("x-mask-admin", "operator-token")
        .json(&export_body())
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.expect("json");
    assert!(body["envelope"].is_object(), "{body}");
}

#[tokio::test]
async fn a_gateway_with_no_terminal_closes_the_admin_channel() {
    // `mask serve` without a controlling terminal mints no token at all: the
    // channel refuses even the operator token a client might guess.
    let harness = guarded(None).await;
    let response = harness
        .client
        .post(harness.url("/admin/export"))
        .bearer_auth("client-token")
        .header("x-mask-admin", "anything")
        .json(&export_body())
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 403);
    let body: serde_json::Value = response.json().await.expect("json");
    assert_eq!(body["error"]["code"], "mask_admin_closed");
}

#[tokio::test]
async fn a_rebound_host_name_cannot_address_the_admin_channel() {
    let harness = guarded(Some("operator-token")).await;
    let response = harness
        .client
        .post(harness.url("/admin/export"))
        .bearer_auth("client-token")
        .header("x-mask-admin", "operator-token")
        .header("host", HeaderValue::from_static("evil.example"))
        .json(&export_body())
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 403);
    let body: serde_json::Value = response.json().await.expect("json");
    assert_eq!(body["error"]["code"], "mask_admin_host");
}

#[tokio::test]
async fn the_proxy_entrance_is_not_affected_by_the_admin_gate() {
    // The point of mask is that an agent *can* use the proxy. The guard covers
    // the operator's controls, never the data path.
    let harness = guarded(Some("operator-token")).await;
    let response = harness
        .post_json_auth(
            "/v1/chat/completions",
            json!({"model": "m", "messages": [{"role": "user", "content": "hello"}]}),
            "client-token",
        )
        .await;
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn refusals_are_counted_and_the_posture_names_the_channel() {
    let harness = guarded(Some("operator-token")).await;
    for _ in 0..3 {
        let _ = harness
            .post_json_auth("/admin/export", export_body(), "client-token")
            .await;
    }
    let status: serde_json::Value = harness
        .get_auth("/status", "client-token")
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(status["counts"]["admin_gate_refusals"], 3, "{status}");
    assert_eq!(status["posture"]["admin_channel"], "human");
    assert_eq!(status["posture"]["agent_host_guard"], true);
    // The token exists in this process, and still must not appear anywhere a
    // client can read. This is the assertion that would catch a leak.
    assert!(!status.to_string().contains("operator-token"), "{status}");
}

#[tokio::test]
async fn import_is_gated_on_the_same_operator_token() {
    let harness = guarded(Some("operator-token")).await;
    let envelope = json!({"passphrase": "p", "envelope": {"v": 1, "kdf": {"salt": "s", "opslimit": 1, "memlimit": 8192}, "boxed": "b", "exp": 1}});
    let without = harness
        .post_json_auth("/admin/import", envelope.clone(), "client-token")
        .await;
    assert_eq!(without.status(), 401);
    let with = harness
        .client
        .post(harness.url("/admin/import"))
        .bearer_auth("client-token")
        .header("x-mask-admin", "operator-token")
        .json(&envelope)
        .send()
        .await
        .expect("request");
    // Past the operator gate: the envelope itself is malformed, which is the
    // refusal we expect from a body this guard has nothing to say about.
    assert_ne!(
        with.status(),
        401,
        "the operator token should pass the gate"
    );
}

#[tokio::test]
async fn the_closed_channel_is_visible_in_the_posture() {
    let harness = guarded(None).await;
    let status: serde_json::Value = harness
        .get_auth("/status", "client-token")
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(status["posture"]["admin_channel"], "closed");
}

#[tokio::test]
async fn a_host_that_only_looks_like_loopback_is_refused() {
    let harness = guarded(Some("operator-token")).await;
    for host in ["127.0.0.1.evil.example", "localhost.evil.example"] {
        let response = harness
            .client
            .post(harness.url("/admin/export"))
            .bearer_auth("client-token")
            .header("x-mask-admin", "operator-token")
            .header("host", host)
            .json(&export_body())
            .send()
            .await
            .expect("request");
        assert_eq!(response.status(), 403, "{host} should be refused");
        let body: serde_json::Value = response.json().await.expect("json");
        assert_eq!(body["error"]["code"], "mask_admin_host");
    }
}

#[tokio::test]
async fn a_config_without_a_gateway_token_reports_a_closed_channel() {
    // Without gateway.token the admin gate refuses before the operator token is
    // consulted; the posture must not claim a human channel there.
    let config = GatewayConfig {
        gateway_token: String::new(),
        admin_require_human: true,
        admin_human_token: Some("operator-token".to_string()),
        ..common::base_config()
    };
    let harness = start_with(config, MockKind::Echo).await;
    let status: serde_json::Value = harness.get("/status").await.json().await.expect("json");
    assert_eq!(status["posture"]["admin_channel"], "closed");
}

#[test]
fn the_operator_gate_is_on_by_default() {
    let defaults = GatewayConfig::default();
    assert!(defaults.admin_require_human, "fail closed by default");
    assert!(defaults.agent_host_guard, "fail closed by default");
    assert!(defaults.admin_human_token.is_none());
}

#[tokio::test]
async fn opting_out_reopens_the_admin_channel_for_a_token_only() {
    let config = GatewayConfig {
        gateway_token: "client-token".to_string(),
        admin_require_human: false,
        ..common::base_config()
    };
    let harness = start_with(config, MockKind::Echo).await;
    // No operator token: the client token alone is enough again (the old
    // contract), which is what `admin_require_human = false` opts into.
    let response = harness
        .post_json_auth("/admin/export", export_body(), "client-token")
        .await;
    assert_eq!(response.status(), 200);
    let status: serde_json::Value = harness
        .get_auth("/status", "client-token")
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(status["posture"]["admin_channel"], "off");
}

#[tokio::test]
async fn a_request_without_a_host_header_is_refused() {
    // HTTP/1.1 requires Host. A client that omits it is not a browser and not
    // the operator's curl: fail closed rather than guess.
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let config = GatewayConfig {
        gateway_token: "client-token".to_string(),
        admin_require_human: true,
        admin_human_token: Some("operator-token".to_string()),
        ..common::base_config()
    };
    let app = mask::gateway::create_app(config, Some(reqwest::Client::new()));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/admin/export")
        .header("content-type", "application/json")
        .header("authorization", "Bearer client-token")
        .header("x-mask-admin", "operator-token")
        .body(Body::from(export_body().to_string()))
        .expect("request");
    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), 403);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let payload: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(payload["error"]["code"], "mask_admin_host");
}
