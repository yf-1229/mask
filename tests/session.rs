//! `mask session`: what the live session masked, and who may read it.
//!
//! The endpoint holds raw values, so these tests pin the two boundaries that
//! make it safe: the operator gate (403 without the terminal token, 403 from a
//! non-loopback client even when remote admin is allowed), values only on an
//! explicit `?values=true`, and no raw value in `tracing`.

mod common;

use std::sync::{Arc, LazyLock, Mutex};

use axum::body::Body;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use common::{Harness, MockKind};
use mask::gateway::config::GatewayConfig;

fn config() -> GatewayConfig {
    GatewayConfig {
        gateway_token: "client-token".to_string(),
        admin_require_human: true,
        admin_human_token: Some("operator-token".to_string()),
        dictionary_path: Some(common::dict_file(&[("山田太郎", "person")])),
        ..common::base_config()
    }
}

async fn populate(harness: &Harness) {
    let response = harness
        .post_json_auth(
            "/v1/chat/completions",
            json!({
                "model": "m",
                "messages": [{"role": "user", "content": "山田太郎さんに連絡してください"}],
            }),
            "client-token",
        )
        .await;
    assert_eq!(response.status(), 200);
}

async fn session(harness: &Harness, query: &str, admin_token: Option<&str>) -> reqwest::Response {
    let mut request = harness
        .client
        .get(harness.url(&format!("/admin/session{query}")))
        .bearer_auth("client-token");
    if let Some(token) = admin_token {
        request = request.header("x-mask-admin", token);
    }
    request.send().await.expect("request")
}

#[tokio::test]
async fn session_lists_tokens_counts_and_pool_without_values() {
    let harness = common::start_with(config(), MockKind::Echo).await;
    populate(&harness).await;

    let response = session(&harness, "", Some("operator-token")).await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.expect("json");
    assert_eq!(body["session_scope"], "global");
    assert_eq!(body["records"], 1);
    assert_eq!(body["capacity"], 256);
    assert_eq!(body["remaining"], 255);
    assert_eq!(body["total_occurrences"], 1);
    let entry = &body["entries"][0];
    assert_eq!(entry["kind"], "person");
    assert!(
        entry["token"].as_str().unwrap().starts_with("⟦人名"),
        "{body}"
    );
    assert_eq!(entry["occurrences"], 1);
    assert_eq!(entry["value_sha256_prefix"].as_str().unwrap().len(), 8);
    assert!(entry.get("value").is_none(), "{body}");
    assert!(!body.to_string().contains("山田太郎"), "{body}");

    // /status stays a counts-only snapshot: no values, no entries.
    let status: Value = harness
        .get_auth("/status", "client-token")
        .await
        .json()
        .await
        .expect("json");
    assert_eq!(status["posture"]["mapping_records"], 1);
    assert!(!status.to_string().contains("山田太郎"), "{status}");
    assert!(status.get("entries").is_none(), "{status}");
}

#[tokio::test]
async fn values_are_returned_only_on_explicit_opt_in() {
    let harness = common::start_with(config(), MockKind::Echo).await;
    populate(&harness).await;

    let response = session(&harness, "?values=true", Some("operator-token")).await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.expect("json");
    assert_eq!(body["entries"][0]["value"], "山田太郎");
}

#[tokio::test]
async fn the_view_is_refused_without_the_operator_token() {
    let harness = common::start_with(config(), MockKind::Echo).await;
    let response = session(&harness, "", None).await;
    assert_eq!(response.status(), 403);
    let body: Value = response.json().await.expect("json");
    assert_eq!(body["error"]["code"], "mask_admin_no_human");
}

#[tokio::test]
async fn a_non_loopback_client_is_refused_even_when_remote_admin_is_allowed() {
    // served without ConnectInfo: the handler must treat that as "not loopback"
    // and refuse before the admin gate's `admin_allow_remote` could say yes.
    let config = GatewayConfig {
        gateway_token: "client-token".to_string(),
        admin_require_human: false,
        admin_allow_remote: true,
        ..common::base_config()
    };
    let app = mask::gateway::create_app(config, Some(reqwest::Client::new()));
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/admin/session")
        .header("host", "localhost")
        .header("authorization", "Bearer client-token")
        .body(Body::empty())
        .expect("request");
    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), 403);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(body["error"]["code"], "mask_session_local_only");
}

// --- tracing ----------------------------------------------------------------

struct CaptureLayer(Arc<Mutex<String>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                let _ = write!(self.0, "{}={value:?} ", field.name());
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                use std::fmt::Write;
                let _ = write!(self.0, "{}={value} ", field.name());
            }
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        let mut log = self.0.lock().unwrap();
        log.push_str(&fields.0);
        log.push('\n');
    }
}

fn capture_logs() -> Arc<Mutex<String>> {
    static LOGS: LazyLock<Arc<Mutex<String>>> = LazyLock::new(|| {
        use tracing_subscriber::layer::SubscriberExt;
        let logs = Arc::new(Mutex::new(String::new()));
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::INFO)
            .with(CaptureLayer(logs.clone()));
        tracing::subscriber::set_global_default(subscriber).expect("install log capture");
        logs
    });
    LOGS.clone()
}

#[tokio::test]
async fn the_session_view_logs_counts_but_never_values() {
    let logs = capture_logs();
    logs.lock().unwrap().clear();

    let harness = common::start_with(config(), MockKind::Echo).await;
    populate(&harness).await;
    let response = session(&harness, "?values=true", Some("operator-token")).await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.expect("json");
    assert_eq!(body["entries"][0]["value"], "山田太郎");

    let captured = logs.lock().unwrap().clone();
    assert!(
        captured.contains("admin session snapshot"),
        "the handler's log line was not captured: {captured}"
    );
    assert!(
        !captured.contains("山田太郎"),
        "a raw value reached tracing: {captured}"
    );
}
