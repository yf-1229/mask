//! Encrypted handoff tests: envelope crypto, table merge policy, admin flow.
//!
//! A handoff carries the mapping table between two gateways so one teammate's
//! masked transcript restores on another's machine. The envelope is the only
//! way the table ever leaves process memory, so its properties are pinned here:
//! authenticated, expiring, single-use, lockout-protected, and never able to
//! rebind a token to a different person.

mod common;

use common::{base_config, chat_body, start_with, MockKind};
use mask::gateway::config::GatewayConfig;
use mask::gateway::sharing::{
    envelope_fingerprint, now_unix, seal, seal_with, unseal, Envelope, KdfParams, SealError,
    UnsealError, DEFAULT_TTL_SECONDS,
};
use mask::replace::{ImportStatus, PseudonymMap};
use mask::types::EntityType;
use serde_json::{json, Value};

const PASS: &str = "team-pass";

fn test_envelope(payload: &Value, passphrase: &str, ttl: i64) -> Envelope {
    mask::install_crypto_provider();
    seal_with(payload, passphrase, ttl, KdfParams::TESTING).expect("seal")
}

fn sample_payload() -> Value {
    json!({
        "v": 1,
        "records": [{"token": "⟦人名17⟧", "value": "山田太郎", "occurrences": 2}],
    })
}

// --- envelope crypto ---------------------------------------------------------

#[test]
fn seal_unseal_roundtrip() {
    let envelope = test_envelope(&sample_payload(), PASS, 60);
    assert_eq!(envelope.v, 1);
    assert_eq!(envelope.kdf.name, "argon2id");
    let opened = unseal(&envelope, PASS).expect("unseal");
    assert_eq!(opened["records"], sample_payload()["records"]);
    // the sealed expiry round-trips
    assert_eq!(opened["exp"], json!(envelope.exp));
}

#[test]
fn wrong_passphrase_is_a_crypto_error() {
    let envelope = test_envelope(&json!({"a": 1}), PASS, 60);
    assert!(matches!(
        unseal(&envelope, "wrong"),
        Err(UnsealError::Crypto)
    ));
}

#[test]
fn tampered_ciphertext_is_a_crypto_error() {
    let mut envelope = test_envelope(&json!({"a": 1}), PASS, 60);
    // flip one base64 character of the ciphertext: same length, other bytes
    let mut chars: Vec<char> = envelope.boxed.chars().collect();
    let index = chars.len() / 2;
    chars[index] = if chars[index] == 'A' { 'B' } else { 'A' };
    envelope.boxed = chars.into_iter().collect();
    assert!(matches!(unseal(&envelope, PASS), Err(UnsealError::Crypto)));
}

#[test]
fn seal_rejects_empty_passphrase_and_bad_ttl() {
    mask::install_crypto_provider();
    assert!(matches!(
        seal_with(&json!({"a": 1}), "", 60, KdfParams::TESTING),
        Err(SealError::EmptyPassphrase)
    ));
    assert!(matches!(
        seal_with(&json!({"a": 1}), PASS, 0, KdfParams::TESTING),
        Err(SealError::InvalidTtl)
    ));
    assert!(matches!(
        seal_with(&json!({"a": 1}), PASS, -5, KdfParams::TESTING),
        Err(SealError::InvalidTtl)
    ));
}

#[test]
fn unseal_rejects_unknown_version() {
    let mut envelope = test_envelope(&json!({"a": 1}), PASS, 60);
    envelope.v = 99;
    match unseal(&envelope, PASS) {
        Err(UnsealError::Malformed(message)) => {
            assert!(message.contains("version"), "{message}")
        }
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn rewound_clear_expiry_fast_fails() {
    let mut envelope = test_envelope(&json!({"v": 1, "records": []}), PASS, 60);
    envelope.exp = now_unix() - 1;
    assert!(matches!(unseal(&envelope, PASS), Err(UnsealError::Expired)));
}

#[test]
fn expired_envelope_is_refused() {
    let envelope = test_envelope(&sample_payload(), PASS, 1);
    // `exp` is whole seconds and `unseal` refuses only once it has *passed*,
    // so one second plus a margin can land on `now == exp`. Two seconds
    // guarantees `now > exp` on any clock granularity.
    std::thread::sleep(std::time::Duration::from_millis(2200));
    assert!(matches!(unseal(&envelope, PASS), Err(UnsealError::Expired)));
}

#[test]
fn fingerprint_is_stable_for_copies_and_unique_per_envelope() {
    let first = test_envelope(&json!({"a": 1}), PASS, 60);
    let copy: Envelope = serde_json::from_value(serde_json::to_value(&first).unwrap()).unwrap();
    assert_eq!(envelope_fingerprint(&first), envelope_fingerprint(&copy));
    let second = test_envelope(&json!({"a": 1}), PASS, 60);
    assert_ne!(envelope_fingerprint(&first), envelope_fingerprint(&second));
}

#[test]
fn kdf_cost_is_moderate_by_default() {
    mask::install_crypto_provider();
    let envelope = seal(&json!({"a": 1}), PASS, 60).expect("seal");
    assert_eq!(envelope.kdf.opslimit, KdfParams::MODERATE.opslimit);
    assert_eq!(envelope.kdf.memlimit, KdfParams::MODERATE.memlimit);
    assert_eq!(DEFAULT_TTL_SECONDS, 3600);
    let defaults = GatewayConfig::default().handoff_kdf();
    assert_eq!(defaults.opslimit, KdfParams::MODERATE.opslimit);
    assert_eq!(defaults.memlimit, KdfParams::MODERATE.memlimit);
    assert_eq!(GatewayConfig::default().handoff_ttl_seconds, 3600);
    assert_eq!(GatewayConfig::default().handoff_max_attempts, 3);
    assert!(!GatewayConfig::default().admin_allow_remote);
}

// --- table merge policy ------------------------------------------------------

#[test]
fn export_import_roundtrip_preserves_tokens() {
    let mut src = PseudonymMap::new();
    let person = src.assign(EntityType::Person, "山田太郎").unwrap();
    let email = src.assign(EntityType::Email, "taro@example.com").unwrap();
    let mut dst = PseudonymMap::new();
    for record in src.export_records() {
        assert_eq!(
            dst.import_record(&record.token, &record.value, record.occurrences),
            ImportStatus::Imported
        );
    }
    assert_eq!(dst.restore_value(&person.token), Some("山田太郎"));
    assert_eq!(dst.restore_value(&email.token), Some("taro@example.com"));
    // the same value maps to the same token on the receiving side
    assert_eq!(
        dst.assign(EntityType::Person, "山田太郎").unwrap().token,
        person.token
    );
}

#[test]
fn import_never_rebinds_a_token() {
    let mut map = PseudonymMap::new();
    let record = map.assign(EntityType::Person, "山田太郎").unwrap();
    assert_eq!(
        map.import_record(&record.token, "別の人物", 1),
        ImportStatus::Conflict
    );
    assert_eq!(map.restore_value(&record.token), Some("山田太郎"));
}

#[test]
fn import_of_the_same_value_is_already() {
    let mut map = PseudonymMap::new();
    let record = map.assign(EntityType::Person, "山田太郎").unwrap();
    assert_eq!(
        map.import_record(&record.token, "山田太郎", 1),
        ImportStatus::Already
    );
}

#[test]
fn import_rejects_malformed_records() {
    let mut map = PseudonymMap::new();
    assert_eq!(map.import_record("人名17", "x", 1), ImportStatus::Invalid);
    assert_eq!(map.import_record("⟦人名17⟧", "", 1), ImportStatus::Invalid);
    assert_eq!(
        map.import_record("⟦謎label17⟧", "x", 1),
        ImportStatus::Invalid
    );
}

#[test]
fn imported_values_feed_the_leak_gate() {
    let mut map = PseudonymMap::new();
    assert_eq!(
        map.import_record("⟦人名17⟧", "山田太郎", 1),
        ImportStatus::Imported
    );
    assert!(map.raw_values().contains(&"山田太郎".to_string()));
}

#[test]
fn sealed_records_roundtrip_through_the_envelope() {
    let mut src = PseudonymMap::new();
    src.assign(EntityType::Person, "山田太郎").unwrap();
    src.assign(EntityType::Address, "港区赤坂一丁目2番3号")
        .unwrap();
    let payload = json!({"v": 1, "records": src.export_records()});
    let envelope = test_envelope(&payload, PASS, 60);
    let opened = unseal(&envelope, PASS).expect("unseal");
    let mut dst = PseudonymMap::new();
    for record in opened["records"].as_array().unwrap() {
        assert_eq!(
            dst.import_record(
                record["token"].as_str().unwrap(),
                record["value"].as_str().unwrap(),
                1
            ),
            ImportStatus::Imported
        );
    }
    assert_eq!(dst.len(), 2);
}

// --- gateway admin flow ------------------------------------------------------

/// Export the source gateway's table and return the envelope.
async fn export_envelope(h: &common::Harness, passphrase: &str) -> Value {
    let body: Value = h
        .post_json_auth(
            "/admin/export",
            json!({"passphrase": passphrase}),
            "team-secret",
        )
        .await
        .json()
        .await
        .unwrap();
    body["envelope"].clone()
}

fn admin_config(terms: &[(&str, &str)]) -> GatewayConfig {
    GatewayConfig {
        gateway_token: "team-secret".to_string(),
        dictionary_path: Some(common::dict_file(terms)),
        // cheap KDF so the suite does not spend minutes in argon2; the
        // production default is asserted separately below
        handoff_kdf_opslimit: KdfParams::TESTING.opslimit,
        handoff_kdf_memlimit: KdfParams::TESTING.memlimit,
        ..base_config()
    }
}

#[tokio::test]
async fn export_import_handoff_between_gateways() {
    let src = start_with(admin_config(&[("山田太郎", "person")]), MockKind::Echo).await;
    let response = src
        .post_json_auth(
            "/v1/chat/completions",
            chat_body("山田太郎さんの件"),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 200);
    let src_masked = src.upstream.sent()["messages"][0]["content"]
        .as_str()
        .unwrap()
        .to_string();

    let export: Value = src
        .post_json_auth(
            "/admin/export",
            json!({"passphrase": "handoff"}),
            "team-secret",
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(export["count"], 1);
    let envelope = export["envelope"].clone();

    let dst = start_with(admin_config(&[("山田太郎", "person")]), MockKind::Echo).await;
    let import: Value = dst
        .post_json_auth(
            "/admin/import",
            json!({"passphrase": "handoff", "envelope": envelope}),
            "team-secret",
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        import["result"],
        json!({"imported": 1, "already": 0, "conflict": 0, "invalid": 0})
    );

    // the same person gets the same token on both sides
    let response = dst
        .post_json_auth(
            "/v1/chat/completions",
            chat_body("山田太郎さんの件"),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 200);
    let dst_masked = dst.upstream.sent()["messages"][0]["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(dst_masked, src_masked);
    // and the transcript restores on the receiving gateway
    let body: Value = response.json().await.unwrap();
    assert!(common::text_of(&body).contains("山田太郎"));
}

#[tokio::test]
async fn admin_is_disabled_without_a_gateway_token() {
    let h = start_with(base_config(), MockKind::Echo).await;
    let response = h
        .post_json("/admin/export", json!({"passphrase": "x"}))
        .await;
    assert_eq!(response.status(), 403);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "mask_admin_disabled");
}

#[tokio::test]
async fn admin_requires_the_token() {
    let h = start_with(admin_config(&[]), MockKind::Echo).await;
    let response = h
        .post_json("/admin/export", json!({"passphrase": "x"}))
        .await;
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn export_requires_a_passphrase() {
    let h = start_with(admin_config(&[]), MockKind::Echo).await;
    let response = h
        .post_json_auth("/admin/export", json!({}), "team-secret")
        .await;
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn export_carries_an_expiry() {
    let h = start_with(admin_config(&[]), MockKind::Echo).await;
    let body: Value = h
        .post_json_auth(
            "/admin/export",
            json!({"passphrase": "p", "ttl_seconds": 60}),
            "team-secret",
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(body["envelope"]["exp"], body["expires_at"]);
    assert!(body["expires_at"].as_i64().unwrap() > now_unix());
}

#[tokio::test]
async fn export_rejects_a_bad_ttl() {
    let h = start_with(admin_config(&[]), MockKind::Echo).await;
    let response = h
        .post_json_auth(
            "/admin/export",
            json!({"passphrase": "p", "ttl_seconds": 0}),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn import_with_wrong_passphrase_is_rejected() {
    let src = start_with(admin_config(&[("山田太郎", "person")]), MockKind::Echo).await;
    let response = src
        .post_json_auth(
            "/v1/chat/completions",
            chat_body("山田太郎さんの件"),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 200);
    let envelope = export_envelope(&src, "right").await;

    let dst = start_with(admin_config(&[]), MockKind::Echo).await;
    let response = dst
        .post_json_auth(
            "/admin/import",
            json!({"passphrase": "wrong", "envelope": envelope}),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 400);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "mask_unseal_failed");
    assert_eq!(payload["error"]["attempts_remaining"], 2);
}

#[tokio::test]
async fn lockout_after_failed_attempts() {
    let src = start_with(admin_config(&[("山田太郎", "person")]), MockKind::Echo).await;
    let response = src
        .post_json_auth(
            "/v1/chat/completions",
            chat_body("山田太郎さんの件"),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 200);
    let envelope = export_envelope(&src, "right").await;

    let dst = start_with(admin_config(&[]), MockKind::Echo).await;
    for expected_remaining in [2, 1] {
        let response = dst
            .post_json_auth(
                "/admin/import",
                json!({"passphrase": "nope", "envelope": envelope}),
                "team-secret",
            )
            .await;
        assert_eq!(response.status(), 400);
        let payload: Value = response.json().await.unwrap();
        assert_eq!(payload["error"]["attempts_remaining"], expected_remaining);
    }
    let response = dst
        .post_json_auth(
            "/admin/import",
            json!({"passphrase": "nope", "envelope": envelope}),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 423);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "mask_envelope_locked");

    // the correct passphrase is impossible now too
    let response = dst
        .post_json_auth(
            "/admin/import",
            json!({"passphrase": "right", "envelope": envelope}),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 423);
}

#[tokio::test]
async fn single_attempt_policy() {
    let src = start_with(
        GatewayConfig {
            handoff_max_attempts: 1,
            ..admin_config(&[("山田太郎", "person")])
        },
        MockKind::Echo,
    )
    .await;
    let response = src
        .post_json_auth(
            "/v1/chat/completions",
            chat_body("山田太郎さんの件"),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 200);
    let envelope = export_envelope(&src, "p").await;

    let dst = start_with(
        GatewayConfig {
            handoff_max_attempts: 1,
            ..admin_config(&[])
        },
        MockKind::Echo,
    )
    .await;
    let response = dst
        .post_json_auth(
            "/admin/import",
            json!({"passphrase": "wrong", "envelope": envelope}),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 423);
}

#[tokio::test]
async fn lockout_is_per_envelope() {
    let src = start_with(admin_config(&[("山田太郎", "person")]), MockKind::Echo).await;
    let response = src
        .post_json_auth(
            "/v1/chat/completions",
            chat_body("山田太郎さんの件"),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 200);
    let envelope_a = export_envelope(&src, "p").await;
    let envelope_b = export_envelope(&src, "p").await;
    assert_ne!(envelope_a, envelope_b);

    let dst = start_with(admin_config(&[]), MockKind::Echo).await;
    for _ in 0..3 {
        let response = dst
            .post_json_auth(
                "/admin/import",
                json!({"passphrase": "wrong", "envelope": envelope_a}),
                "team-secret",
            )
            .await;
        assert!(response.status() == 400 || response.status() == 423);
    }
    let response = dst
        .post_json_auth(
            "/admin/import",
            json!({"passphrase": "p", "envelope": envelope_b}),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 200);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(payload["result"]["imported"], 1);
}

#[tokio::test]
async fn successful_import_consumes_the_envelope() {
    let src = start_with(admin_config(&[("山田太郎", "person")]), MockKind::Echo).await;
    let response = src
        .post_json_auth(
            "/v1/chat/completions",
            chat_body("山田太郎さんの件"),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 200);
    let envelope = export_envelope(&src, "p").await;

    let dst = start_with(admin_config(&[]), MockKind::Echo).await;
    let response = dst
        .post_json_auth(
            "/admin/import",
            json!({"passphrase": "p", "envelope": envelope}),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 200);

    // single use: even the correct passphrase cannot import it again
    let response = dst
        .post_json_auth(
            "/admin/import",
            json!({"passphrase": "p", "envelope": envelope}),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 410);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "mask_envelope_consumed");
}

#[tokio::test]
async fn expired_envelope_is_gone() {
    let h = start_with(admin_config(&[]), MockKind::Echo).await;
    let envelope = test_envelope(&json!({"v": 1, "records": []}), "p", 1);
    // `exp` is whole seconds and `unseal` refuses only once it has *passed*,
    // so one second plus a margin can land on `now == exp`. Two seconds
    // guarantees `now > exp` on any clock granularity.
    std::thread::sleep(std::time::Duration::from_millis(2200));
    let response = h
        .post_json_auth(
            "/admin/import",
            json!({"passphrase": "p", "envelope": envelope}),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 410);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "mask_envelope_expired");
}

#[tokio::test]
async fn malformed_envelope_is_rejected() {
    let h = start_with(admin_config(&[]), MockKind::Echo).await;
    let response = h
        .post_json_auth(
            "/admin/import",
            json!({"passphrase": "p", "envelope": {"v": 1}}),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 400);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "mask_bad_request");
}

#[tokio::test]
async fn admin_rejects_request_scope() {
    let h = start_with(
        GatewayConfig {
            session_scope: mask::gateway::config::SessionScope::Request,
            ..admin_config(&[])
        },
        MockKind::Echo,
    )
    .await;
    let response = h
        .post_json_auth("/admin/export", json!({"passphrase": "x"}), "team-secret")
        .await;
    assert_eq!(response.status(), 409);
    let payload: Value = response.json().await.unwrap();
    assert_eq!(payload["error"]["code"], "mask_scope_unsupported");
}

#[tokio::test]
async fn admin_refuses_non_loopback_clients() {
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    mask::install_crypto_provider();
    // no ConnectInfo extension on the request == no trusted peer == not loopback
    let app = mask::gateway::create_app(admin_config(&[]), Some(reqwest::Client::new()));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/admin/export")
        // A loopback name, so this test exercises the peer check rather than
        // the Host check (which refuses a missing Host of its own accord).
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("authorization", "Bearer team-secret")
        .body(Body::from(json!({"passphrase": "p"}).to_string()))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), 403);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let payload: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(payload["error"]["code"], "mask_admin_local_only");
}

#[tokio::test]
async fn handoff_counters_are_recorded() {
    let src = start_with(admin_config(&[("山田太郎", "person")]), MockKind::Echo).await;
    let response = src
        .post_json_auth(
            "/v1/chat/completions",
            chat_body("山田太郎さんの件"),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 200);
    let envelope = export_envelope(&src, "p").await;
    let dst = start_with(admin_config(&[]), MockKind::Echo).await;
    let response = dst
        .post_json_auth(
            "/admin/import",
            json!({"passphrase": "p", "envelope": envelope}),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 200);

    let src_status: Value = src
        .get_auth("/status", "team-secret")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(src_status["counts"]["handoff_exports"], 1);
    let dst_status: Value = dst
        .get_auth("/status", "team-secret")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(dst_status["counts"]["handoff_imports"], 1);
}
