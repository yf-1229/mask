//! Dictionary lifecycle tests: the file format, the additive reload rule, the
//! live pickup a running gateway does, and the `mask dict` commands.
//!
//! Two properties are pinned here:
//!
//! - a file edit can add coverage to a running process, never remove it;
//! - nothing in the reporting surfaces (status, admin response, `dict check`)
//!   carries a term value — counts and line numbers only.

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use common::{base_config, chat_body, dict_file, start_with, MockKind};
use mask::cli::render_dict_check;
use mask::detect::dictionary::{append_or_update, AddOutcome, ParseReport, UserDictionary};
use mask::gateway::config::GatewayConfig;
use mask::types::EntityType;
use serde_json::{json, Value};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mask"))
}

fn isolated_config() -> std::path::PathBuf {
    common::temp_file("empty.toml", "")
}

// --- file format -------------------------------------------------------------

#[test]
fn parse_report_names_skipped_lines_without_values() {
    let (dictionary, report) =
        UserDictionary::parse_report("# header\n\n山田太郎\tperson\n謎\tunknown\n壊れた\n");
    assert_eq!(dictionary.size(), 1);
    assert_eq!(report.terms, 1);
    assert_eq!(report.skipped, 2);
    assert_eq!(report.skipped_lines, vec![4, 5]);
}

#[test]
fn parse_accepts_crlf_and_ignores_comments() {
    let dictionary = UserDictionary::parse("# team\r\n山田太郎\tperson\r\n");
    assert_eq!(dictionary.size(), 1);
    assert_eq!(dictionary.get("山田太郎"), Some(EntityType::Person));
}

// --- additive reload ---------------------------------------------------------

#[test]
fn merge_adds_and_retypes_but_never_removes() {
    let mut live = UserDictionary::from_terms([
        ("山田太郎".to_string(), EntityType::Person),
        ("ACME".to_string(), EntityType::Org),
    ]);
    let newer = UserDictionary::from_terms([
        ("山田太郎".to_string(), EntityType::Person),
        ("鈴木一郎".to_string(), EntityType::Person),
        ("ACME".to_string(), EntityType::Location),
    ]);
    let report = live.merge_additive(&newer);
    assert_eq!(report.added, 1);
    assert_eq!(report.updated, 1);
    assert_eq!(report.kept, 0);
    assert_eq!(report.terms, 3);
    assert_eq!(live.get("ACME"), Some(EntityType::Location));
    assert!(report.changed());

    // A later file that dropped every term removes nothing from the process.
    let report = live.merge_additive(&UserDictionary::new());
    assert!(!report.changed());
    assert_eq!(report.kept, 3);
    assert_eq!(report.terms, 3);
    assert_eq!(live.get("山田太郎"), Some(EntityType::Person));
}

#[test]
fn merge_is_idempotent() {
    let mut live = UserDictionary::new();
    let file = UserDictionary::from_terms([("山田太郎".to_string(), EntityType::Person)]);
    assert_eq!(live.merge_additive(&file).added, 1);
    let again = live.merge_additive(&file);
    assert!(!again.changed());
    assert_eq!(again.terms, 1);
}

// --- writing the file --------------------------------------------------------

#[test]
fn append_or_update_preserves_layout_and_line_endings() {
    let path = common::temp_file("dict-add.tsv", "# team names\r\n山田太郎\tperson\r\n");
    assert_eq!(
        append_or_update(&path, "鈴木一郎", EntityType::Person).unwrap(),
        AddOutcome::Added
    );
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("# team names"), "{text:?}");
    assert!(text.contains("山田太郎\tperson"), "{text:?}");
    assert!(text.contains("鈴木一郎\tperson"), "{text:?}");
    assert!(
        text.contains("\r\n") && !text.replace("\r\n", "").contains('\n'),
        "CRLF file stays CRLF: {text:?}"
    );

    assert_eq!(
        append_or_update(&path, "山田太郎", EntityType::Org).unwrap(),
        AddOutcome::Updated {
            from: Some(EntityType::Person)
        }
    );
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("山田太郎\torg"), "{text:?}");
    assert!(!text.contains("山田太郎\tperson"), "{text:?}");

    assert_eq!(
        append_or_update(&path, "山田太郎", EntityType::Org).unwrap(),
        AddOutcome::Unchanged
    );
    // parsing the rewritten file agrees with what was written
    assert_eq!(
        UserDictionary::load(&path).unwrap().get("山田太郎"),
        Some(EntityType::Org)
    );
}

#[test]
fn a_spreadsheet_byte_order_mark_is_not_part_of_the_term() {
    let path = common::temp_file("dict-bom.tsv", "\u{feff}山田太郎\tperson\n");
    let dictionary = UserDictionary::load(&path).unwrap();
    assert_eq!(dictionary.get("山田太郎"), Some(EntityType::Person));
    assert_eq!(
        append_or_update(&path, "山田太郎", EntityType::Person).unwrap(),
        AddOutcome::Unchanged
    );
    assert_eq!(
        append_or_update(&path, "鈴木一郎", EntityType::Person).unwrap(),
        AddOutcome::Added
    );
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.starts_with('\u{feff}'), "BOM preserved: {text:?}");
    assert!(text.contains("鈴木一郎\tperson"), "{text:?}");
}

#[test]
fn append_or_update_refuses_layout_breakers() {
    let path = common::temp_file("dict-bad.tsv", "");
    for term in ["", "  ", "a\tb", "a\nb", "#comment"] {
        let error = append_or_update(&path, term, EntityType::Person).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{term:?}");
    }
    assert_eq!(fs::read_to_string(&path).unwrap(), "");
}

#[test]
fn append_or_update_creates_a_missing_file() {
    let mut path = std::env::temp_dir();
    path.push(format!("mask-test-missing-{}.tsv", std::process::id()));
    let _ = fs::remove_file(&path);
    assert_eq!(
        append_or_update(&path, "山田太郎", EntityType::Person).unwrap(),
        AddOutcome::Added
    );
    assert!(fs::read_to_string(&path)
        .unwrap()
        .contains("山田太郎\tperson"));
    let _ = fs::remove_file(&path);
}

// --- the running gateway -----------------------------------------------------

#[tokio::test]
async fn additions_reach_a_running_gateway_without_a_restart() {
    let path = dict_file(&[("山田太郎", "person")]);
    let config = GatewayConfig {
        dictionary_path: Some(path.clone()),
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;

    let response = h
        .post_json(
            "/v1/chat/completions",
            chat_body("山田太郎と鈴木一郎の件をお願いします"),
        )
        .await;
    assert_eq!(response.status(), 200);
    let first = h.upstream.sent()["messages"][0]["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(first.contains('⟦'), "{first}");
    assert!(
        first.contains("鈴木一郎"),
        "precondition: only the dictionary term is masked: {first}"
    );

    // The operator registers the missed name; no restart, no lost mapping.
    assert_eq!(
        append_or_update(&path, "鈴木一郎", EntityType::Person).unwrap(),
        AddOutcome::Added
    );
    let response = h
        .post_json(
            "/v1/chat/completions",
            chat_body("山田太郎と鈴木一郎の件をお願いします"),
        )
        .await;
    assert_eq!(response.status(), 200);
    let second = h.upstream.sent()["messages"][0]["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        !second.contains("鈴木一郎"),
        "a live addition did not reach the session: {second}"
    );

    let status: Value = h.get("/status").await.json().await.unwrap();
    assert_eq!(status["posture"]["dictionary_terms"], 2);
    assert_eq!(status["counts"]["dictionary_reloads"], 1);
    // the snapshot stays value-free
    let snapshot = status.to_string();
    assert!(!snapshot.contains("山田太郎"), "{snapshot}");
    assert!(!snapshot.contains("鈴木一郎"), "{snapshot}");
}

#[tokio::test]
async fn deleting_the_file_does_not_disable_detection() {
    let path = dict_file(&[("山田太郎", "person")]);
    let config = GatewayConfig {
        dictionary_path: Some(path.clone()),
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;

    // Exercise the file once so the watch has a stamp.
    let _ = h
        .post_json("/v1/chat/completions", chat_body("山田太郎の件"))
        .await;

    fs::remove_file(&path).unwrap();
    let response = h
        .post_json("/v1/chat/completions", chat_body("山田太郎の件"))
        .await;
    assert_eq!(response.status(), 200);
    let sent = h.upstream.sent()["messages"][0]["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        !sent.contains("山田太郎"),
        "removing the file must not unmask: {sent}"
    );
}

// --- admin reload ------------------------------------------------------------

#[tokio::test]
async fn admin_reload_reports_counts_only_and_keeps_removed_terms() {
    let path = dict_file(&[("山田太郎", "person"), ("ACME", "org")]);
    let config = GatewayConfig {
        gateway_token: "team-secret".to_string(),
        dictionary_path: Some(path.clone()),
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;

    // Rewrite the file: one addition, one removal, one type change.
    fs::write(&path, "ACME\tlocation\n鈴木一郎\tperson\n").unwrap();
    let response = h
        .post_json_auth("/admin/dictionary/reload", json!({}), "team-secret")
        .await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["added"], 1);
    assert_eq!(body["updated"], 1);
    assert_eq!(body["kept"], 1);
    assert_eq!(body["terms"], 3);
    let raw = body.to_string();
    assert!(
        !raw.contains("山田太郎") && !raw.contains("鈴木一郎"),
        "{raw}"
    );

    // The old name is still masked: reloads cannot reduce coverage.
    let response = h
        .post_json_auth(
            "/v1/chat/completions",
            chat_body("山田太郎と鈴木一郎の件"),
            "team-secret",
        )
        .await;
    assert_eq!(response.status(), 200);
    let sent = h.upstream.sent()["messages"][0]["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!sent.contains("山田太郎"), "{sent}");
    assert!(!sent.contains("鈴木一郎"), "{sent}");
}

#[tokio::test]
async fn admin_reload_needs_the_gateway_token_and_a_configured_file() {
    let h = start_with(base_config(), MockKind::Echo).await;
    let response = h.post_json("/admin/dictionary/reload", json!({})).await;
    assert_eq!(response.status(), 403);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "mask_admin_disabled");

    let config = GatewayConfig {
        gateway_token: "team-secret".to_string(),
        ..base_config()
    };
    let h = start_with(config, MockKind::Echo).await;
    let response = h
        .post_json_auth("/admin/dictionary/reload", json!({}), "team-secret")
        .await;
    assert_eq!(response.status(), 409);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "mask_no_dictionary");
}

// --- `mask dict` -------------------------------------------------------------

#[test]
fn cli_dict_add_list_and_check_roundtrip() {
    let path = common::temp_file("cli-dict.tsv", "山田太郎\tperson\n");
    let config = isolated_config();
    let config = config.to_str().unwrap();

    let output = binary()
        .args([
            "--no-color",
            "--config",
            config,
            "dict",
            "add",
            "鈴木一郎",
            "--type",
            "person",
            "--file",
        ])
        .arg(&path)
        .output()
        .expect("cannot run mask");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("added person"), "{stdout}");
    assert!(stdout.contains("2 terms"), "{stdout}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no [mask].dictionary"),
        "the command says how to wire the file up"
    );
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("山田太郎\tperson"), "{text}");
    assert!(text.contains("鈴木一郎\tperson"), "{text}");

    let output = binary()
        .args(["--no-color", "--config", config, "dict", "list", "--file"])
        .arg(&path)
        .output()
        .expect("cannot run mask");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("山田太郎\tperson"), "{stdout}");
    assert!(stdout.contains("鈴木一郎\tperson"), "{stdout}");

    let output = binary()
        .args(["--no-color", "--config", config, "dict", "check", "--file"])
        .arg(&path)
        .output()
        .expect("cannot run mask");
    assert_eq!(output.status.code(), Some(0));

    fs::write(&path, "山田太郎\tperson\n謎\tunknown\n").unwrap();
    let output = binary()
        .args(["--no-color", "--config", config, "dict", "check", "--file"])
        .arg(&path)
        .output()
        .expect("cannot run mask");
    assert_eq!(
        output.status.code(),
        Some(1),
        "a skipped line must fail the check"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("line 2"), "{stdout}");
    assert!(
        !stdout.contains("謎"),
        "the report must not carry values: {stdout}"
    );
}

#[test]
fn cli_dict_add_refuses_an_unknown_type() {
    let path = common::temp_file("cli-dict-type.tsv", "");
    let config = isolated_config();
    let output = binary()
        .args([
            "--no-color",
            "--config",
            config.to_str().unwrap(),
            "dict",
            "add",
            "山田太郎",
            "--type",
            "persona",
            "--file",
        ])
        .arg(&path)
        .output()
        .expect("cannot run mask");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read_to_string(&path).unwrap(), "");
}

#[test]
fn render_dict_check_keeps_values_out() {
    let report = ParseReport {
        terms: 2,
        skipped: 1,
        skipped_lines: vec![7],
    };
    let text = render_dict_check(Path::new("dictionary.tsv"), &report, false);
    assert!(text.contains("2 terms"), "{text}");
    assert!(text.contains("skipped lines   1"), "{text}");
    assert!(text.contains("line 7"), "{text}");
    assert!(!text.contains('\u{1b}'), "{text}");
}
