//! CLI tests: pure rendering plus the real binary.
//!
//! `render_status` is the same function the website widget contract relies on,
//! and `mask check` must work with no network at all (detection only).

mod common;

use std::process::Command;

use mask::cli::{render_check, render_status};
use mask::detect::detect;
use mask::detect::dictionary::UserDictionary;
use mask::types::EntityType;
use serde_json::json;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mask"))
}

#[test]
fn render_status_panel_lights() {
    let snapshot = json!({
        "status": "ok",
        "uptime_seconds": 42.0,
        "posture": {
            "leak_gate": "block",
            "leak_gate_active": true,
            "session_scope": "global",
            "ner": true,
            "dictionary_terms": 3,
            "mapping_records": 7,
            "gateway_token": true,
        },
        "counts": {
            "requests_total": 12,
            "entities_masked": 34,
            "tokens_restored": 30,
            "leak_blocks": 1,
            "paths_denied": 2,
            "auth_denied": 0,
            "tokens_unresolved": 0,
        },
    });
    let text = render_status(&snapshot, false);
    assert!(
        text.contains("leak gate") && text.contains("fail-closed"),
        "{text}"
    );
    assert!(
        text.contains("global") && text.contains("7 records"),
        "{text}"
    );
    assert!(text.contains("built-in name detection on"), "{text}");
    assert!(text.contains("required (both entrances)"), "{text}");
    assert!(text.contains("34"), "{text}");
    // no ANSI escape sequences when colorize is off
    assert!(!text.contains('\u{1b}'), "{text}");
}

#[test]
fn render_status_flags_warn_gate() {
    let snapshot = json!({
        "posture": {"leak_gate": "warn", "leak_gate_active": false},
        "counts": {"tokens_unresolved": 0},
    });
    let text = render_status(&snapshot, false);
    assert!(text.contains("warn only"), "{text}");
    assert!(text.contains("not set (localhost only)"), "{text}");
}

#[test]
fn render_status_shows_live_dictionary_reloads() {
    let snapshot = json!({
        "posture": {"dictionary_terms": 4, "mapping_records": 0},
        "counts": {"dictionary_reloads": 2, "tokens_unresolved": 0},
    });
    let text = render_status(&snapshot, false);
    assert!(text.contains("4 terms"), "{text}");
    assert!(text.contains("2 live reloads"), "{text}");
}

#[test]
fn render_status_colorizes_on_request() {
    let snapshot = json!({
        "posture": {"leak_gate": "block", "leak_gate_active": true},
        "counts": {},
    });
    let text = render_status(&snapshot, true);
    assert!(text.contains('\u{1b}'), "expected ANSI colors");
}

#[test]
fn render_check_counts_entities() {
    let dictionary = UserDictionary::from_terms([
        ("山田太郎".to_string(), EntityType::Person),
        ("090-1234-5678".to_string(), EntityType::Phone),
    ]);
    let result = detect("山田太郎さんと090-1234-5678の件", Some(&dictionary), None);
    let text = render_check("", &result, false);
    assert!(text.contains("2 entities"), "{text}");
    assert!(text.contains("人名 1") && text.contains("電話 1"), "{text}");
    assert!(text.contains("⟦token⟧"), "{text}");
}

#[test]
fn render_check_handles_an_empty_result() {
    let result = detect("特に何もありません", None, None);
    let text = render_check("", &result, false);
    assert!(text.contains("nothing found"), "{text}");
}

#[test]
fn binary_check_masks_from_the_argument() {
    let output = binary()
        .args(["check", "--no-color", "山田太郎さんと090-1234-5678の件"])
        .output()
        .expect("cannot run mask");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(stdout.contains('⟦'), "stdout: {stdout}");
    assert!(!stdout.contains("090-1234-5678"), "stdout: {stdout}");
    assert!(stderr.contains("2 entities"), "stderr: {stderr}");
}

#[test]
fn binary_check_reads_stdin() {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = binary()
        .args(["check", "--no-color"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("cannot run mask");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        stdin
            .write_all("taro.yamada@example.co.jp までご連絡ください".as_bytes())
            .expect("write");
    }
    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(!stdout.contains("taro.yamada@example.co.jp"), "{stdout}");
    assert!(stdout.contains('⟦'), "{stdout}");
}

#[test]
fn binary_check_exits_zero_even_when_pii_is_found() {
    // detection is the tool working, not failing
    let output = binary()
        .args(["check", "--no-color", "03-1234-5678"])
        .output()
        .expect("cannot run mask");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn binary_reports_a_missing_config_file() {
    let output = binary()
        .args(["--config", "/nonexistent/mask.toml", "check", "hi"])
        .output()
        .expect("cannot run mask");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(stderr.contains("config file not found"), "{stderr}");
}

#[test]
fn binary_help_lists_every_entrance() {
    let output = binary().arg("--help").output().expect("cannot run mask");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    for command in ["check", "chat", "status", "serve", "dict"] {
        assert!(stdout.contains(command), "missing {command} in {stdout}");
    }
}

// --- the binary against a live gateway ---------------------------------------

mod live {
    use crate::common;
    use mask::gateway::config::GatewayConfig;

    fn config() -> GatewayConfig {
        GatewayConfig {
            dictionary_path: Some(common::dict_file(&[("山田太郎", "person")])),
            ..common::base_config()
        }
    }

    #[tokio::test]
    async fn status_panel_and_json_read_a_live_gateway() {
        let h = common::start_with(config(), common::MockKind::Echo).await;
        let binary = env!("CARGO_BIN_EXE_mask");
        let empty = common::temp_file("empty.toml", "");
        let empty = empty.to_str().unwrap();

        let output = tokio::process::Command::new(binary)
            .args(["--no-color", "--config", empty, "status", "--url"])
            .arg(&h.base_url)
            .output()
            .await
            .expect("cannot run mask");
        // the empty config has no gateway token: exercises the anonymous path
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        assert!(output.status.success(), "{stdout}");
        assert!(stdout.contains("leak gate"), "{stdout}");
        assert!(stdout.contains("fail-closed"), "{stdout}");
        // The admin channel is part of the panel: an agent-written gateway
        // (no terminal) must be visibly closed, not silently so.
        assert!(stdout.contains("admin channel"), "{stdout}");
        assert!(
            !stdout.contains('\u{1b}'),
            "--no-color must strip ANSI: {stdout}"
        );

        let output = tokio::process::Command::new(binary)
            .args(["--config", empty, "status", "--url"])
            .arg(&h.base_url)
            .arg("--json")
            .output()
            .await
            .expect("cannot run mask");
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let snapshot: serde_json::Value = serde_json::from_str(&stdout).expect("json snapshot");
        assert_eq!(snapshot["posture"]["leak_gate"], "block");
        assert!(snapshot["counts"]["requests_total"].is_u64());
    }

    #[tokio::test]
    async fn chat_round_trips_through_the_gateway() {
        let h = common::start_with(config(), common::MockKind::Echo).await;
        let empty = common::temp_file("empty.toml", "");
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_mask"))
            .args([
                "--no-color",
                "--config",
                empty.to_str().unwrap(),
                "chat",
                "--url",
            ])
            .arg(&h.base_url)
            .arg("山田太郎さんに折返し電話してください")
            .output()
            .await
            .expect("cannot run mask");
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        assert!(output.status.success(), "{stdout}{stderr}");
        // the human sees the real name back
        assert!(stdout.contains("山田太郎"), "{stdout}");
        assert!(!stdout.contains('⟦'), "{stdout}");
        // and the footer reports the per-request indicators
        assert!(stderr.contains("masked 1 / restored 1"), "{stderr}");
        // the model only ever saw the token
        assert!(h.upstream.sent_raw().contains('⟦'));
        assert!(!h.upstream.sent_raw().contains("山田太郎"));
    }

    #[tokio::test]
    async fn status_reports_an_unreachable_gateway() {
        let empty = common::temp_file("empty.toml", "");
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_mask"))
            .args([
                "--no-color",
                "--config",
                empty.to_str().unwrap(),
                "status",
                "--url",
                "http://127.0.0.1:1",
                "--timeout",
                "0.3",
            ])
            .output()
            .await
            .expect("cannot run mask");
        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        assert!(stderr.contains("unreachable"), "{stderr}");
    }
}

#[test]
fn serve_refuses_a_shell_that_belongs_to_an_agent() {
    let output = binary()
        .env("CLAUDECODE", "1")
        .args(["serve"])
        .output()
        .expect("cannot run mask");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(stderr.contains("belongs to an AI agent"), "{stderr}");
    assert!(stderr.contains("--allow-agent-host"), "{stderr}");
}

#[test]
fn serve_starts_under_an_explicit_agent_override() {
    // An override is a decision, not an accident: CLAUDECODE=1 plus
    // --allow-agent-host must start the gateway.
    let mut child = binary()
        .env("CLAUDECODE", "1")
        .args(["serve", "--port", "0", "--allow-agent-host"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("cannot run mask");
    std::thread::sleep(std::time::Duration::from_millis(700));
    let still_running = child.try_wait().expect("wait").is_none();
    let _ = child.kill();
    let _ = child.wait();
    assert!(still_running, "serve exited instead of starting");
}

#[test]
fn serve_starts_when_no_agent_owns_the_shell() {
    // Under an agent (this test may itself run inside one) the ancestry walk
    // finds the agent and the gateway must refuse; on a plain shell it starts.
    // Either outcome is correct — what must not happen is the guard firing on a
    // clean shell.
    if mask::gateway::guard::agent_origin().is_some() {
        return;
    }
    let mut child = binary()
        .args(["serve", "--port", "0"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("cannot run mask");
    std::thread::sleep(std::time::Duration::from_millis(700));
    let still_running = child.try_wait().expect("wait").is_none();
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        still_running,
        "serve exited on a shell with no agent marker"
    );
}
