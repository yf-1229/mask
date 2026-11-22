//! `mask audit` tests: a detection dry run over files that shows the masked
//! text and points at likely misses, without ever printing a value in the
//! report.

mod common;

use std::fs;
use std::process::Command;

use mask::cli::render_audit;
use mask::detect::suspect::{scan, Suspicion, SuspicionKind};
use mask::types::{DetectionResult, Entity, EntityType, Source, BAND_EXACT};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mask"))
}

/// A config with NER off (deterministic) and the given dictionary terms.
fn config_with(terms: &[(&str, &str)]) -> std::path::PathBuf {
    let dictionary = common::dict_file(terms);
    let path = dictionary.to_string_lossy().replace('\\', "/");
    common::temp_file(
        "audit.toml",
        &format!("[mask]\nuse_ner = false\ndictionary = \"{path}\"\n"),
    )
}

fn notes() -> std::path::PathBuf {
    common::temp_file(
        "audit-notes.txt",
        "山田太郎様へ\n鈴木一郎様へ\nお客様各位\nさくら様\n",
    )
}

#[test]
fn audit_masks_what_it_can_and_points_at_the_rest() {
    let config = config_with(&[("山田太郎", "person")]);
    let notes = notes();
    let output = binary()
        .args(["--no-color", "--config"])
        .arg(&config)
        .arg("audit")
        .arg(&notes)
        .output()
        .expect("cannot run mask");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // the known name is masked, the unknown one is visibly still there
    assert!(stdout.contains('⟦'), "{stdout}");
    assert!(!stdout.contains("山田太郎"), "{stdout}");
    assert!(stdout.contains("鈴木一郎"), "{stdout}");

    // the report points at line 2 and never repeats the value
    assert!(stderr.contains("entities        1"), "{stderr}");
    assert!(stderr.contains("suspicious      1"), "{stderr}");
    assert!(stderr.contains("line 2"), "{stderr}");
    assert!(!stderr.contains("鈴木一郎"), "{stderr}");
    assert!(!stderr.contains("山田太郎"), "{stderr}");
    // one-character and kana runs are outside the hint's scope
    assert!(!stderr.contains("line 3"), "{stderr}");
    assert!(!stderr.contains("line 4"), "{stderr}");
}

#[test]
fn strict_turns_a_suspicious_span_into_a_nonzero_exit() {
    let config = config_with(&[]);
    let notes = notes();
    let output = binary()
        .args(["--no-color", "--config"])
        .arg(&config)
        .args(["audit", "--strict", "--no-output"])
        .arg(&notes)
        .output()
        .expect("cannot run mask");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "--no-output wrote stdout");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("line 1") && stderr.contains("line 2"),
        "{stderr}"
    );
    assert!(!stderr.contains("鈴木一郎"), "{stderr}");
}

#[test]
fn audit_reads_stdin_and_lists_files() {
    let config = config_with(&[]);
    let mut child = binary()
        .args(["--no-color", "--config"])
        .arg(&config)
        .arg("audit")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("cannot run mask");
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all("佐藤花子さん\n".as_bytes())
            .expect("write");
    }
    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("佐藤花子"), "{stdout}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("line 1"),
        "stdin line number"
    );

    let first = notes();
    let second = common::temp_file("audit-second.txt", "田中様\n");
    let output = binary()
        .args(["--no-color", "--config"])
        .arg(&config)
        .arg("audit")
        .arg(&first)
        .arg(&second)
        .output()
        .expect("cannot run mask");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("==>"), "{stdout}");
    assert!(stdout.contains("audit-second.txt"), "{stdout}");
}

#[test]
fn render_audit_keeps_values_out_of_the_report() {
    let text = "鈴木一郎様へ";
    let entity = Entity::new(
        EntityType::Person,
        0,
        "鈴木一郎".len(),
        "鈴木一郎",
        BAND_EXACT,
        Source::Dict,
    );
    let result = DetectionResult::new(text, vec![entity]);
    let hints = scan(text, &DetectionResult::new(text, vec![]));
    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].kind, SuspicionKind::HonorificName);

    let report = render_audit("notes.txt", text, &result, &hints, false);
    assert!(report.contains("entities        1"), "{report}");
    assert!(report.contains("line 1"), "{report}");
    assert!(!report.contains("鈴木一郎"), "{report}");
    assert!(!report.contains('\u{1b}'), "{report}");
}

#[test]
fn render_audit_reports_a_clean_file_as_clean() {
    let text = "山田太郎様";
    let entity = Entity::new(
        EntityType::Person,
        0,
        "山田太郎".len(),
        "山田太郎",
        BAND_EXACT,
        Source::Dict,
    );
    let result = DetectionResult::new(text, vec![entity]);
    let report = render_audit("notes.txt", text, &result, &[], false);
    assert!(report.contains("suspicious      0"), "{report}");
    assert!(!report.contains("mask dict add"), "{report}");
}

#[test]
fn a_suspicion_carries_the_span_but_the_report_does_not() {
    let text = "鈴木一郎様";
    let hints = scan(text, &DetectionResult::new(text, vec![]));
    let hint: &Suspicion = &hints[0];
    assert_eq!(&text[hint.start..hint.end], "鈴木一郎");
    let report = render_audit(
        "x",
        text,
        &DetectionResult::new(text, vec![]),
        &hints,
        false,
    );
    assert!(!report.contains("鈴木一郎"), "{report}");
}

#[test]
fn audit_of_a_missing_file_is_an_error() {
    let config = config_with(&[]);
    let missing = std::env::temp_dir().join("mask-audit-does-not-exist.txt");
    let _ = fs::remove_file(&missing);
    let output = binary()
        .args(["--no-color", "--config"])
        .arg(&config)
        .arg("audit")
        .arg(&missing)
        .output()
        .expect("cannot run mask");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot read"), "{stderr}");
}
