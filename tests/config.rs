//! Configuration tests: TOML shape, defaults, validation, URL joining.
//!
//! The defaults are the security posture: leak gate blocking, global scope,
//! loopback-only admin, status private. A regression here must fail loudly.

use std::io::Write;

use mask::gateway::config::{
    GatewayConfig, LeakGate, SessionScope, DEFAULT_CONFIG_NAME, DEFAULT_PASSTHROUGH_ALLOWLIST,
};
use mask::gateway::sharing::{KdfParams, DEFAULT_TTL_SECONDS};

const FULL_TOML: &str = r#"
[server]
host = "127.0.0.1"
port = 9000

[upstream]
base_url = "https://api.example.test/v1"
api_key = "sk-real"

[mask]
use_ner = false
dictionary = "dict.tsv"

[session]
scope = "request"
capacity = 64

[gateway]
token = "tok"
passthrough_allowlist = ["/v1/a", "/v1/b"]
leak_gate = "warn"
handoff_ttl_seconds = 600
handoff_max_attempts = 5
admin_allow_remote = true
status_public = true
"#;

fn write_temp(name: &str, content: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("mask-config-{}-{name}", std::process::id()));
    let mut file = std::fs::File::create(&path).expect("create");
    file.write_all(content.as_bytes()).expect("write");
    path
}

#[test]
fn defaults_are_the_closed_posture() {
    let config = GatewayConfig::default();
    assert_eq!(config.host, "127.0.0.1");
    assert_eq!(config.port, 8080);
    assert!(config.use_ner);
    assert_eq!(config.session_scope, SessionScope::Global);
    assert_eq!(config.session_capacity, 256);
    assert_eq!(config.leak_gate, LeakGate::Block);
    assert!(config.leak_gate.is_active());
    assert!(config.gateway_token.is_empty());
    assert!(!config.admin_allow_remote);
    assert!(!config.status_public);
    assert_eq!(config.handoff_ttl_seconds, DEFAULT_TTL_SECONDS);
    assert_eq!(config.handoff_max_attempts, 3);
    assert_eq!(config.handoff_kdf(), KdfParams::MODERATE);
    assert_eq!(
        config.passthrough_allowlist,
        DEFAULT_PASSTHROUGH_ALLOWLIST
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(DEFAULT_CONFIG_NAME, "mask.toml");
}

#[test]
fn full_toml_loads_every_section() {
    let config = GatewayConfig::from_toml(FULL_TOML).expect("parse");
    assert_eq!(config.host, "127.0.0.1");
    assert_eq!(config.port, 9000);
    assert_eq!(config.upstream_base_url, "https://api.example.test/v1");
    assert_eq!(config.upstream_api_key, "sk-real");
    assert!(!config.use_ner);
    assert_eq!(
        config.dictionary_path.as_ref().unwrap().to_str().unwrap(),
        "dict.tsv"
    );
    assert_eq!(config.session_scope, SessionScope::Request);
    assert_eq!(config.session_capacity, 64);
    assert_eq!(config.gateway_token, "tok");
    assert_eq!(config.passthrough_allowlist, vec!["/v1/a", "/v1/b"]);
    assert_eq!(config.leak_gate, LeakGate::Warn);
    assert!(!config.leak_gate.is_active());
    assert_eq!(config.handoff_ttl_seconds, 600);
    assert_eq!(config.handoff_max_attempts, 5);
    assert!(config.admin_allow_remote);
    assert!(config.status_public);
}

#[test]
fn empty_toml_keeps_defaults() {
    let config = GatewayConfig::from_toml("").expect("parse");
    assert_eq!(config.session_scope, SessionScope::Global);
    assert_eq!(config.leak_gate, LeakGate::Block);
}

#[test]
fn handoff_config_loads_from_toml() {
    let config = GatewayConfig::from_toml(
        "[gateway]\nhandoff_ttl_seconds = 3600\nhandoff_max_attempts = 5\n\
         handoff_kdf_opslimit = 2\nhandoff_kdf_memlimit = 67108864\n",
    )
    .expect("parse");
    assert_eq!(config.handoff_ttl_seconds, 3600);
    assert_eq!(config.handoff_max_attempts, 5);
    assert_eq!(config.handoff_kdf().opslimit, 2);
    assert_eq!(config.handoff_kdf().memlimit, 67_108_864);
}

#[test]
fn invalid_values_are_rejected() {
    for toml in [
        "[session]\nscope = \"nope\"\n",
        "[session]\ncapacity = 0\n",
        "[gateway]\nleak_gate = \"nope\"\n",
        "[gateway]\nhandoff_ttl_seconds = 0\n",
        "[gateway]\nhandoff_ttl_seconds = -5\n",
        "[gateway]\nhandoff_max_attempts = 0\n",
        "[gateway]\nhandoff_kdf_opslimit = 0\n",
        "[gateway]\nhandoff_kdf_memlimit = 1024\n",
        "[server]\nport = \"not a port\"\n",
        "this is not toml",
    ] {
        assert!(
            GatewayConfig::from_toml(toml).is_err(),
            "accepted: {toml:?}"
        );
    }
}

#[test]
fn unknown_keys_are_ignored() {
    let config = GatewayConfig::from_toml("[gateway]\nfuture_flag = 1\n").expect("parse");
    assert_eq!(config.leak_gate, LeakGate::Block);
}

#[test]
fn load_reads_an_explicit_path() {
    let path = write_temp("explicit.toml", "[server]\nport = 12345\n");
    let config = GatewayConfig::load(Some(&path)).expect("load");
    assert_eq!(config.port, 12345);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn load_rejects_a_missing_path() {
    let error = GatewayConfig::load(Some(std::path::Path::new("/nonexistent/mask.toml")));
    assert!(error.is_err());
    assert!(error
        .unwrap_err()
        .to_string()
        .contains("config file not found"));
}

#[test]
fn upstream_urls_join_cleanly() {
    let config = GatewayConfig {
        upstream_base_url: "https://api.example.test/v1/".to_string(),
        ..GatewayConfig::default()
    };
    assert_eq!(config.upstream_base(), "https://api.example.test/v1");
    assert_eq!(
        config.upstream_url("chat/completions"),
        "https://api.example.test/v1/chat/completions"
    );
    assert_eq!(
        config.upstream_url("/models"),
        "https://api.example.test/v1/models"
    );
}

#[test]
fn scope_and_gate_names_are_stable() {
    // these strings are the /status contract the website widget reads
    assert_eq!(SessionScope::Global.as_str(), "global");
    assert_eq!(SessionScope::Request.as_str(), "request");
    assert_eq!(LeakGate::Block.as_str(), "block");
    assert_eq!(LeakGate::Warn.as_str(), "warn");
}
