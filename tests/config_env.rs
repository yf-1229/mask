//! Environment-override tests, isolated in their own test binary.
//!
//! `GatewayConfig::load` layers environment variables on top of the file, so an
//! operator can point a container at a different upstream without mounting a
//! config. Environment variables are process-global, hence the separate file:
//! nothing else in the suite can observe these mutations.

use std::sync::{Mutex, MutexGuard};

use mask::gateway::config::{GatewayConfig, LeakGate};

/// Environment variables are process-global: serialise the whole file.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

#[test]
fn environment_overrides_the_file() {
    let _guard = env_lock();
    let mut path = std::env::temp_dir();
    path.push(format!("mask-env-{}.toml", std::process::id()));
    std::fs::write(
        &path,
        "[server]\nport = 1111\n[upstream]\nbase_url = \"http://file.test/v1\"\n",
    )
    .expect("write");

    std::env::set_var("MASK_SERVER_PORT", "2222");
    std::env::set_var("MASK_SERVER_HOST", "0.0.0.0");
    std::env::set_var("MASK_UPSTREAM_BASE_URL", "http://env.test/v1");
    std::env::set_var("MASK_UPSTREAM_API_KEY", "sk-env");
    std::env::set_var("MASK_GATEWAY_TOKEN", "env-token");
    std::env::set_var("MASK_LEAK_GATE", "warn");
    std::env::set_var("MASK_HANDOFF_TTL_SECONDS", "120");
    std::env::set_var("MASK_HANDOFF_MAX_ATTEMPTS", "7");
    std::env::set_var("MASK_ADMIN_ALLOW_REMOTE", "true");
    std::env::set_var("MASK_STATUS_PUBLIC", "1");

    let config = GatewayConfig::load(Some(&path)).expect("load");
    assert_eq!(config.port, 2222);
    assert_eq!(config.host, "0.0.0.0");
    assert_eq!(config.upstream_base_url, "http://env.test/v1");
    assert_eq!(config.upstream_api_key, "sk-env");
    assert_eq!(config.gateway_token, "env-token");
    assert_eq!(config.leak_gate, LeakGate::Warn);
    assert_eq!(config.handoff_ttl_seconds, 120);
    assert_eq!(config.handoff_max_attempts, 7);
    assert!(config.admin_allow_remote);
    assert!(config.status_public);

    for key in [
        "MASK_SERVER_PORT",
        "MASK_SERVER_HOST",
        "MASK_UPSTREAM_BASE_URL",
        "MASK_UPSTREAM_API_KEY",
        "MASK_GATEWAY_TOKEN",
        "MASK_LEAK_GATE",
        "MASK_HANDOFF_TTL_SECONDS",
        "MASK_HANDOFF_MAX_ATTEMPTS",
        "MASK_ADMIN_ALLOW_REMOTE",
        "MASK_STATUS_PUBLIC",
    ] {
        std::env::remove_var(key);
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn nonsense_environment_values_are_ignored() {
    let _guard = env_lock();
    std::env::set_var("MASK_SERVER_PORT", "not-a-port");
    std::env::set_var("MASK_HANDOFF_TTL_SECONDS", "0");
    std::env::set_var("MASK_HANDOFF_MAX_ATTEMPTS", "0");
    std::env::set_var("MASK_LEAK_GATE", "nonsense");
    std::env::set_var("MASK_HANDOFF_KDF_MEMLIMIT", "1");

    let config = GatewayConfig::load(None).expect("load");
    assert_eq!(config.port, GatewayConfig::default().port);
    assert_eq!(
        config.handoff_ttl_seconds,
        GatewayConfig::default().handoff_ttl_seconds
    );
    assert_eq!(
        config.handoff_max_attempts,
        GatewayConfig::default().handoff_max_attempts
    );
    assert_eq!(config.leak_gate, LeakGate::Block);
    assert_eq!(
        config.handoff_kdf_memlimit,
        GatewayConfig::default().handoff_kdf_memlimit
    );

    for key in [
        "MASK_SERVER_PORT",
        "MASK_HANDOFF_TTL_SECONDS",
        "MASK_HANDOFF_MAX_ATTEMPTS",
        "MASK_LEAK_GATE",
        "MASK_HANDOFF_KDF_MEMLIMIT",
    ] {
        std::env::remove_var(key);
    }
}

#[test]
fn mask_config_env_selects_the_file() {
    let _guard = env_lock();
    let mut path = std::env::temp_dir();
    path.push(format!("mask-env-file-{}.toml", std::process::id()));
    std::fs::write(&path, "[server]\nport = 3333\n").expect("write");
    std::env::set_var("MASK_CONFIG", &path);

    let config = GatewayConfig::load(None).expect("load");
    assert_eq!(config.port, 3333);

    std::env::remove_var("MASK_CONFIG");
    let _ = std::fs::remove_file(&path);
}
