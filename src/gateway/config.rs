//! Gateway configuration: mask.toml with environment overrides.
//!
//! Precedence (lowest to highest):
//!     defaults < mask.toml < MASK_* environment variables < CLI flags
//!
//! Which file is read (first match wins):
//!     --config <path> > $MASK_CONFIG > $XDG_CONFIG_HOME/mask/mask.toml
//!     (~/.config/mask/mask.toml) > ./mask.toml
//!
//! The operator's config directory outranks the working directory on purpose:
//! a checkout is somewhere an AI agent writes, and the upstream key should not
//! be reachable from there. See [`user_config_path`].

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

pub const DEFAULT_CONFIG_NAME: &str = "mask.toml";

/// Paths (as seen by the client, "/v1/..." included) the gateway forwards
/// verbatim. Everything else is refused: deny by default.
pub const DEFAULT_PASSTHROUGH_ALLOWLIST: &[&str] = &["/v1/models"];

/// How long a mapping table lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionScope {
    /// One Session (and mapping table) for the whole process, so pseudonyms
    /// stay stable across the turns of a conversation.
    Global,
    /// A fresh Session per request; lighter table but the LLM cannot rely on
    /// pseudonyms from earlier turns.
    Request,
}

impl SessionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionScope::Global => "global",
            SessionScope::Request => "request",
        }
    }
}

/// Outbound leak gate behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeakGate {
    /// Refuse the request (fail closed).
    Block,
    /// Log and send anyway.
    Warn,
}

impl LeakGate {
    pub fn as_str(self) -> &'static str {
        match self {
            LeakGate::Block => "block",
            LeakGate::Warn => "warn",
        }
    }

    pub fn is_active(self) -> bool {
        self == LeakGate::Block
    }
}

#[derive(Clone)]
pub struct GatewayConfig {
    pub host: String,
    pub port: u16,
    pub upstream_base_url: String,
    pub upstream_api_key: String,
    pub use_ner: bool,
    pub dictionary_path: Option<PathBuf>,
    pub session_scope: SessionScope,
    /// If set, clients must send it as their API key (`Authorization: Bearer
    /// <token>` or `x-api-key: <token>`). Distribute this instead of the real
    /// upstream key.
    pub gateway_token: String,
    /// Client paths forwarded verbatim (leak-gated). Anything else: 403.
    pub passthrough_allowlist: Vec<String>,
    pub leak_gate: LeakGate,
    /// Encrypted handoff: envelope lifetime and failed-passphrase attempts
    /// before the envelope is locked for good (per envelope, in-process).
    pub handoff_ttl_seconds: i64,
    pub handoff_max_attempts: u32,
    /// argon2id cost for handoff envelopes, in bytes of memory and passes.
    /// Defaults are moderate-grade (256 MiB / 3 passes); lower them only on a
    /// host that cannot afford the derivation, and understand that offline
    /// guessing against a copied envelope gets cheaper with every step down.
    pub handoff_kdf_opslimit: u32,
    pub handoff_kdf_memlimit: u64,
    /// Admin endpoints (export/import) accept loopback clients only unless
    /// this is set. The envelope file travels, not the admin API.
    pub admin_allow_remote: bool,
    /// Publish /status with a CORS header so the indicator widget on the
    /// website can read it from a browser. Off by default: fail closed.
    pub status_public: bool,
    /// Admin endpoints also require a token that only the gateway's own
    /// terminal ever sees. On by default: the mapping table leaves the process
    /// because a human asked for it, not because something could reach the
    /// port. See [`super::guard`].
    pub admin_require_human: bool,
    /// Refuse `mask serve` when the shell belongs to an AI agent. On by
    /// default; `--allow-agent-host` is the deliberate way out.
    pub agent_host_guard: bool,
    /// The operator token for this process. Minted at startup and printed to
    /// the controlling terminal; never read from the file or the environment,
    /// so no artefact an agent can read ever carries it.
    pub admin_human_token: Option<String>,
}

/// Redacted on purpose: `tracing::debug!(?config)` is one careless line away,
/// and this struct holds the upstream key, the client token and the operator
/// token. Secrets print as `<set>`; nothing else is hidden.
impl std::fmt::Debug for GatewayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn secret(value: &str) -> &'static str {
            if value.is_empty() {
                "<unset>"
            } else {
                "<set>"
            }
        }
        f.debug_struct("GatewayConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("upstream_base_url", &self.upstream_base_url)
            .field("upstream_api_key", &secret(&self.upstream_api_key))
            .field("use_ner", &self.use_ner)
            .field("dictionary_path", &self.dictionary_path)
            .field("session_scope", &self.session_scope)
            .field("gateway_token", &secret(&self.gateway_token))
            .field("passthrough_allowlist", &self.passthrough_allowlist)
            .field("leak_gate", &self.leak_gate)
            .field("handoff_ttl_seconds", &self.handoff_ttl_seconds)
            .field("handoff_max_attempts", &self.handoff_max_attempts)
            .field("handoff_kdf_opslimit", &self.handoff_kdf_opslimit)
            .field("handoff_kdf_memlimit", &self.handoff_kdf_memlimit)
            .field("admin_allow_remote", &self.admin_allow_remote)
            .field("status_public", &self.status_public)
            .field("admin_require_human", &self.admin_require_human)
            .field("agent_host_guard", &self.agent_host_guard)
            .field(
                "admin_human_token",
                &secret(self.admin_human_token.as_deref().unwrap_or("")),
            )
            .finish()
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        GatewayConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            upstream_base_url: "https://api.openai.com/v1".to_string(),
            upstream_api_key: String::new(),
            use_ner: true,
            dictionary_path: None,
            session_scope: SessionScope::Global,
            gateway_token: String::new(),
            passthrough_allowlist: DEFAULT_PASSTHROUGH_ALLOWLIST
                .iter()
                .map(|s| s.to_string())
                .collect(),
            leak_gate: LeakGate::Block,
            handoff_ttl_seconds: 3600,
            handoff_max_attempts: 3,
            handoff_kdf_opslimit: crate::gateway::sharing::KdfParams::MODERATE.opslimit,
            handoff_kdf_memlimit: crate::gateway::sharing::KdfParams::MODERATE.memlimit,
            admin_allow_remote: false,
            status_public: false,
            admin_require_human: true,
            agent_host_guard: true,
            admin_human_token: None,
        }
    }
}

// --- TOML shape -------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    server: Option<ServerSection>,
    upstream: Option<UpstreamSection>,
    mask: Option<MaskSection>,
    session: Option<SessionSection>,
    gateway: Option<GatewaySection>,
}

#[derive(Debug, Deserialize)]
struct ServerSection {
    host: Option<String>,
    port: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct UpstreamSection {
    base_url: Option<String>,
    api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MaskSection {
    use_ner: Option<bool>,
    dictionary: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SessionSection {
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GatewaySection {
    token: Option<String>,
    passthrough_allowlist: Option<Vec<String>>,
    leak_gate: Option<String>,
    handoff_ttl_seconds: Option<i64>,
    handoff_max_attempts: Option<u32>,
    handoff_kdf_opslimit: Option<u32>,
    handoff_kdf_memlimit: Option<u64>,
    admin_allow_remote: Option<bool>,
    status_public: Option<bool>,
    admin_require_human: Option<bool>,
    agent_host_guard: Option<bool>,
}

impl GatewayConfig {
    /// Load config from `path`, `MASK_CONFIG`, the user config directory, or
    /// `./mask.toml` (if present).
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let resolved = Self::resolve_path(path)?;
        match resolved {
            Some(path) => {
                let text = std::fs::read_to_string(&path)
                    .with_context(|| format!("cannot read config {}", path.display()))?;
                let mut config = Self::from_toml(&text)?;
                config.apply_env();
                warn_on_loose_permissions(&path, !config.upstream_api_key.is_empty());
                Ok(config)
            }
            None => {
                let mut config = GatewayConfig::default();
                config.apply_env();
                Ok(config)
            }
        }
    }

    /// Parse a TOML document (no environment overrides). Useful for tests.
    pub fn from_toml(text: &str) -> Result<Self> {
        let file: FileConfig =
            toml::from_str(text).map_err(|e| anyhow!("invalid mask.toml: {e}"))?;
        let mut config = GatewayConfig::default();
        if let Some(server) = file.server {
            if let Some(host) = server.host {
                config.host = host;
            }
            if let Some(port) = server.port {
                config.port = port;
            }
        }
        if let Some(upstream) = file.upstream {
            if let Some(base_url) = upstream.base_url {
                config.upstream_base_url = base_url;
            }
            if let Some(api_key) = upstream.api_key {
                config.upstream_api_key = api_key;
            }
        }
        if let Some(mask) = file.mask {
            if let Some(use_ner) = mask.use_ner {
                config.use_ner = use_ner;
            }
            if let Some(dictionary) = mask.dictionary {
                config.dictionary_path = Some(PathBuf::from(dictionary));
            }
        }
        if let Some(session) = file.session {
            if let Some(scope) = session.scope {
                config.session_scope = match scope.as_str() {
                    "global" => SessionScope::Global,
                    "request" => SessionScope::Request,
                    other => {
                        bail!("session.scope must be 'global' or 'request', got {other:?}")
                    }
                };
            }
        }
        if let Some(gateway) = file.gateway {
            if let Some(token) = gateway.token {
                config.gateway_token = token;
            }
            if let Some(allowlist) = gateway.passthrough_allowlist {
                config.passthrough_allowlist = allowlist;
            }
            if let Some(leak_gate) = gateway.leak_gate {
                config.leak_gate = match leak_gate.as_str() {
                    "block" => LeakGate::Block,
                    "warn" => LeakGate::Warn,
                    other => bail!("gateway.leak_gate must be 'block' or 'warn', got {other:?}"),
                };
            }
            if let Some(ttl) = gateway.handoff_ttl_seconds {
                if ttl <= 0 {
                    bail!("gateway.handoff_ttl_seconds must be a positive integer");
                }
                config.handoff_ttl_seconds = ttl;
            }
            if let Some(attempts) = gateway.handoff_max_attempts {
                if attempts < 1 {
                    bail!("gateway.handoff_max_attempts must be >= 1");
                }
                config.handoff_max_attempts = attempts;
            }
            if let Some(ops) = gateway.handoff_kdf_opslimit {
                if ops < 1 {
                    bail!("gateway.handoff_kdf_opslimit must be >= 1");
                }
                config.handoff_kdf_opslimit = ops;
            }
            if let Some(memlimit) = gateway.handoff_kdf_memlimit {
                if memlimit < 8 * 1024 {
                    bail!("gateway.handoff_kdf_memlimit must be at least 8192 bytes");
                }
                config.handoff_kdf_memlimit = memlimit;
            }
            if let Some(value) = gateway.admin_allow_remote {
                config.admin_allow_remote = value;
            }
            if let Some(value) = gateway.status_public {
                config.status_public = value;
            }
            if let Some(value) = gateway.admin_require_human {
                config.admin_require_human = value;
            }
            if let Some(value) = gateway.agent_host_guard {
                config.agent_host_guard = value;
            }
        }
        Ok(config)
    }

    fn apply_env(&mut self) {
        if let Ok(value) = std::env::var("MASK_SERVER_HOST") {
            self.host = value;
        }
        if let Ok(value) = std::env::var("MASK_SERVER_PORT") {
            if let Ok(port) = value.trim().parse::<u16>() {
                self.port = port;
            }
        }
        if let Ok(value) = std::env::var("MASK_UPSTREAM_BASE_URL") {
            self.upstream_base_url = value;
        }
        if let Ok(value) = std::env::var("MASK_UPSTREAM_API_KEY") {
            self.upstream_api_key = value;
        }
        if let Ok(value) = std::env::var("MASK_GATEWAY_TOKEN") {
            self.gateway_token = value;
        }
        if let Ok(value) = std::env::var("MASK_LEAK_GATE") {
            match value.as_str() {
                "block" => self.leak_gate = LeakGate::Block,
                "warn" => self.leak_gate = LeakGate::Warn,
                _ => {}
            }
        }
        if let Ok(value) = std::env::var("MASK_HANDOFF_TTL_SECONDS") {
            if let Ok(ttl) = value.trim().parse::<i64>() {
                if ttl > 0 {
                    self.handoff_ttl_seconds = ttl;
                }
            }
        }
        if let Ok(value) = std::env::var("MASK_HANDOFF_MAX_ATTEMPTS") {
            if let Ok(attempts) = value.trim().parse::<u32>() {
                if attempts >= 1 {
                    self.handoff_max_attempts = attempts;
                }
            }
        }
        if let Ok(value) = std::env::var("MASK_HANDOFF_KDF_OPSLIMIT") {
            if let Ok(ops) = value.trim().parse::<u32>() {
                if ops >= 1 {
                    self.handoff_kdf_opslimit = ops;
                }
            }
        }
        if let Ok(value) = std::env::var("MASK_HANDOFF_KDF_MEMLIMIT") {
            if let Ok(memlimit) = value.trim().parse::<u64>() {
                if memlimit >= 8 * 1024 {
                    self.handoff_kdf_memlimit = memlimit;
                }
            }
        }
        if let Ok(value) = std::env::var("MASK_ADMIN_ALLOW_REMOTE") {
            self.admin_allow_remote = env_bool(&value);
        }
        if let Ok(value) = std::env::var("MASK_STATUS_PUBLIC") {
            self.status_public = env_bool(&value);
        }
        if let Ok(value) = std::env::var("MASK_ADMIN_REQUIRE_HUMAN") {
            self.admin_require_human = env_bool(&value);
        }
        if let Ok(value) = std::env::var("MASK_AGENT_HOST_GUARD") {
            self.agent_host_guard = env_bool(&value);
        }
    }

    fn resolve_path(path: Option<&Path>) -> Result<Option<PathBuf>> {
        if let Some(path) = path {
            if !path.exists() {
                bail!("config file not found: {}", path.display());
            }
            return Ok(Some(path.to_path_buf()));
        }
        if let Ok(env) = std::env::var("MASK_CONFIG") {
            let path = PathBuf::from(env);
            if !path.exists() {
                bail!("config file not found: {}", path.display());
            }
            return Ok(Some(path));
        }
        // The operator's own file wins over whatever sits in the working
        // directory: a checkout is a place an agent writes to, the config
        // directory is not (see AGENTS.md and SECURITY.md).
        if let Some(path) = user_config_path().filter(|path| path.exists()) {
            // Two configs is a confusing state: say which one won, every time.
            let local = PathBuf::from(DEFAULT_CONFIG_NAME);
            if local.exists() {
                tracing::warn!(
                    using = %path.display(),
                    ignoring = %local.display(),
                    "both a user config and ./mask.toml exist; the user config wins"
                );
            }
            return Ok(Some(path));
        }
        let default = PathBuf::from(DEFAULT_CONFIG_NAME);
        Ok(if default.exists() {
            Some(default)
        } else {
            None
        })
    }

    /// argon2id cost for sealing a new handoff envelope. Unsealing always uses
    /// the cost recorded inside the envelope, so a table sealed elsewhere opens
    /// here regardless of local settings.
    pub fn handoff_kdf(&self) -> crate::gateway::sharing::KdfParams {
        crate::gateway::sharing::KdfParams {
            opslimit: self.handoff_kdf_opslimit,
            memlimit: self.handoff_kdf_memlimit,
        }
    }

    /// Base URL with any trailing slash removed.
    pub fn upstream_base(&self) -> &str {
        self.upstream_base_url.trim_end_matches('/')
    }

    /// Absolute upstream URL for a path relative to the API root
    /// (`chat/completions`, `models`, ...).
    pub fn upstream_url(&self, path: &str) -> String {
        format!("{}/{}", self.upstream_base(), path.trim_start_matches('/'))
    }
}

fn env_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    )
}

/// The operator's config file: `$XDG_CONFIG_HOME/mask/mask.toml`, falling back
/// to `~/.config/mask/mask.toml` (`%APPDATA%\mask\mask.toml` on Windows).
///
/// Keeping the real file here, instead of in a checkout, means an agent working
/// in the repository is never one `read_file` away from the upstream key: the
/// path is outside the project, where agent harnesses deny access by default
/// (see AGENTS.md).
pub fn user_config_path() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("XDG_CONFIG_HOME") {
        let dir = dir.trim();
        if !dir.is_empty() {
            return Some(PathBuf::from(dir).join("mask").join(DEFAULT_CONFIG_NAME));
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    let home = home.trim();
    if home.is_empty() {
        return None;
    }
    let base = if cfg!(windows) {
        std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(home))
    } else {
        PathBuf::from(home).join(".config")
    };
    Some(base.join("mask").join(DEFAULT_CONFIG_NAME))
}

/// Warn when a config that carries an upstream key is readable by others.
///
/// Not an error: a shared machine may have reasons. But the key is the one
/// secret mask cannot pseudonymize, and a mode that lets every process on the
/// box read it makes the rest of the guarantees moot.
fn warn_on_loose_permissions(path: &Path, carries_key: bool) {
    if !carries_key {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    mode = %format!("{mode:o}"),
                    "config file holds an upstream key and is readable beyond its owner; chmod 600 it"
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
