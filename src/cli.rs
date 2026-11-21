//! Shell entrance: the `mask` command.
//!
//! The gateway is the machine's entrance (agents arrive via the proxy); the CLI
//! is the human's entrance from the shell:
//!
//! ```text
//! mask check '...'    # dry-run: what would be masked, no network, no LLM
//! mask chat '...'     # one prompt, through the gateway, restored answer
//! mask status         # reliability indicator panel of a running gateway
//! mask serve          # start the gateway
//! ```
//!
//! Output discipline: masked/checked text goes to stdout so it can be piped;
//! indicators go to stderr so pipes stay clean; exit status is 0 even when PII
//! is detected (detection is the tool working, not failing).

use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};

use crate::detect::dictionary::UserDictionary;
use crate::gateway::config::GatewayConfig;
use crate::session::Session;
use crate::types::{DetectionResult, EntityType};

// --- ANSI --------------------------------------------------------------------

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

fn type_ja(kind: EntityType) -> &'static str {
    kind.ja_label()
}

fn paint(text: &str, color: &str, colorize: bool) -> String {
    if colorize {
        format!("{color}{text}{RESET}")
    } else {
        text.to_string()
    }
}

/// Indicator lamp: green when the guarantee holds, amber otherwise.
fn light(ok: bool, colorize: bool) -> String {
    paint("●", if ok { GREEN } else { YELLOW }, colorize)
}

// --- command line ------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "mask",
    version,
    about = "mask — PII pseudonymization: shell entrance to the mask gateway"
)]
struct Cli {
    /// path to mask.toml (default: $MASK_CONFIG or ./mask.toml)
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// disable ANSI colors
    #[arg(long = "no-color", global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// dry-run mask: show what would be pseudonymized (no network)
    Check {
        /// text to check (or pipe via stdin)
        text: Vec<String>,
    },
    /// one prompt through the gateway; the answer is restored PII
    Chat {
        /// prompt (or pipe via stdin)
        text: Vec<String>,
        /// model for the upstream
        #[arg(long, default_value = "gpt-4o-mini")]
        model: String,
        /// gateway base URL (default: config server host/port)
        #[arg(long)]
        url: Option<String>,
        #[arg(long, default_value_t = 120.0)]
        timeout: f64,
    },
    /// reliability indicator panel of the running gateway
    Status {
        /// gateway base URL (default: config server host/port)
        #[arg(long)]
        url: Option<String>,
        #[arg(long, default_value_t = 5.0)]
        timeout: f64,
        /// raw /status JSON
        #[arg(long)]
        json: bool,
    },
    /// start the gateway (same as `mask-server`)
    #[command(alias = "server")]
    Serve {
        #[arg(long, default_value = "info")]
        log_level: String,
        /// bind address (overrides config/env)
        #[arg(long)]
        host: Option<String>,
        /// port (overrides config/env)
        #[arg(long)]
        port: Option<u16>,
    },
}

pub fn main() -> i32 {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: cannot start runtime: {error}");
            return 1;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            1
        }
    }
}

async fn run(cli: Cli) -> Result<i32> {
    let colorize = !cli.no_color;
    if let Command::Serve {
        log_level,
        host,
        port,
    } = &cli.command
    {
        init_tracing(log_level);
        let mut config = GatewayConfig::load(cli.config.as_deref())?;
        if let Some(host) = host {
            config.host = host.clone();
        }
        if let Some(port) = port {
            config.port = *port;
        }
        crate::gateway::serve(config).await?;
        return Ok(0);
    }

    let config = GatewayConfig::load(cli.config.as_deref())?;
    match cli.command {
        Command::Check { text } => cmd_check(&text, &config, colorize),
        Command::Chat {
            text,
            model,
            url,
            timeout,
        } => cmd_chat(&text, &config, &model, url.as_deref(), timeout, colorize).await,
        Command::Status { url, timeout, json } => {
            cmd_status(&config, url.as_deref(), timeout, json, colorize).await
        }
        Command::Serve { .. } => unreachable!("handled above"),
    }
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_new(level.to_uppercase())
        .or_else(|_| EnvFilter::try_new("info"))
        .expect("static filter is valid");
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

// --- session / config helpers ------------------------------------------------

fn session_for(config: &GatewayConfig) -> Result<Session> {
    let dictionary = match &config.dictionary_path {
        Some(path) => UserDictionary::load(path)
            .with_context(|| format!("cannot load dictionary {}", path.display()))?,
        None => UserDictionary::new(),
    };
    Ok(Session::new(dictionary, config.use_ner))
}

fn gateway_url(config: &GatewayConfig, override_url: Option<&str>) -> String {
    match override_url {
        Some(url) => url.trim_end_matches('/').to_string(),
        None => format!("http://{}:{}", config.host, config.port),
    }
}

fn http_client(timeout_secs: f64) -> Result<reqwest::Client> {
    crate::install_crypto_provider();
    reqwest::Client::builder()
        .timeout(Duration::from_secs_f64(timeout_secs.max(0.1)))
        .build()
        .context("cannot build HTTP client")
}

async fn fetch_snapshot(base_url: &str, token: &str, timeout_secs: f64) -> Result<Value> {
    let client = http_client(timeout_secs)?;
    let mut request = client.get(format!("{base_url}/status"));
    if !token.is_empty() {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.context("gateway unreachable")?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("gateway returned {status}: {}", body.trim());
    }
    serde_json::from_str(&body).context("gateway returned invalid JSON")
}

// --- rendering ---------------------------------------------------------------

fn get_u64(snapshot: &Value, section: &str, key: &str) -> u64 {
    snapshot
        .get(section)
        .and_then(|s| s.get(key))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn get_str<'a>(snapshot: &'a Value, section: &str, key: &str) -> Option<&'a str> {
    snapshot
        .get(section)
        .and_then(|s| s.get(key))
        .and_then(Value::as_str)
}

fn get_bool(snapshot: &Value, section: &str, key: &str) -> bool {
    snapshot
        .get(section)
        .and_then(|s| s.get(key))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Indicator panel for `mask status` and the website widget (pure).
pub fn render_status(snapshot: &Value, colorize: bool) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(paint(
        "mask gateway — reliability indicators",
        BOLD,
        colorize,
    ));
    let uptime = snapshot
        .get("uptime_seconds")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    lines.push(paint(&format!("uptime {uptime:.0}s"), DIM, colorize));
    lines.push(String::new());

    let leak_gate = get_str(snapshot, "posture", "leak_gate").unwrap_or("?");
    let leak_gate_active = get_bool(snapshot, "posture", "leak_gate_active");
    lines.push(format!(
        "{} leak gate        {}{}",
        light(leak_gate_active, colorize),
        leak_gate,
        if leak_gate_active {
            paint("  (fail-closed)", GREEN, colorize)
        } else {
            paint("  (warn only — PII may pass)", RED, colorize)
        }
    ));

    let scope = get_str(snapshot, "posture", "session_scope").unwrap_or("?");
    let records = get_u64(snapshot, "posture", "mapping_records");
    lines.push(format!(
        "{} session         {}  (mapping table: {} records)",
        light(true, colorize),
        scope,
        records
    ));

    let ner = get_bool(snapshot, "posture", "ner");
    lines.push(format!(
        "{} ner             {}",
        light(ner, colorize),
        if ner {
            "built-in name detection on"
        } else {
            "off — rules/dictionary only"
        }
    ));

    let terms = get_u64(snapshot, "posture", "dictionary_terms");
    lines.push(format!(
        "{} dictionary      {} terms",
        light(true, colorize),
        terms
    ));

    let token_set = get_bool(snapshot, "posture", "gateway_token");
    lines.push(format!(
        "{} gateway token  {}",
        light(token_set, colorize),
        if token_set {
            "required (both entrances)"
        } else {
            "not set (localhost only)"
        }
    ));
    lines.push(String::new());

    for (label, key) in [
        ("requests", "requests_total"),
        ("entities masked", "entities_masked"),
        ("tokens restored", "tokens_restored"),
        ("leak blocks", "leak_blocks"),
        ("paths denied", "paths_denied"),
        ("auth denied", "auth_denied"),
    ] {
        lines.push(format!(
            "  {label:<16}{}",
            paint(&get_u64(snapshot, "counts", key).to_string(), DIM, colorize)
        ));
    }
    let unresolved = get_u64(snapshot, "counts", "tokens_unresolved");
    lines.push(format!(
        "  {:<16}{}",
        "unresolved",
        paint(
            &unresolved.to_string(),
            if unresolved == 0 { GREEN } else { RED },
            colorize
        )
    ));
    let repaired = get_u64(snapshot, "counts", "tokens_fuzzy_repaired");
    if repaired > 0 {
        lines.push(format!(
            "  {:<16}{}",
            "repaired tokens",
            paint(&repaired.to_string(), YELLOW, colorize)
        ));
    }
    lines.join("\n")
}

/// Indicator report for `mask check` (pure; text output separate).
pub fn render_check(_masked: &str, result: &DetectionResult, colorize: bool) -> String {
    let mut by_type: Vec<(&'static str, usize)> = Vec::new();
    for entity in &result.entities {
        let label = type_ja(entity.kind);
        match by_type.iter_mut().find(|(name, _)| *name == label) {
            Some((_, count)) => *count += 1,
            None => by_type.push((label, 1)),
        }
    }
    by_type.sort_by_key(|(name, _)| *name);
    let summary = if by_type.is_empty() {
        "  (nothing found — check the dictionary)".to_string()
    } else {
        let parts: Vec<String> = by_type
            .iter()
            .map(|(name, count)| format!("{name} {count}"))
            .collect();
        format!("  ({})", parts.join(", "))
    };
    let lines = [
        format!(
            "  {} detected edge   {} entities{}",
            light(!result.entities.is_empty(), colorize),
            paint(&result.entities.len().to_string(), BOLD, colorize),
            summary
        ),
        format!(
            "  {} ready          phrases like this leave the machine only as {} via the gateway (if the gateway isn't running, run `mask serve` next)",
            light(true, colorize),
            paint("⟦token⟧", DIM, colorize)
        ),
    ];
    lines.join("\n")
}

// --- subcommands -------------------------------------------------------------

fn read_prompt(args: &[String]) -> Option<String> {
    if !args.is_empty() {
        return Some(args.join(" "));
    }
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        return None;
    }
    let mut buffer = String::new();
    match stdin.read_to_string(&mut buffer) {
        Ok(_) if !buffer.is_empty() => Some(buffer),
        _ => None,
    }
}

fn cmd_check(args: &[String], config: &GatewayConfig, colorize: bool) -> Result<i32> {
    let Some(text) = read_prompt(args) else {
        eprintln!("error: no text given (pass it as an argument or pipe via stdin)");
        return Ok(1);
    };
    let mut session = session_for(config)?;
    let (masked, result) = session.masked(&text);
    println!("{masked}");
    eprintln!("{}", paint("[mask check]", DIM, colorize));
    eprintln!("{}", render_check(&masked, &result, colorize));
    Ok(0)
}

async fn cmd_chat(
    args: &[String],
    config: &GatewayConfig,
    model: &str,
    url: Option<&str>,
    timeout: f64,
    colorize: bool,
) -> Result<i32> {
    let Some(prompt) = read_prompt(args) else {
        eprintln!("error: no prompt given");
        return Ok(1);
    };
    let base = gateway_url(config, url);
    let client = http_client(timeout)?;
    let mut request = client
        .post(format!("{base}/v1/chat/completions"))
        .json(&json!({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
        }));
    if !config.gateway_token.is_empty() {
        request = request.bearer_auth(&config.gateway_token);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            eprintln!(
                "error: gateway at {base} unreachable ({}); is `mask serve` running?",
                error
                    .without_url()
                    .to_string()
                    .split(':')
                    .next()
                    .unwrap_or("request failed")
            );
            return Ok(1);
        }
    };
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        let message = serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(|error| error.get("message"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_else(|| body.chars().take(200).collect());
        eprintln!("error: gateway returned {}: {message}", status.as_u16());
        return Ok(1);
    }
    let data: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let mut content = String::new();
    if let Some(choices) = data.get("choices").and_then(Value::as_array) {
        for choice in choices {
            if let Some(text) = choice
                .get("message")
                .and_then(|message| message.get("content"))
                .and_then(Value::as_str)
            {
                content = text.to_string();
                break;
            }
        }
    }
    println!("{content}");

    // Instant-reliability footer: the gateway's own per-request indicators.
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("?")
            .to_string()
    };
    let masked_n = header("X-Mask-Masked");
    let restored_n = header("X-Mask-Restored");
    let unresolved_n = header("X-Mask-Unresolved");
    let clean = unresolved_n == "0" || unresolved_n == "?";
    let line = format!(
        "masked {masked_n} / restored {restored_n} / unresolved {unresolved_n} / leak gate {}",
        header("X-Mask-Leak-Gate")
    );
    eprintln!(
        "{}{}",
        paint("[mask] ", DIM, colorize),
        paint(&line, if clean { GREEN } else { RED }, colorize)
    );
    Ok(0)
}

async fn cmd_status(
    config: &GatewayConfig,
    url: Option<&str>,
    timeout: f64,
    json: bool,
    colorize: bool,
) -> Result<i32> {
    let base = gateway_url(config, url);
    let snapshot = match fetch_snapshot(&base, &config.gateway_token, timeout).await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("error: gateway at {base} unreachable ({error})");
            return Ok(1);
        }
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
        return Ok(0);
    }
    println!("{}", render_status(&snapshot, colorize));
    Ok(0)
}
