//! Shell entrance: the `mask` command.
//!
//! The gateway is the machine's entrance (agents arrive via the proxy); the CLI
//! is the human's entrance from the shell:
//!
//! ```text
//! mask check '...'    # dry-run: what would be masked, no network, no LLM
//! mask audit FILE     # dry-run over files, plus likely-miss line numbers
//! mask chat '...'     # one prompt, through the gateway, restored answer
//! mask status         # reliability indicator panel of a running gateway
//! mask dict add ...   # register a term; a running gateway picks it up live
//! mask serve          # start the gateway
//! ```
//!
//! Output discipline: masked/checked text goes to stdout so it can be piped;
//! indicators go to stderr so pipes stay clean; exit status is 0 even when PII
//! is detected (detection is the tool working, not failing).

use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};

use crate::detect::dictionary::{append_or_update, AddOutcome, ParseReport, UserDictionary};
use crate::detect::suspect::{scan as scan_suspicions, Suspicion};
use crate::detect::Explanation;
use crate::gateway::config::GatewayConfig;
use crate::session::Session;
use crate::types::{DetectionResult, EntityType, Source};

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
        /// print the rule that accepted each span (detection unchanged)
        #[arg(long)]
        explain: bool,
    },
    /// dry-run over files: mask, then point at likely detection misses
    Audit {
        /// files to audit ('-' reads stdin; default: stdin)
        files: Vec<PathBuf>,
        /// exit 1 when a suspicious span is found (for docs CI)
        #[arg(long)]
        strict: bool,
        /// report only; do not print the masked text
        #[arg(long)]
        no_output: bool,
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
    /// register a term, list terms, or validate the dictionary file
    Dict {
        #[command(subcommand)]
        action: DictAction,
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
        /// start the gateway even though this shell belongs to an AI agent
        #[arg(long)]
        allow_agent_host: bool,
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
        allow_agent_host,
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
        refuse_agent_host(&config, *allow_agent_host)?;
        crate::gateway::serve(config).await?;
        return Ok(0);
    }

    let config = GatewayConfig::load(cli.config.as_deref())?;
    match cli.command {
        Command::Check { text, explain } => cmd_check(&text, explain, &config, colorize),
        Command::Audit {
            files,
            strict,
            no_output,
        } => cmd_audit(&files, strict, no_output, &config, colorize),
        Command::Dict { action } => match action {
            DictAction::Add { term, kind, file } => {
                cmd_dict_add(&term, &kind, file.as_deref(), &config, colorize)
            }
            DictAction::List { file } => cmd_dict_list(file.as_deref(), &config, colorize),
            DictAction::Check { file } => cmd_dict_check(file.as_deref(), &config, colorize),
        },
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

/// The gateway is an operator-run process: it holds the upstream key and the
/// live mapping table, so an AI agent's shell may not start it by accident.
///
/// Agents are welcome as *clients* of a gateway a human started. This check
/// covers the other direction — an agent quietly standing up an instance with
/// the human's credentials — and is deliberately loud and overridable rather
/// than silent.
fn refuse_agent_host(config: &GatewayConfig, allow_agent_host: bool) -> Result<()> {
    if !config.agent_host_guard || allow_agent_host {
        return Ok(());
    }
    if std::env::var("MASK_ALLOW_AGENT_HOST").is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes"
        )
    }) {
        return Ok(());
    }
    match crate::gateway::guard::agent_origin() {
        Some(origin) => bail!("{}", crate::gateway::guard::agent_host_refusal(&origin)),
        None => Ok(()),
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

#[derive(Subcommand, Debug)]
enum DictAction {
    /// add a term (or correct its type); a running gateway merges it live
    Add {
        /// the term to register
        term: String,
        /// entity type: person, org, location, address, phone, email, account
        #[arg(short = 't', long = "type", default_value = "person")]
        kind: String,
        /// dictionary file (default: [mask].dictionary, else ./dictionary.tsv)
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// print every registered term
    List {
        /// dictionary file (default: [mask].dictionary, else ./dictionary.tsv)
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// validate the file; reports counts and line numbers, never values
    Check {
        /// dictionary file (default: [mask].dictionary, else ./dictionary.tsv)
        #[arg(long)]
        file: Option<PathBuf>,
    },
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
    let reloads = get_u64(snapshot, "counts", "dictionary_reloads");
    let live = if reloads > 0 {
        paint(
            &format!(
                "  ({reloads} live reload{})",
                if reloads == 1 { "" } else { "s" }
            ),
            DIM,
            colorize,
        )
    } else {
        String::new()
    };
    lines.push(format!(
        "{} dictionary      {} terms{}",
        light(true, colorize),
        terms,
        live
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

    // The admin channel: whether an operator token exists in this process. A
    // green lamp means "the table leaves only if you ask from this terminal".
    let admin = get_str(snapshot, "posture", "admin_channel").unwrap_or("off");
    lines.push(format!(
        "{} admin channel  {}",
        light(admin == "human", colorize),
        match admin {
            "human" => "human (export/import/reload need the terminal token)",
            "closed" => "closed — no operator terminal (admin refused; dictionary reload is local)",
            _ => "off (admin_require_human = false)",
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
        ("admin refusals", "admin_gate_refusals"),
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

/// Counts per entity type, ordered by label; shared by `check` and `audit`.
fn type_counts(result: &DetectionResult) -> Vec<(&'static str, usize)> {
    let mut by_type: Vec<(&'static str, usize)> = Vec::new();
    for entity in &result.entities {
        let label = type_ja(entity.kind);
        match by_type.iter_mut().find(|(name, _)| *name == label) {
            Some((_, count)) => *count += 1,
            None => by_type.push((label, 1)),
        }
    }
    by_type.sort_by_key(|(name, _)| *name);
    by_type
}

fn type_summary(by_type: &[(&'static str, usize)], empty: &str) -> String {
    if by_type.is_empty() {
        empty.to_string()
    } else {
        let parts: Vec<String> = by_type
            .iter()
            .map(|(name, count)| format!("{name} {count}"))
            .collect();
        format!("  ({})", parts.join(", "))
    }
}

/// Indicator report for `mask check` (pure; text output separate).
pub fn render_check(_masked: &str, result: &DetectionResult, colorize: bool) -> String {
    let by_type = type_counts(result);
    let summary = type_summary(&by_type, "  (nothing found — check the dictionary)");
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

/// Report for `mask check --explain`: one line per accepted span, with the
/// layer and rule that accepted it. Offsets and labels only — the matched text
/// is deliberately absent so the report can be pasted into an issue.
pub fn render_explain(explanations: &[Explanation]) -> String {
    if explanations.is_empty() {
        return "  (nothing accepted — no rule matched)".to_string();
    }
    let mut lines = vec!["    span        layer  kind      rule".to_string()];
    for explanation in explanations {
        let entity = &explanation.entity;
        lines.push(format!(
            "  {:>4}..{:<4} {:<6} {:<9} {}",
            entity.start,
            entity.end,
            source_label(entity.source),
            entity.kind.as_str(),
            explanation.reason
        ));
    }
    lines.join("\n")
}

fn source_label(source: Source) -> &'static str {
    match source {
        Source::Rule => "rule",
        Source::Dict => "dict",
        Source::Ner => "ner",
    }
}

/// Report for `mask audit` (pure). Locations and counts only: the audited
/// values never enter the report, so it can be pasted into an issue.
pub fn render_audit(
    label: &str,
    text: &str,
    result: &DetectionResult,
    suspicions: &[Suspicion],
    colorize: bool,
) -> String {
    let by_type = type_counts(result);
    let mut lines = vec![
        format!(
            "{} audit           {}  ({} char{})",
            light(true, colorize),
            paint(label, DIM, colorize),
            text.chars().count(),
            if text.chars().count() == 1 { "" } else { "s" }
        ),
        format!(
            "  entities        {}{}",
            result.entities.len(),
            type_summary(&by_type, "  (nothing found — check the dictionary)")
        ),
        format!(
            "{} suspicious      {}{}",
            light(suspicions.is_empty(), colorize),
            suspicions.len(),
            if suspicions.is_empty() {
                String::new()
            } else {
                paint("  (unmasked name before an honorific)", YELLOW, colorize)
            }
        ),
    ];
    for hint in suspicions.iter().take(20) {
        lines.push(format!("    line {}", hint.line));
    }
    if suspicions.len() > 20 {
        lines.push(format!("    … {} more", suspicions.len() - 20));
    }
    if !suspicions.is_empty() {
        lines.push(format!(
            "  next            {} and re-run: the line stays unmasked until then",
            paint("`mask dict add <term> person`", DIM, colorize)
        ));
    }
    lines.join("\n")
}

/// Validation report for `mask dict check` (pure). Counts and line numbers
/// only: the file's contents never enter the output, so it can be pasted into
/// a bug report.
pub fn render_dict_check(path: &Path, report: &ParseReport, colorize: bool) -> String {
    let ok = report.skipped == 0;
    let mut lines = vec![
        format!(
            "{} dictionary      {}  ({} term{})",
            light(ok, colorize),
            paint(&path.display().to_string(), DIM, colorize),
            report.terms,
            if report.terms == 1 { "" } else { "s" }
        ),
        format!("{} skipped lines   {}", light(ok, colorize), report.skipped),
    ];
    if !report.skipped_lines.is_empty() {
        let shown: Vec<String> = report
            .skipped_lines
            .iter()
            .take(10)
            .map(usize::to_string)
            .collect();
        let more = if report.skipped_lines.len() > 10 {
            format!(" … {} more", report.skipped_lines.len() - 10)
        } else {
            String::new()
        };
        lines.push(format!(
            "  {}",
            paint(
                &format!("line {}{more}", shown.join(", ")),
                YELLOW,
                colorize
            )
        ));
    }
    lines.join("\n")
}

// --- subcommands -------------------------------------------------------------

fn read_prompt(args: &[String]) -> Option<String> {
    if !args.is_empty() {
        return Some(args.join(" "));
    }
    read_stdin_text()
}

/// Read all of stdin when it is a pipe or a file, never when it is a terminal.
fn read_stdin_text() -> Option<String> {
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

fn cmd_check(
    args: &[String],
    explain: bool,
    config: &GatewayConfig,
    colorize: bool,
) -> Result<i32> {
    let Some(text) = read_prompt(args) else {
        eprintln!("error: no text given (pass it as an argument or pipe via stdin)");
        return Ok(1);
    };
    let mut session = session_for(config)?;
    let (masked, result) = session.masked(&text);
    // Detection already ran in `masked`; explain re-runs the same layers for
    // labels only, so enabling it cannot change what is masked.
    let explanations = explain.then(|| session.explain(&text));
    println!("{masked}");
    eprintln!("{}", paint("[mask check]", DIM, colorize));
    eprintln!("{}", render_check(&masked, &result, colorize));
    if let Some(explanations) = explanations {
        eprintln!("{}", paint("[explain]", DIM, colorize));
        eprintln!("{}", render_explain(&explanations));
    }
    Ok(0)
}

fn cmd_audit(
    files: &[PathBuf],
    strict: bool,
    no_output: bool,
    config: &GatewayConfig,
    colorize: bool,
) -> Result<i32> {
    let inputs = read_audit_inputs(files)?;
    let mut session = session_for(config)?;
    let multiple = inputs.len() > 1;
    let mut suspicious = 0usize;
    for (label, text) in &inputs {
        let (masked, result) = session.masked(text);
        let hints = scan_suspicions(text, &result);
        suspicious += hints.len();
        if !no_output {
            if multiple {
                println!("==> {label} <==");
            }
            println!("{masked}");
            if multiple {
                println!();
            }
        }
        eprintln!("{}", render_audit(label, text, &result, &hints, colorize));
    }
    if strict && suspicious > 0 {
        return Ok(1);
    }
    Ok(0)
}

/// Files plus `-` for stdin, or stdin alone when no path is given.
fn read_audit_inputs(files: &[PathBuf]) -> Result<Vec<(String, String)>> {
    if files.is_empty() {
        let Some(text) = read_stdin_text() else {
            bail!("no input: name files or pipe text via stdin");
        };
        return Ok(vec![("stdin".to_string(), text)]);
    }
    let mut inputs: Vec<(String, String)> = Vec::new();
    for path in files {
        if path.to_str() == Some("-") {
            let Some(text) = read_stdin_text() else {
                bail!("cannot read '-' from a terminal: pipe the text");
            };
            inputs.push(("stdin".to_string(), text));
            continue;
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        inputs.push((path.display().to_string(), text));
    }
    Ok(inputs)
}

/// Where `mask dict ...` reads and writes: `--file`, then `[mask].dictionary`,
/// then the working-directory convention `./dictionary.tsv`.
fn dictionary_path(config: &GatewayConfig, file: Option<&Path>) -> PathBuf {
    file.map(Path::to_path_buf)
        .or_else(|| config.dictionary_path.clone())
        .unwrap_or_else(|| PathBuf::from("dictionary.tsv"))
}

fn cmd_dict_add(
    term: &str,
    kind: &str,
    file: Option<&Path>,
    config: &GatewayConfig,
    colorize: bool,
) -> Result<i32> {
    let Some(kind) = EntityType::from_name(kind) else {
        let names: Vec<&str> = EntityType::ALL.iter().map(|kind| kind.as_str()).collect();
        eprintln!(
            "error: unknown type {kind:?}; expected one of {}",
            names.join(", ")
        );
        return Ok(2);
    };
    let path = dictionary_path(config, file);
    let outcome = match append_or_update(&path, term, kind) {
        Ok(outcome) => outcome,
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
            eprintln!("error: {error}");
            return Ok(2);
        }
        Err(error) => {
            return Err(error).with_context(|| format!("cannot write {}", path.display()))
        }
    };
    let terms = UserDictionary::load(&path)
        .with_context(|| format!("cannot read {}", path.display()))?
        .size();
    let verb = match outcome {
        AddOutcome::Added => format!("added {kind}"),
        AddOutcome::Updated { from: Some(from) } => format!("updated {from} -> {kind}"),
        AddOutcome::Updated { from: None } => format!("repaired -> {kind}"),
        AddOutcome::Unchanged => format!("already registered as {kind}"),
    };
    println!(
        "{verb} {}  {}  ({} term{})",
        term.trim(),
        paint(&path.display().to_string(), DIM, colorize),
        terms,
        if terms == 1 { "" } else { "s" }
    );
    match config.dictionary_path.as_deref() {
        None => eprintln!(
            "note: mask.toml has no [mask].dictionary — add `dictionary = \"{}\"` so the gateway loads this file",
            path.display()
        ),
        Some(configured) if !same_file(configured, &path) => eprintln!(
            "note: the gateway watches {}; this edit is not live. Pass --file to match",
            configured.display()
        ),
        Some(_) => eprintln!(
            "{}",
            paint(
                "[mask] a running gateway merges additions on the next request; removals take effect on restart",
                DIM,
                colorize
            )
        ),
    }
    Ok(0)
}

/// Same file, even when one path is relative and the other is not.
fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

fn cmd_dict_list(file: Option<&Path>, config: &GatewayConfig, colorize: bool) -> Result<i32> {
    let path = dictionary_path(config, file);
    let dictionary = UserDictionary::load(&path)
        .with_context(|| format!("cannot load dictionary {}", path.display()))?;
    if dictionary.is_empty() {
        eprintln!("(no terms in {})", path.display());
        return Ok(0);
    }
    let mut entries: Vec<(&str, EntityType)> = dictionary.entries().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (term, kind) in entries {
        println!("{term}\t{kind}");
    }
    eprintln!(
        "{}",
        paint(
            &format!("[mask] {} term(s) in {}", dictionary.size(), path.display()),
            DIM,
            colorize
        )
    );
    Ok(0)
}

fn cmd_dict_check(file: Option<&Path>, config: &GatewayConfig, colorize: bool) -> Result<i32> {
    let path = dictionary_path(config, file);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "error: dictionary {} not found (nothing registered yet)",
                path.display()
            );
            return Ok(1);
        }
        Err(error) => return Err(error).with_context(|| format!("cannot read {}", path.display())),
    };
    let (_, report) = UserDictionary::parse_report(&text);
    println!("{}", render_dict_check(&path, &report, colorize));
    if report.skipped > 0 {
        eprintln!(
            "{}",
            paint(
                "[mask] skipped lines would be ignored by the gateway; fix them or they never mask",
                YELLOW,
                colorize
            )
        );
        return Ok(1);
    }
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
