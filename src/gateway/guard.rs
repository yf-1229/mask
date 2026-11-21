//! Guards that keep the *running* gateway in a human's hands.
//!
//! mask's data path is built for agents: a harness such as Claude Code connects
//! to the proxy and is supposed to. What an agent must never reach is the
//! operator's own instance — its upstream key, its live mapping table, its
//! process lifetime. Three independent guards cover that, and none of them
//! relies on the calling side behaving:
//!
//! - **Agent host guard** ([`agent_origin`]): a gateway started from an AI
//!   agent's shell is refused. An agent can start its own instance, but not
//!   quietly borrow the human's credentials and terminal. The check reads the
//!   environment *and* walks the parent chain (`/proc` on Linux), because an
//!   agent can clear its own environment but not its parent.
//! - **Operator terminal gate** ([`mint_admin_token`], [`announce_operator_channel`]):
//!   `/admin/export` and `/admin/import` require a token that is printed once,
//!   to the controlling terminal, and never stored or logged. A process with no
//!   terminal (a service, CI, an agent's pipe) leaves the admin channel closed.
//! - **Loopback name check** ([`host_is_local`]): a request whose `Host` header
//!   is not a loopback name is refused, so a browser-driven DNS-rebinding page
//!   cannot address the admin channel by a name that resolves to 127.0.0.1.
//!
//! Design constraints, in the spirit of [`crate::gateway::indicators`]:
//! nothing here logs a token, and nothing here reports a value — only refusals
//! are counted.

use axum::http::{header, HeaderMap};

use crate::replace::random_hex;

/// Environment markers set by an AI agent for the commands it runs.
///
/// Each entry is documented with the tool that sets it. The list is
/// deliberately explicit rather than a heuristic (`*_AGENT=*` would also match
/// an operator's own scripts): a false negative here costs a guard that did not
/// fire, a false positive costs an operator one flag.
pub const AGENT_MARKERS: &[&str] = &[
    // Mistral Vibe: set for every command the agent runs on the host.
    "VIBE_SESSION",
    // Claude Code.
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    // Cursor's agent mode.
    "CURSOR_AGENT",
    // OpenAI Codex CLI sandbox.
    "CODEX_SANDBOX",
    // Gemini CLI.
    "GEMINI_CLI",
    // GitHub Copilot's agent mode.
    "COPILOT_AGENT",
    // OpenCode.
    "OPENCODE_SESSION",
    // Aider.
    "AIDER_SESSION",
];

/// Length of an operator token in bytes (hex, so twice this many characters).
pub const ADMIN_TOKEN_BYTES: usize = 16;

/// Header the operator token travels in on `/admin/*`.
pub const ADMIN_TOKEN_HEADER: &str = "x-mask-admin";

/// The AI-agent marker visible in the current environment, if any.
pub fn agent_marker() -> Option<&'static str> {
    agent_marker_with(|name| std::env::var(name).ok())
}

/// [`agent_marker`] with an injectable environment lookup, so the detection
/// itself is testable without mutating the process environment.
pub fn agent_marker_with(mut get: impl FnMut(&str) -> Option<String>) -> Option<&'static str> {
    AGENT_MARKERS
        .iter()
        .copied()
        .find(|name| get(name).is_some_and(|value| !value.trim().is_empty()))
}

/// Process names that host an AI agent. Used for the ancestry walk, where the
/// environment cannot be trusted: an agent can `env -u VIBE_SESSION` its own
/// child, but the agent process itself is still its parent — and on Linux that
/// parent's environment and command name are readable from `/proc`.
pub const AGENT_PROCESS_NAMES: &[&str] = &[
    "claude",
    "codex",
    "cursor-agent",
    "opencode",
    "aider",
    "gemini",
    "vibe",
    "copilot",
    "crush",
    "amp",
    "goose",
];

/// How far up the process tree to look. An agent's shell is a child of the
/// agent; two or three generations cover a wrapper such as `sh -c` or `cargo`.
#[cfg(target_os = "linux")] // the walk itself is /proc-based; elsewhere it is dead code
const ANCESTRY_DEPTH: usize = 12;

/// What says an AI agent owns the current shell, if anything.
///
/// Returns a human-readable origin: the marker name, or the ancestor process
/// that named itself an agent. Environment markers are checked first because
/// they are cheap and precise; the ancestry walk is what survives an agent that
/// clears them.
pub fn agent_origin() -> Option<String> {
    if let Some(marker) = agent_marker() {
        return Some(format!("{marker} is set"));
    }
    agent_ancestry()
}

/// Walk the parent chain looking for an agent, by command name and by the
/// environment that process was started with.
///
/// Linux only: `/proc` is what makes it possible without spawning anything.
/// Elsewhere the environment markers in [`agent_marker`] are the whole check,
/// which is why `--allow-agent-host` exists as an explicit escape.
pub fn agent_ancestry() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let me = std::process::id();
        let mut pid = me;
        for _ in 0..ANCESTRY_DEPTH {
            let (comm, ppid) = proc_stat(pid)?;
            if AGENT_PROCESS_NAMES
                .iter()
                .any(|name| comm.eq_ignore_ascii_case(name))
            {
                return Some(format!("parent process {comm:?}"));
            }
            if pid != me {
                if let Some(marker) = proc_environ_marker(pid) {
                    return Some(format!("{marker} in the environment of pid {pid}"));
                }
            }
            if ppid <= 1 || ppid == pid {
                break;
            }
            pid = ppid;
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// `comm` and `ppid` for a pid, from `/proc/<pid>/stat`.
#[cfg(target_os = "linux")]
fn proc_stat(pid: u32) -> Option<(String, u32)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `comm` is parenthesised and may itself contain spaces or parentheses, so
    // parse from the last ')' rather than splitting on whitespace.
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let comm = stat.get(open + 1..close)?.to_string();
    let rest = stat.get(close + 1..)?;
    let ppid = rest.split_whitespace().nth(1)?.parse().ok()?;
    Some((comm, ppid))
}

/// The first agent marker found in another process's environment.
#[cfg(target_os = "linux")]
fn proc_environ_marker(pid: u32) -> Option<&'static str> {
    let environ = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    let text = String::from_utf8_lossy(&environ);
    AGENT_MARKERS.iter().copied().find(|name| {
        text.split('\0').any(|entry| match entry.split_once('=') {
            Some((key, value)) => key == *name && !value.trim().is_empty(),
            None => false,
        })
    })
}

/// A fresh operator token. Printed once to the terminal, kept in memory only.
///
/// `None` when the OS CSPRNG is unavailable; the caller then leaves the admin
/// channel closed rather than minting a predictable token.
pub fn mint_admin_token() -> Option<String> {
    std::panic::catch_unwind(random_hex_token).ok()
}

fn random_hex_token() -> String {
    random_hex(ADMIN_TOKEN_BYTES)
}

/// Print the operator token to the process's controlling terminal.
///
/// Deliberately *not* stdout/stderr: `mask serve` is often launched with its
/// output redirected to a log file, and that log is exactly the artefact an
/// agent could read back. `/dev/tty` (Unix) and `CONOUT$` (Windows) address the
/// terminal the human is looking at, which is empty when the process was
/// started by a service manager or behind a pipe — and then the admin channel
/// stays closed, which is the intended fail-closed outcome.
///
/// Returns whether the token was actually delivered.
pub fn announce_operator_channel(token: &str) -> bool {
    use std::io::Write;

    let message = format!(
        "\n mask: admin channel open (this terminal only)\n\
         \x20 /admin/export and /admin/import require  {ADMIN_TOKEN_HEADER}: {token}\n\
         \x20 the token lives in this process only: it is not written to disk, not logged,\n\
         \x20 and not reported by /status. Restarting the gateway replaces it.\n\n"
    );

    #[cfg(unix)]
    let opened = std::fs::OpenOptions::new().write(true).open("/dev/tty");
    #[cfg(not(unix))]
    let opened = std::fs::OpenOptions::new().write(true).open("CONOUT$");

    match opened {
        Ok(mut tty) => tty.write_all(message.as_bytes()).is_ok() && tty.flush().is_ok(),
        Err(_) => false,
    }
}

/// Whether the request addresses the gateway by a loopback name.
///
/// The socket is already loopback-bound by default; this closes the *name*
/// side: a page on `evil.example` that resolves to 127.0.0.1 (DNS rebinding)
/// reaches the admin channel with `Host: evil.example`. The name is parsed as
/// an IP address rather than string-matched, so `127.0.0.1.evil.example` does
/// not pass for loopback.
///
/// A request with no `Host` header at all is refused: HTTP/1.1 requires one,
/// and the only clients that omit it are hand-rolled. Fail closed.
pub fn host_is_local(headers: &HeaderMap) -> bool {
    let Some(value) = headers.get(header::HOST) else {
        return false;
    };
    let Ok(raw) = value.to_str() else {
        return false;
    };
    let name = raw.trim();
    if let Some(ip) = parse_host_ip(name) {
        return ip.is_loopback();
    }
    // A name with a port (`localhost:8080`), then the bare name.
    if let Some((host, port)) = name.rsplit_once(':') {
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return match parse_host_ip(host) {
                Some(ip) => ip.is_loopback(),
                None => host.eq_ignore_ascii_case("localhost"),
            };
        }
    }
    name.eq_ignore_ascii_case("localhost")
}

/// Parse a `Host` name as an IP address, bracketed IPv6 literal or not.
///
/// String comparison is not enough: `127.0.0.1.evil.example` starts with the
/// loopback literal and is exactly the DNS-rebinding shape this check exists
/// for, so the name has to be an address, not merely to look like one.
fn parse_host_ip(raw: &str) -> Option<std::net::IpAddr> {
    let without_brackets = match raw.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map(|(literal, _)| literal)?,
        None => raw,
    };
    without_brackets.parse().ok()
}

/// Operator-facing refusal text when an agent tries to host the gateway.
pub fn agent_host_refusal(marker: &str) -> String {
    format!(
        "refusing to start the gateway: this shell belongs to an AI agent ({marker}).\n\
         `mask serve` is an operator-run process: it holds the upstream API key and the live\n\
         mapping table. Start it from your own terminal, or pass --allow-agent-host (or set\n\
         MASK_ALLOW_AGENT_HOST=1) if this instance really is meant to be agent-hosted."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_the_first_agent_marker_present() {
        let marker = agent_marker_with(|name| match name {
            "CLAUDECODE" => Some("1".to_string()),
            _ => None,
        });
        assert_eq!(marker, Some("CLAUDECODE"));
        assert_eq!(agent_marker_with(|_| None), None);
        // An empty value is not a session: shells leave stray variables behind.
        assert_eq!(agent_marker_with(|_| Some(String::new())), None);
    }

    #[test]
    fn host_is_local_parses_the_name_instead_of_matching_a_prefix() {
        let mut headers = HeaderMap::new();
        // No Host header: HTTP/1.1 requires one, so refuse rather than guess.
        assert!(!host_is_local(&headers));

        for good in [
            "localhost",
            "localhost:8080",
            "LOCALHOST:1",
            "127.0.0.1:8080",
            "127.0.0.1",
            "[::1]:8080",
            "[::1]",
            "127.4.5.6:9",
        ] {
            headers.insert(header::HOST, good.parse().unwrap());
            assert!(host_is_local(&headers), "{good} should be local");
        }
        for bad in [
            // The rebinding shapes: a name that merely starts with the literal.
            "127.0.0.1.evil.example",
            "localhost.evil.example",
            "evil.example:8080",
            "mask.example.com",
            "0.0.0.0:8080",
            "[::]:8080",
            "not-an-ip",
        ] {
            headers.insert(header::HOST, bad.parse().unwrap());
            assert!(!host_is_local(&headers), "{bad} should not be local");
        }
    }

    #[test]
    fn minted_tokens_are_hex_and_fresh() {
        let first = mint_admin_token().expect("CSPRNG");
        let second = mint_admin_token().expect("CSPRNG");
        assert_eq!(first.len(), ADMIN_TOKEN_BYTES * 2);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn the_refusal_names_the_origin_and_the_override() {
        let text = agent_host_refusal("VIBE_SESSION is set");
        assert!(text.contains("VIBE_SESSION"));
        assert!(text.contains("--allow-agent-host"));
    }

    /// The ancestry walk parses this very process, so it must at least find us:
    /// a non-empty command name and a real parent.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_ancestry_walk_reads_proc_for_this_process() {
        let (comm, ppid) = proc_stat(std::process::id()).expect("own stat");
        assert!(!comm.is_empty(), "comm should not be empty");
        assert!(ppid > 0, "ppid should be a real process");
    }
}
