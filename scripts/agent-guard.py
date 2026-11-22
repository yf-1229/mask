#!/usr/bin/env python3
"""agent-guard — refuse the calls that would touch the operator's running mask.

The rules are the ones in AGENTS.md, expressed as code so they hold even when a
model has not read that file, drifted from it, or decided a guard did not apply
to the task at hand. Two harnesses feed this script the same JSON on stdin:

- Vibe (`pre_tool`):  {"hook_event_name": "pre_tool", "tool_name": "file_system.bash",
                       "tool_input": {"command": "…"}}
- Claude Code (`PreToolUse`): {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": {"command": "…"}}

Vibe reads a decision from stdout (`{"decision": "deny", "reason": "…"}`,
exit 0); Claude Code blocks on exit code 2 with the reason on stderr. A
`session_start` payload gets the contract injected as context, so the boundary
is stated at the top of the session too.

Two design rules worth keeping when you edit this file:

1. **Reviewing the code is not a violation.** A guard that refuses
   `rg -n "mask.toml" src/` stops the agent from doing the job it was hired for,
   and an agent that cannot read the source will route around the guard. So a
   command that only *searches* this repository (a repo path, no reader/writer
   verb, no connection) is allowed even though it names an operator file.
2. **Matching is on what runs, not on what is written.** Write and edit tools
   are judged by their target path only: documentation that *describes*
   `mask serve` is allowed, writing to `mask.toml` is not.
3. **A command is judged by its shape, not by a substring of the line.** The
   `mask` rules anchor on the executable token (see `mask_subcommand`), because
   this checkout is itself called `mask`: a bare `\bmask\b … \bstatus\b` over the
   line refused `cd …/mask && git status`, which is how an agent gets work done.
   Path spellings of the executable (`~/.local/bin/mask`, `./target/release/mask`)
   still match, so the anchor is not a way around the guard.

Usage:
    agent-guard.sh                 # hook mode: JSON on stdin
    agent-guard.sh --check "text"  # human check: exit 1 when the text is refused
    agent-guard.sh --self-test     # run the built-in cases
"""

from __future__ import annotations

import json
import re
import sys

# --- vocabulary --------------------------------------------------------------

#: Where the repository keeps its own code and docs. Naming one of these while
#: merely searching is reviewing, not reaching for the operator's instance.
REPO_PATH = re.compile(r"(^|[\s\"'=])(\./)?(src|tests|docs|site|scripts|\.vibe|\.claude)/")

#: Verbs that read or write a named path. `grep`/`rg` are deliberately absent:
#: searching for the string `mask.toml` is the opposite of reading the file.
IO_VERB = re.compile(
    r"\b(cat|less|more|head|tail|sed|awk|strings|xxd|od|cp|mv|rm|chmod|chown|touch|"
    r"tee|dd|install|truncate|gzip|tar|zip|scp|rsync|vi|vim|nvim|nano|emacs|code|"
    r"open|bat|python3?\s+-c|sh\s+-c)\b"
)

#: Verbs that reach the network. A port number is only interesting next to one.
CONNECT = re.compile(r"\b(curl|wget|nc|ncat|netcat|socat|telnet|ssh|http|xh|httpie|"
                     r"lsof|ss|netstat|nmap|dig|host|ping)\b")

#: The gateway port, however it is spelled.
PORT = re.compile(r"(127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)\s*:\s*8080|:\s*8080\b|\b8080\b")

#: Operator files: names only, so the same pattern serves quotes and paths.
OPERATOR_FILE = re.compile(
    r"mask\.toml(?!\.example)|\bdictionary\.tsv\b|\.maskbox\b|\.config/mask|"
    r"(^|[/\s\"'=])\.env\b"
)

#: Where a shell starts a command: line start, or after a separator (and an
#: opening quote, so `sh -c "mask serve"` is still read as a command).
CMD_START = r"""(?:^|[\s;&|("'`$])"""

#: The `mask` executable, optionally addressed through a path (`~/.local/bin/mask`,
#: `./target/release/mask`, `mask.exe`). A path prefix is allowed on purpose:
#: spelling the path out is the obvious way around the guard, so it must not work.
MASK_EXE = r"(?:[^\s;&|]*/)?mask(?:\.exe)?"

#: Flags and their values between the executable and the subcommand
#: (`mask --config ~/.config/mask/mask.toml status`). Deliberately unable to
#: cross a newline: hooks see whole scripts, so `cd …/mask` on one line and
#: `git status` on the next must not be glued into a command nobody ran.
MASK_ARGS = r"(?:[^\S\n]+[^\s;&|]+)*"


def mask_subcommand(*names: str) -> re.Pattern[str]:
    """Match `mask <subcommand …>` only where the shell would run it.

    The checkout, the user's config directory and this file's own examples all
    contain the word `mask` on paths. A bare `\\bmask\\b … \\bstatus\\b` over the
    line therefore reads `cd …/Documents/mask && git status` as `mask status`
    and refuses ordinary work — the reason this is anchored on the executable
    token instead. The cost is that a command whose *argument* is a path ending
    in `/mask` followed by one of these words (`git -C …/mask status`) is
    refused too; that is the fail-closed direction, and `cd` first works.
    """
    return re.compile(
        CMD_START + MASK_EXE + MASK_ARGS + r"[^\S\n]+(?:" + "|".join(names) + r")\b",
        re.IGNORECASE,
    )


#: Rules that do not need a path or a verb to matter: the process itself, its
#: controls, and the switches that turn the guards off.
HARD_RULES: list[tuple[re.Pattern[str], str]] = [
    (
        mask_subcommand("serve", "server"),
        "starting the gateway is a human action: it holds the upstream key and the "
        "live pseudonym table. Ask the operator to run `mask serve`.",
    ),
    (
        re.compile(r"\bcargo\s+run\b[^\n]*\bserve\b", re.IGNORECASE),
        "starting the gateway is a human action: it holds the upstream key and the "
        "live pseudonym table. Ask the operator to run `mask serve`.",
    ),
    (
        mask_subcommand("chat", "status"),
        "that talks to the operator's running gateway (their key, their session). "
        "`mask check \"…\"` is local and fine; ask the operator for the rest.",
    ),
    (
        re.compile(r"\b(pkill|killall)\b[^\n]*\bmask\b|\bkill\b[^\n]*\bmask\b", re.IGNORECASE),
        "killing the gateway discards every pseudonym: the next turn would send real "
        "values upstream unmasked. Never signal the operator's process.",
    ),
    (
        re.compile(r"/admin/(export|import)"),
        "/admin/export hands out the live mapping table; the operator token exists "
        "only on their terminal. Not from an agent.",
    ),
    (
        re.compile(r"--allow-agent-host|MASK_ALLOW_AGENT_HOST|MASK_AGENT_HOST_GUARD|"
                   r"MASK_ADMIN_REQUIRE_HUMAN|--no-admin-require-human"),
        "these switch off the guard that keeps the gateway in human hands. If the task "
        "really needs it, ask the operator to change it themselves.",
    ),
    (
        re.compile(r"/proc/\d+/(environ|mem|cmdline)|\bpgrep\b[^\n]*\bmask\b", re.IGNORECASE),
        "reading another process's environment, memory or command line is how an agent "
        "lifts the upstream key or the operator token out of the running gateway. Ask "
        "the human for what you need.",
    ),
    (
        re.compile(r"leak_gate\s*[=:]\s*[\"']?warn|admin_allow_remote\s*[=:]\s*true",
                   re.IGNORECASE),
        "loosening the leak gate or the admin locality is a human's trade-off to make, "
        "in their own config. Propose it; do not write it.",
    ),
]

#: Rules that need a connection verb to be interesting: a port number in prose,
#: in a test name or in a `git log --grep` is not a connection.
CONNECT_RULES: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"\blsof\b[^\n]*\s-i|\b(ss|netstat)\b[^\n]*-[a-z]*[tln]", re.IGNORECASE),
        "listing listening sockets is how a probe starts. The gateway port belongs to "
        "the operator; ask them whether it is running.",
    ),
    (
        PORT,
        "the gateway port belongs to the operator. Do not connect to, probe or scan it "
        "(that includes lsof, ss, netstat, nc, socat and port scans).",
    ),
]

CONTRACT = (
    "Repository contract (AGENTS.md): the operator's running `mask serve`, its "
    "mask.toml / ~/.config/mask/mask.toml, its dictionary.tsv and *.maskbox files, and "
    "its /admin/* endpoints are off limits — do not start, stop, probe, read or export "
    "from them. Start the gateway only when the human explicitly asks. Work on the code "
    "instead: cargo fmt / clippy / test starts its own loopback gateways with mock "
    "upstreams. When a guard blocks you, report which one and ask."
)

#: Tool-input keys worth matching for a command-like tool.
COMMAND_KEYS = ("command", "cmd", "code", "content", "url", "query")

#: Tool-input keys worth matching for a file tool: the target only, never the
#: text being written (documentation may describe the gateway).
PATH_KEYS = ("file_path", "path", "paths", "notebook_path")


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(_strings(item))
        return out
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            out.extend(_strings(item))
        return out
    return []


def _reviewing(text: str) -> bool:
    """True when the text only searches this repository."""
    return bool(REPO_PATH.search(text)) and not IO_VERB.search(text) and not CONNECT.search(text)


def inspect(text: str) -> str | None:
    """The reason `text` is refused, or None when it is allowed."""
    if not text.strip():
        return None

    searching = _reviewing(text)
    for pattern, why in HARD_RULES:
        if pattern.search(text):
            if searching and not pattern.pattern.startswith(r"\b(pkill"):
                continue
            return why

    if OPERATOR_FILE.search(text):
        # A quoted name is a search pattern; only a path (or a reader/writer
        # verb over a quoted name) is an attempt to touch the file.
        if not searching:
            return (
                "mask.toml (upstream key), dictionary.tsv, *.maskbox envelopes and .env "
                "are operator data: do not read, write, move, chmod or delete them. "
                "mask.toml.example documents the keys."
            )

    for pattern, why in CONNECT_RULES:
        if CONNECT.search(text) and pattern.search(text):
            return why
    return None


def first_refusal(payload: dict) -> str | None:
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    tool = str(payload.get("tool_name", "")).lower()
    keys = PATH_KEYS if any(word in tool for word in ("write", "edit", "notebook")) else COMMAND_KEYS
    for key in keys:
        if key in tool_input:
            for text in _strings(tool_input[key]):
                reason = inspect(text)
                if reason:
                    return reason
    return None


# --- output ------------------------------------------------------------------


def emit_allow() -> int:
    return 0


def emit_deny(claude_style: bool, reason: str) -> int:
    if claude_style:
        sys.stderr.write(
            "agent-guard: refused — the operator's gateway is off limits.\n"
            f"{reason}\n"
            "Run `mask check \"…\"` or `cargo test` instead, or ask the human.\n"
        )
        return 2
    print(json.dumps({"decision": "deny", "reason": f"agent-guard: {reason}"}, ensure_ascii=False))
    return 0


def emit_context() -> int:
    print(
        json.dumps(
            {
                "system_message": "operator contract loaded (running gateway is off limits)",
                "hook_specific_output": {"additional_context": CONTRACT},
            },
            ensure_ascii=False,
        )
    )
    return 0


# --- entry points ------------------------------------------------------------

ALLOWED = [
    "cargo test",
    "cargo clippy --all-targets",
    "git status",
    # The false positive that motivated the command-position anchor: a
    # checkout named `mask` followed by anything called `status`.
    "cd /home/yuta/Documents/mask && git status --short",
    "cd ~/Documents/mask && git log --grep=serve",
    "cd /home/yuta/Documents/mask\ngit status",
    'mask check "call 山田太郎"',
    'mask check "０９０－１２３４－５６７８"',
    "cat mask.toml.example",
    "rg -n 8080 src/",
    'grep -rn "mask.toml" src/gateway/config.rs',
    'grep -rn x-mask-admin src/gateway/mod.rs',
    'grep -rn "mask status" src/',
    "grep -rn MASK_ADMIN_REQUIRE_HUMAN src/",
    "git log --grep 8080",
    "sed -n 1,60p src/gateway/guard.rs",
]

REFUSED = [
    "mask serve",
    "mask serve --port 8090",
    "env -u VIBE_SESSION mask serve",
    "cargo run -- serve",
    "./target/debug/mask serve --port 8090",
    "MASK_ALLOW_AGENT_HOST=1 mask serve",
    "mask serve --allow-agent-host",
    "mask --no-color chat hi",
    # A path to the executable must not be a way around the anchor.
    "/home/yuta/.local/bin/mask serve",
    "/home/yuta/.local/bin/mask status",
    "./target/release/mask status",
    'sh -c "mask serve"',
    "cd /home/yuta/Documents/mask && mask chat hi",
    "mask --no-color status",
    "pkill -f mask",
    "killall mask",
    "curl -s http://127.0.0.1:8080/status",
    "curl -X POST localhost:8080/admin/export",
    "nc -z 127.0.0.1 8080",
    "lsof -i -P",
    "ss -tlnp",
    "cat mask.toml",
    'cat "mask.toml"',
    "cat src/../mask.toml",
    "sed -n 1,50p ~/.config/mask/mask.toml",
    "rm -rf ~/.config/mask",
    "cat dictionary.tsv",
    "ls *.maskbox",
    "cat .env",
    "tr '\\0' '\\n' < /proc/1/environ | grep MASK_",
    "printf 'leak_gate = warn' >> mask.toml",
]


def self_test() -> int:
    failures = 0
    for text in ALLOWED:
        if inspect(text) is not None:
            failures += 1
            print(f"FAIL (should allow) {text!r}: {inspect(text)}")
    for text in REFUSED:
        if inspect(text) is None:
            failures += 1
            print(f"FAIL (should refuse) {text!r}")
    total = len(ALLOWED) + len(REFUSED)
    print(f"{total - failures}/{total} cases behave")
    return 0 if failures == 0 else 1


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--self-test":
        return self_test()
    if len(argv) > 2 and argv[1] == "--check":
        reason = inspect(argv[2])
        if reason:
            print(f"refused: {reason}")
            return 1
        print("allowed")
        return 0

    raw = sys.stdin.read()
    if not raw.strip():
        return emit_allow()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        # A hook that cannot read its input must not block the session: fail
        # open, and let the harness's own `strict` flag decide otherwise.
        return emit_allow()
    if not isinstance(payload, dict):
        return emit_allow()

    event = str(payload.get("hook_event_name", ""))
    if event == "session_start":
        return emit_context()
    if event == "SessionStart":
        print(CONTRACT)
        return 0

    claude_style = event in {"PreToolUse", "PreToolUseHook"}
    reason = first_refusal(payload)
    if reason is None:
        return emit_allow()
    return emit_deny(claude_style, reason)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
