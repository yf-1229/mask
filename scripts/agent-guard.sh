#!/bin/sh
# agent-guard — the shell entry point both harnesses call.
#
# The rules live in agent-guard.py so they can be tested without a session;
# this wrapper exists because hooks run as a shell line in the session's
# working directory. See AGENTS.md for the contract and .vibe/hooks.toml /
# .claude/settings.json for the wiring.
#
#   sh scripts/agent-guard.sh                 # hook mode (JSON on stdin)
#   sh scripts/agent-guard.sh --check "text"   # human check: exit 1 when refused
#   sh scripts/agent-guard.sh --self-test      # run the built-in cases
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if ! command -v python3 >/dev/null 2>&1; then
    # No interpreter, no judgement. Say so on stderr and hand the harness an
    # explicit denial rather than a silent pass: a guard that quietly stops
    # guarding is worse than one the human has to fix.
    echo "agent-guard: python3 not found — install python3 or remove the hook (see AGENTS.md)" >&2
    printf '{"decision": "deny", "reason": "agent-guard unavailable: python3 not found. Ask the human to install python3 (the guard is the AGENTS.md contract)"}\n'
    exit 0
fi

exec python3 "$here/agent-guard.py" "$@"
