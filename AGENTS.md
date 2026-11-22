# AGENTS.md — the operator's gateway is off limits

This file is a contract for any AI agent (Vibe, Claude Code, Codex, Cursor,
Copilot, …) working in this repository. Read it before your first tool call.

`mask` is a PII pseudonymization gateway. A human runs one instance on this
machine — `mask serve` on `127.0.0.1:8080` by default — and that process is the
one place where real names, the live pseudonym table and the upstream API key
meet. The whole product exists so that the model never sees those values. An
agent that pokes at the running instance undoes that guarantee from the inside,
so:

> **Work on the code. Never touch the running gateway, its config, or its
> mapping table. If a task seems to need them, stop and ask the human.**

This is not a style preference. It is the security boundary this repository
exists to defend, and several of the rules below are enforced by the runtime
itself (see [Guardrails](#guardrails-what-actually-stops-you)).

## Never, without an explicit instruction from the human

| # | Forbidden | Why |
|---|---|---|
| 1 | Starting, stopping, restarting or reloading `mask serve`, or `kill`/`pkill`/`killall` on a `mask` process | The operator's instance holds their upstream key and their live pseudonym table. Killing it silently loses every mapping, and the next turn sends real values upstream unmasked. |
| 2 | `mask serve --allow-agent-host`, `MASK_ALLOW_AGENT_HOST=1`, `MASK_AGENT_HOST_GUARD=0`, `MASK_ADMIN_REQUIRE_HUMAN=0` | These are the doors you are being asked not to walk through. Starting a gateway, or opening its admin channel, is a human action. |
| 3 | Reading `mask.toml`, `~/.config/mask/mask.toml`, `dictionary.tsv`, `*.maskbox`, or any `.env` | They carry the upstream key, the human's own terms, and handoff envelopes. Reading them is a leak even if you only print the path. If you need to know a setting, read `mask.toml.example` or ask. |
| 4 | Writing, moving, chmod-ing or deleting those files | Same. Config changes are the human's, made in their editor. |
| 5 | Calling `/admin/export` or `/admin/import` (or `curl`/`wget`/`nc`/`socat`/`http` against port 8080 at all), or guessing the `x-mask-admin` operator token | `/admin/export` hands out the live mapping table. The token exists only on the human's terminal by design. |
| 6 | Port-scanning, `lsof -i :8080`, or probing to see "if the gateway is up" | The gateway being up is the human's business. Ask them. |
| 7 | Weakening a guarantee in the data path: `leak_gate = "warn"`, widening `passthrough_allowlist`, disabling NER, removing the admin gate, `admin_allow_remote = true` | Each one is a deliberate trade-off a human made. Propose the change; do not slip it in. |
| 8 | Deleting or loosening the tests that pin those guarantees (`tests/guard.rs`, the canary suite, `tests/leak*`, `tests/sharing.rs` lockout cases) | A test that stops asserting a guarantee reads, later, as a guarantee that never existed. |
| 9 | Publishing: `git push`, `cargo publish`, `wrangler deploy`, Docker pushes, publishing releases | The human publishes. You only have to commit|

If a task genuinely requires one of these — "why does `/admin/export` fail for
me?" — do the part that does not need the secret (read the handler, write a test
with a synthetic token) and ask the human for the rest.

## Always

- **Build and test freely.** `cargo fmt`, `cargo clippy --all-targets`,
  `cargo test`. The suite starts its own loopback gateways with mock upstreams,
  needs no real config, and never reaches the network — that is your gateway.
- **Read the spec before the code**: `README.md`, `SECURITY.md`, `CHANGELOG.md`,
  `branchead_base_DESIGN.md`, `docs/superpowers/`.
- **Prefer `mask.toml.example`** over any real config when you need to know a
  key name.
- **Keep the fail-closed posture.** When a choice is between availability and
  strictness, this project picks strictness, and says why in a comment.
- **State the guarantee you changed** in your final message, if you touched
  detection, the leak gate, the admin channel or config resolution.

## The side of the line that is fine

An agent is a first-class *client* of `mask`, and that client relationship lives
in its harness configuration: point `ANTHROPIC_BASE_URL` (or an OpenAI-style
base URL) at the gateway a human started and the traffic flows through it
without the agent touching the process. What is off limits is the *operator*
side — starting the process, reading the secrets, exporting the table, changing
the posture — and the shell route to the running instance: from a shell in this
checkout, `mask chat`, `mask status` and any connection to the gateway port are
refused, because a request an agent composes by hand spends the operator's key
and rewrites their session. Ask the human to run those.

```
agent may:  edit src/, add tests, run cargo test, run `mask check "…"` (no network)
agent may:  reach the gateway through its own harness base URL — a setting, not a command
agent must: stop before serve/kill/export/read-secrets/posture-changes, and ask
```

## Guardrails: what actually stops you

Documentation alone would be a wish. Three layers enforce the boundary, and
each one fails closed:

1. **Runtime gates (in the binary).**
   - `mask serve` refuses to start when the environment — or the parent process
     chain — says an AI agent owns the shell (`VIBE_SESSION`, `CLAUDECODE`,
     `CODEX_SANDBOX`, …, or a `claude` / `codex` / `vibe` ancestor). Override is
     an explicit `--allow-agent-host`.
   - `/admin/export` and `/admin/import` require `x-mask-admin`, a token minted at
     startup, printed **only to the gateway's own terminal**, never written to
     disk, never logged, never shown by `/status`. A gateway started without a
     terminal has no token, so the admin channel is closed, not open.
   - Admin requests whose `Host` is not a loopback *address* are refused (DNS
     rebinding: `127.0.0.1.evil.example` does not pass), a request with no
     `Host` at all is refused, and the loopback-only client check is unchanged.
   - `gateway.admin_require_human = false` opts out — a human's decision to
     record in `mask.toml`, never yours to flip.
2. **Repository guards (this checkout).**
   - `.vibe/hooks.toml` → `scripts/agent-guard.sh`: a `pre_tool` hook in Vibe (and
     Claude Code) that denies the commands and paths in the table above, before
     they run — plus `mask chat` / `mask status` and any connection to the
     gateway port, which is the shell route to the operator's running instance.
     It matches `mask` as an executable in command position, so working in a
     checkout named `mask` is not mistaken for running the CLI.
   - `.vibe/config.toml` and `.claude/settings.json`: deny lists for the same
     paths and for `mask serve`, so the quiet paths are closed too.
3. **Layout.**
   - The real config lives in `~/.config/mask/mask.toml` (mode 600), outside this
     checkout — beyond the working directory, where agent harnesses refuse by
     default. `mask.toml` is gitignored and should not exist here.

Two things about the fence you should know rather than discover:

- Clearing your own marker variable does not help. `mask serve` also walks the
  parent process chain (`/proc` on Linux) and looks for the agent that started
  you. An agent can rename a variable; it cannot change who its parent is.
- The repository guards only load in a folder the human has marked *trusted*
  (`.vibe/` sits behind that). When it is not loaded, nothing warns you — the
  runtime gates still apply, and this contract still holds. Do not assume the
  absence of a hook is permission.

Bypassing a guard — rewriting `scripts/agent-guard.sh`, unsetting a marker
variable, passing an override flag — is not a clever workaround. It is the
violation the guard exists to prevent. If a guard blocks something you believe
is legitimate, say so and ask; do not route around it.

## Reporting

When a guard stops you, report it plainly: which guard, which command, and what
you were trying to achieve. The human can run it themselves in one line, or
loosen the guard deliberately. Never present a blocked action as done.

---

## 日本語要約

このリポジトリで作業する AI エージェントへの契約です。

- **触ってはいけない**: 稼働中の `mask serve`（起動・停止・再起動）、
  `mask.toml` / `~/.config/mask/mask.toml` / `dictionary.tsv` / `*.maskbox` /
  `.env` の読み書き、`/admin/export`・`/admin/import`（および 8080 番への
  接続・スキャン）、`leak_gate` や `passthrough_allowlist` など保証を緩める変更、
  それらを検証しているテストの削除、`git push` / `cargo publish` / デプロイ。
- **してよい**: ソースの編集、`cargo fmt` / `clippy` / `test`（自前のモック上流で
  完結します）、`mask check`（ネットワークなし）、自分の harness の base URL
  設定としてゲートウェイへ向けること（シェルからの `mask chat` / `mask status` /
  8080 番への接続はフックが拒否します）。
- **迷ったら**: 実行せず、人間に「これは稼働中のインスタンスに触りますが、
  実行してよいですか」と確認する。ガードで止められた場合は、どのガードに
  止められたかをそのまま報告する（迂回しない）。
