# Changelog

Notable changes to `mask`. The guarantee is stable; the surface is versioned.

## 1.0.0 — unreleased

First public release. The Rust rewrite ships as a single native binary for
Windows, macOS and Linux.

### The gateway stays in a human's hands

- `mask serve` refuses to start when the environment says an AI agent owns the
  shell (`VIBE_SESSION`, `CLAUDECODE`, `CODEX_SANDBOX`, `CURSOR_AGENT`,
  `GEMINI_CLI`, `COPILOT_AGENT`, `OPENCODE_SESSION`, `AIDER_SESSION`), or when an
  ancestor process is one (`/proc` walk on Linux, so clearing a marker variable
  does not get around it). `--allow-agent-host` / `MASK_ALLOW_AGENT_HOST=1` is
  the explicit override, and `gateway.agent_host_guard = false` records the
  decision in the config
- `/admin/export` and `/admin/import` now also require `x-mask-admin`: a token
  minted at startup and printed **only** to the gateway's controlling terminal.
  It is never written to disk, never logged, and never appears in `/status`. A
  gateway with no terminal (systemd unit, CI, a pipe) has no token, so the admin
  channel is closed. Opt out with `gateway.admin_require_human = false`
- Admin requests whose `Host` header is not a loopback *address* are refused,
  with its own code `mask_admin_host`: the name is parsed, so
  `127.0.0.1.evil.example` does not pass, and a request with no `Host` header is
  refused too (DNS rebinding, fail closed)
- The token is minted after the listener binds (a token printed for a gateway
  that never started is a token the human wrote down for nothing), and a
  CSPRNG failure leaves the channel closed instead of aborting the process
- `GatewayConfig`'s `Debug` is hand-written: the upstream key, the gateway token
  and the operator token print as `<set>`, so one careless `debug!(?config)`
  cannot leak them
- `/status` gains `posture.admin_channel` (`human` / `closed` / `off`),
  `posture.agent_host_guard`, and the `admin_gate_refusals` counter — numbers and
  posture only, as before
- Config resolution reaches the operator's directory first: `--config` >
  `$MASK_CONFIG` > `$XDG_CONFIG_HOME/mask/mask.toml` (`~/.config/mask/mask.toml`)
  > `./mask.toml`. A config carrying an upstream key that is readable beyond its
  owner now logs a warning at load
- New `AGENTS.md` (with `CLAUDE.md` importing it) states the contract for coding
  agents, and `scripts/agent-guard.sh` enforces it before a command runs, wired
  through `.vibe/hooks.toml` (Vibe) and `.claude/settings.json` (Claude Code).
  Self-test: `sh scripts/agent-guard.sh --self-test`

### Native rewrite

- The Python runtime is gone: `mask` is one self-contained executable
  (Windows x86_64, macOS x86_64/aarch64, Linux x86_64/aarch64), built with
  `cargo build --release` and published per release tag
- No interpreter, no virtualenv, no OpenSSL, no cmake. TLS is rustls with
  bundled native roots; crypto is pure Rust (argon2, xsalsa20poly1305)
- NER without a model download: an offline surname lexicon plus a
  given-name extension that stops at honorifics, replacing the spaCy/ja_ginza
  dependency. Names that matter in an operation belong in `dictionary.tsv`,
  which still outranks the built-in detector on span ties
- Envelope crypto stays wire-compatible with the previous implementation
  (argon2id + XSalsa20-Poly1305, `nonce‖tag‖ciphertext`), so existing handoff
  tooling keeps working
- New: `gateway.handoff_kdf_opslimit` / `handoff_kdf_memlimit` (and the matching
  `MASK_HANDOFF_KDF_*` environment variables) tune the KDF cost for hosts that
  cannot afford 256 MiB per attempt; unsealing always uses the cost recorded in
  the envelope
- CI is a Linux/macOS/Windows matrix running `cargo fmt --check`,
  `cargo clippy -D warnings` and `cargo test`

### Pseudonymization core

- Detection pipeline: regex rules (phone, email, account, address), a TSV
  dictionary, and built-in offline name detection
- NFKC normalization so full-width and half-width variants fold onto the same
  entity
- Replacement with opaque, type-tagged tokens (`⟦人名7⟧`) and restoration of the
  response, including fuzzy repair of corrupted tokens
- Session scopes: `global` (stable pseudonyms across a conversation) and
  `request` (a fresh table per request)

### Gateway

- OpenAI-compatible entrance (`/v1/chat/completions`)
- Anthropic-compatible entrance (`/v1/messages`), including `tools` /
  `tool_use` / `tool_result` loops and a correct SSE event sequence for
  `stream: true`
- Deny-by-default routing: only supported endpoints and
  `gateway.passthrough_allowlist` paths are forwarded; everything else is 403
- Pre-flight leak gate: the whole payload and forwarded headers are walked
  before sending; any real value the session has detected discards the request
  (fail-closed)
- Gateway token authentication on both entrances, constant-time comparison
- Logs carry field paths and sha256 digests only — never values

### Reliability indicators

- Per-request `X-Mask-*` response headers
- `GET /status` posture and counter snapshot, token-protected unless
  `gateway.status_public = true`
- `mask status` CLI panel with lamps

### Encrypted handoff (封筒)

- `/admin/export` and `/admin/import` seal the mapping table with argon2id +
  XSalsa20-Poly1305
- Envelopes expire (default 1 hour), lock after repeated wrong passphrases
  (default 3), and are single-use
- Admin API is loopback-only by default; token-ID collisions are reported as
  conflicts and never overwrite a local binding

### CLI

- `mask check` (detection dry run, no network), `mask chat` (one round trip
  through a running gateway), `mask status`, `mask serve`

### Website

- The landing page is one short page now: what mask does, the three setup steps,
  what is guaranteed, and what is not. No JavaScript, no CDN, no embedded
  webfont; the CSP no longer allows scripts at all (`default-src 'none'`, no
  `script-src`)
- The live `/status` widget is gone from the published page. A page served over
  https cannot read `http://127.0.0.1` anyway, and the numbers are one command
  away in `mask status` (the `X-Mask-*` headers stay as they were)
- The OGP card is regenerated from `docs/og-card.html`; the previous one still
  advertised "Python 3.12+" and `branchead.com/mask`
- The example in the hero flow and on the OGP card now uses an address instead
  of a phone number. A phone-shaped example invites the reader to ask whose
  number it is; the address is the Imperial Palace's public location
  (`東京都千代田区千代田1-1`), and the figure caption says so
- The footer ends with a `branchead.com` credit line

### Tests

- 135 tests across eight integration binaries, including a canary suite
  asserting that no known PII appears in any byte a mock upstream received
- The CLI is tested against a live gateway too: `mask status`, `mask status
  --json`, `mask chat` round trip, and the `--no-color` contract

### Website

- `site/index.html`: static, single file, no external requests
- Published at <https://mask.branchead.com/> as an assets-only Cloudflare Worker
  on its own subdomain (`wrangler.jsonc`); the site moved off the
  `branchead.com/mask/` path route, so internal links, canonical and OGP URLs are
  root-relative or on the new host

### Known limitations

- `stream: true` buffers the upstream response before restoring it (accurate,
  not incremental)
- Built-in name detection is lexicon-based: unfamiliar names and rare
  orthographies need a `dictionary.tsv` entry
- Unsupported Anthropic content blocks (images, thinking) are dropped
- Allowlisted paths are forwarded unmasked (the leak gate still applies)
