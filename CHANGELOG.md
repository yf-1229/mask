# Changelog

Notable changes to `mask`. The guarantee is stable; the surface is versioned.

## 1.0.0 — unreleased

First public release. The Rust rewrite ships as a single native binary for
Windows, macOS and Linux.

### Install without a toolchain

- A Debian package, `mask_<version>_<arch>.deb` (`amd64`, `arm64`), built by
  `packaging/debian/build-deb.sh` and attached to every release:
  `sudo apt install ./mask_amd64.deb`. It ships the binary, `man mask` and
  `/usr/share/doc/mask/`, and deliberately ships **no service and no `/etc`
  configuration** — starting the gateway stays a human's act, done from a
  terminal the operator token can be printed to, and the config holds the
  upstream key, so it stays in `~/.config/mask/mask.toml` at mode 600
- The package's `Depends` is derived, not asserted: `build-deb.sh` reads the
  versioned symbols the binary imports and declares `libc6 (>= …)` from that, so
  an older distribution refuses the package instead of installing a binary that
  cannot start. Releases build it inside `debian:12` for the same reason
- The `.deb` is reproducible: `dpkg-deb` clamps the payload timestamps to
  `SOURCE_DATE_EPOCH`, and the build defaults that to the commit's own time, so a
  released package can be rebuilt byte-for-byte from its tag
- `curl -fsSL https://mask.branchead.com/install.sh | sh` installs the binary for
  the current machine after checking it against the release's `SHA256SUMS`, and
  fails closed when the sums are missing or do not match (`--no-verify` is the
  deliberate override, and it says so). It writes no config, starts nothing,
  reads no key; `--uninstall` removes the binary and leaves your config and
  dictionary alone. The script served from the site is the one in `scripts/`,
  copied at deploy time, not a second copy
- Every release publishes `SHA256SUMS` over all its assets, plus stable
  `mask_amd64.deb` / `mask_arm64.deb` aliases so
  `/releases/latest/download/…` survives a version bump
- `scripts/install-test.sh` (run in CI) builds the package, checks its metadata
  and payload against what the README promises, unpacks it, installs it with
  `dpkg -i` on a throwaway runner, and drives `install.sh` against a `file://`
  mirror — including the cases that must fail

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
- The guard now judges a command by its shape: `mask` is matched as an
  executable in command position, not as a substring of the line. A checkout
  named `mask` followed by `git status` is repo work, not `mask status`, while
  `~/.local/bin/mask status` and `sh -c "mask serve"` are still refused. The
  self-test grows to 47 cases and runs in CI

### Dictionary work without a restart

- New `mask dict add <term> [--type person]`, `mask dict list`, `mask dict check`.
  `add` validates the term, corrects a type in place, keeps comments and line
  endings, and replaces `dictionary.tsv` atomically (temp file + rename).
  `check` reports skipped lines by number only — no value ever appears in the
  report — and exits non-zero so a typo cannot silently shrink recall
- A running gateway re-reads `dictionary.tsv` on each request (one `stat`) and
  merges the file into the live table. The merge is **additive**: additions
  and type changes apply, removals wait for a restart. Reload therefore cannot
  lower coverage mid-session, and registering a missed name no longer costs the
  in-memory mapping table
- New `POST /admin/dictionary/reload` for an explicit check, behind the same
  four admin gates (loopback `Host`, gateway token, loopback client, operator
  token). It answers with counts only: `added`, `updated`, `kept`, `terms`
- `/status` gains the `dictionary_reloads` counter; `mask status` shows live
  reloads next to the dictionary size when there are any
- Tests: `tests/dictionary.rs` pins the file format, the additive merge (a file
  that drops every term removes nothing), the live pickup across a real
  request, deletion of the file not disabling detection, the admin endpoint,
  and the CLI commands

### Seeing your own misses

- New `mask audit [FILES…]` (or stdin): the same detector over whole files, the
  masked text on stdout, a report on stderr. The report counts entities by type
  and lists the line numbers of **likely misses** — an unmasked run of 2–4 kanji
  immediately before an honorific (`鈴木一郎様`), the shape of a personal name the
  lexicon did not know. Values never enter the report, only line numbers, so it
  can be pasted into an issue
- `--strict` exits 1 when a hint exists (a docs CI gate); `--no-output` prints
  the report without the masked text. Names in kana, and names longer than four
  characters, are outside this hint — the report says so in the README
- The canary corpus moved from Rust constants to `tests/corpus/canary.txt`: a
  block format a contributor can extend without writing code. `tests/corpus.rs`
  validates the case structure, requires every built-in entity type, and checks
  that every expected value really occurs in its text

### Native rewrite

- The Python runtime is gone: `mask` is one self-contained executable
  (Windows x86_64, macOS x86_64/aarch64, Linux x86_64/aarch64), built with
  `cargo build --release` and published per release tag
- No interpreter, no virtualenv, no OpenSSL, no cmake. TLS is rustls with
  bundled native roots; crypto is pure Rust (argon2, xsalsa20poly1305)
- NER without a model download: an offline surname lexicon plus a
  given-name extension that stops at honorifics, replacing the spaCy/ja_ginza
  dependency. The lexicon is data (`src/detect/surnames.txt`, 540+ reviewed
  surnames), so expanding it is a one-line change rather than a Rust edit Names that matter in an operation belong in `dictionary.tsv`,
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

- Detection pipeline: regex rules (phone, email, account, address, card), a TSV
  dictionary, and built-in offline name detection
- Phone rules accept the hyphen that actually arrives — U+FF0D `－` from an IME,
  a spreadsheet or a web form, alongside ASCII `-` and U+2010/U+30FC — and
  E.164 numbers without the leading zero (`+81 90 1234 5678`). Both used to pass
  through unmasked while the README claimed full-width and `+81` support
- Card numbers carry their own type (`⟦カード7⟧`, `card` in the dictionary
  vocabulary) instead of being labelled as a bank account: a card can be
  charged and an account drained, and the token tells the model which
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
- Streaming restores each text delta as it arrives instead of buffering the
  upstream to completion. A token split across SSE chunks is held in a tail
  buffer until complete; EOF flushes it and emits `finish_reason` /
  `message_stop`
- Deny-by-default routing: only supported endpoints and
  `gateway.passthrough_allowlist` paths are forwarded; everything else is 403
- A session binds pseudonyms for at most `session.capacity` entities (default
  256). Going over fails that one request with `mask_session_full` (400) and
  sends nothing upstream; a poisoned session lock is recovered, not inherited,
  so the gateway keeps answering
- Pre-flight leak gate: the whole payload and forwarded headers are walked
  before sending; any real value the session has detected discards the request
  (fail-closed)
- Gateway token authentication on both entrances, constant-time comparison
- Leak-gate logs and block responses carry hashed paths (`key#<sha256-prefix>`)
  and value hash prefixes only — never values or raw object keys; the raw-value
  opt-in is the local `mask check --explain`

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
- Install docs say out loud that `cargo build` leaves the binary in `target/`,
  and that `cargo install --path . --root "$HOME/.local"` is what makes
  `mask …` work. A first-run table maps every message this tool can print —
  `command not found`, `gateway unreachable`, the agent-shell refusal, a closed
  admin channel — to its cause and its fix: a guard that reads as "broken" to
  the human it protects has failed at its only job

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

- Built-in name detection is lexicon-based: unfamiliar names and rare
  orthographies need a `dictionary.tsv` entry
- Unsupported Anthropic content blocks (images, thinking) are dropped
- Allowlisted paths are forwarded unmasked (the leak gate still applies)
