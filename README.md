# mask — a PII pseudonymization gateway for LLM APIs

[![CI](https://github.com/yf-1229/mask/actions/workflows/ci.yml/badge.svg)](https://github.com/yf-1229/mask/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-35d0ba.svg)](LICENSE)
[![Rust 1.82+](https://img.shields.io/badge/rust-1.82%2B-35d0ba.svg)](Cargo.toml)
[![Windows · macOS · Linux](https://img.shields.io/badge/native-Windows%20%C2%B7%20macOS%20%C2%B7%20Linux-35d0ba.svg)](#install)

**Real names never reach the model — and mask guarantees the way back.**

`mask` is a single native binary that sits in front of an LLM API. You type
names, phone numbers and addresses as usual; what leaves the machine is an
opaque pseudonym such as `⟦人名7⟧`. The response is restored to the real values
before you see it.

```
LLM client ──(real PII)──> mask gateway ──(pseudonyms only)──> LLM API
LLM client <──(restored)── mask gateway <──(pseudonyms)─────── LLM API
```

- **One self-contained executable** for Windows, macOS (Intel/Apple silicon) and
  Linux (x86_64/aarch64) — no Python, no interpreter, no OpenSSL, no cmake
- Speaks **both** OpenAI (`/v1/chat/completions`) and **Anthropic**
  (`/v1/messages`) protocols, so agent harnesses such as Claude Code connect by
  changing a base URL only
- The real API key lives in the gateway; clients get a dummy token
- The mapping table lives in process memory only — the LLM never sees a real value
- A `mask` CLI gives humans the same guarantee from the shell
- **Reliability indicators**: per-request `X-Mask-*` headers, a `/status`
  snapshot, and a `mask status` panel — numbers only, never values

Website: **https://mask.branchead.com/** (static, single file, zero external requests)

## Three entrances, one guarantee

Every entrance passes through the same masking layer, leak gate and indicators.
There is no weaker path.

| Entrance | For | How |
|---|---|---|
| Proxy (OpenAI-compatible) | OpenAI-style harnesses and agents | `base URL = http://127.0.0.1:8080/v1` |
| Proxy (Anthropic-compatible) | Claude Code and similar | `ANTHROPIC_BASE_URL=http://127.0.0.1:8080`, `ANTHROPIC_API_KEY=<gateway.token>` |
| Shell (CLI) | Humans | `mask chat` / `mask check` / `mask audit` / `mask status` / `mask session` / `mask dict` / `mask serve` |

### Anthropic-compatible entrance (`/v1/messages`)

The Anthropic Messages protocol is accepted in a model-agnostic way:

- Requests are translated to the OpenAI chat shape *before* masking and the
  leak gate run — no low road is created. Unsupported blocks (images, etc.) are
  dropped: deny by default
- `tools` / `tool_use` / `tool_result` agent loops are translated. Tool
  arguments are **restored** because they execute locally; tool results are
  masked on the next turn like any other input
- `stream: true` restores each upstream text delta as it arrives and emits the
  Anthropic SSE event sequence incrementally. A token split across chunks is
  held until the next chunk completes it; the tail is flushed at upstream EOF,
  then `message_stop` (or the OpenAI `finish_reason`) closes the stream
- Authentication accepts both `Authorization: Bearer` and `x-api-key`

### Shell entrance (`mask` command)

```sh
mask chat "call 山田太郎 for me"   # one round trip; the answer is restored
mask check "090-1234-5678"        # dry run: what would be masked (no network)
mask audit notes.md               # mask files; report likely misses (line numbers)
mask status                       # reliability indicator panel
mask status --json                # raw /status snapshot
mask session                      # what this session masked (hashes only)
mask session --values             # …with the raw values, local stdout only
mask dict add 山田太郎             # register a term; a running gateway picks it up
mask dict list                    # what the gateway knows (term<TAB>type)
mask dict check                   # validate the file; counts and line numbers
mask serve                        # start the gateway
```

- `check` is a detection dry run: masked text on stdout, indicators (counts and
  types) on stderr, so it pipes cleanly. `check --explain` adds the raw detected
  values to stderr — the local, opt-in diagnostic. The gateway's leak-block
  response and WARN log always show only `key#<sha256-prefix>` paths and a
  value hash prefix, never the value or the raw key.
- `chat` talks to a running gateway and prints the response body to stdout, with
  a reliability footer derived from the `X-Mask-*` headers
- `audit` runs the same detector over whole files (or stdin) and prints the
  masked text to stdout. On stderr it reports entity counts and the line numbers
  of **likely misses**: an unmasked run of 2–4 kanji immediately before an
  honorific (`鈴木一郎様`), which is the shape of a personal name the lexicon did
  not know. The report carries no values — only counts and line numbers — and
  `--strict` exits 1 so a docs CI can gate on it. A name written in kana, or
  longer than four characters, is outside this hint
- `dict add` is the path from a detection miss to a registered term: it
  validates the term, keeps comments and line endings, and replaces
  `dictionary.tsv` atomically. A running gateway merges additions on the next
  request — no restart, and the in-memory mapping table survives. `dict check`
  reports skipped lines by number only, so a typo fails loudly instead of
  silently shrinking recall
- `session` answers "what has this session masked?" from the gateway's live
  table. It reads `GET /admin/session`, which sits behind the same operator
  token as export/import and answers loopback clients only; `/status` keeps
  carrying counts, never values. Values are shown as a sha256 prefix unless
  `--values` is passed (stdout only — logs and `/status` never carry one), long
  cells are truncated unless `--full` is passed, and `--json` is the same
  snapshot for `jq`. `--admin-token` is the token printed on the gateway's
  terminal:

  ```
  $ mask session --admin-token "<token on the gateway's terminal>"
  mask session — global  (2 entities, 3 occurrences · id pool 254/256 left)
    kind    token        occurrences  value
    person  ⟦人名17⟧   2            sha256:1a2b3c4d
    phone   ⟦電話201⟧  1            sha256:9f8e7d6c
  ```

  `remaining`/`capacity` in the JSON (and "id pool … left" in the table) is the
  same pool `SessionFull` fails against, so token exhaustion from mask#10 is
  visible before a request is refused
- No API-key spoofing to worry about: the CLI only uses `gateway.token` as a Bearer

## How detection works (no model download)

The rewrite replaces the Python stack's spaCy/ja_ginza pipeline with a built-in,
dependency-free detector that ships inside the binary:

1. **Rules** — emails, phone numbers (hyphenated, parenthesised, full-width),
   postal addresses, bank accounts and card numbers, with explicit boundary
   guards so dates (`2019-04-01`) never register as phone numbers.
2. **User dictionary** — `dictionary.tsv` (`term<TAB>type`), longest match first,
   for the names that matter in your operation. `mask dict add 山田太郎` writes
   it; the gateway re-reads the file and merges additions while it runs
   (additive: a reload can add a term, never remove one — removal waits for a
   restart, because a restart also clears the mapping table).
3. **Built-in name detection** — an offline surname lexicon (540+ names in
   `src/detect/surnames.txt`) plus a
   given-name extension that stops at honorifics and function words. It needs no
   model file and starts instantly.

Trade-off, stated plainly: a statistical NER model has wider recall on
unfamiliar names than a lexicon. The canary corpus (`tests/pipeline.rs`,
`tests/gateway.rs`, `tests/dictionary.rs`) pins the recall the tool claims, and
anything it misses belongs in `dictionary.tsv` — that is the highest-trust layer
and beats the built-in detector on span ties. `mask audit` points at the likely
misses in your own files (unmasked names before an honorific), registering one is
`mask dict add`, and a running gateway takes it without losing the table.

## Reliability indicators

"Nothing leaves" is unverifiable if you cannot see it. mask shows it on three
surfaces, always as **numbers only** — never values, tokens or entity paths.

1. **Response headers (per request)**

   ```
   X-Mask: on
   X-Mask-In: v1/messages          # which entrance was used
   X-Mask-Leak-Gate: block
   X-Mask-Masked: 3                # real values replaced
   X-Mask-Restored: 2              # tokens restored
   X-Mask-Fuzzy-Repaired: 0        # corrupted tokens repaired
   X-Mask-Unresolved: 0            # tokens that could not be restored (watch this)
   X-Mask-Nonce: 734dc18c9d7a      # minted per response (cache detection)
   ```

   A leak-gate block also sets `X-Mask-Leak-Blocked: true`.

2. **`GET /status`** — posture (leak gate mode, session scope, NER, dictionary
   size, mapping-table records, token configuration, upstream) plus cumulative
   process counters (requests, masked/restored, leak blocks, path denials, auth
   denials, envelope stats, uptime). With `gateway.token` set it requires the
   token like any other entrance. Setting `gateway.status_public = true`
   explicitly turns it into a public snapshot for dashboards and scripts.
   Fail-closed default: `false`.

3. **CLI panel (`mask status`)** — reads `/status` and renders lamps:

   ```
   ● leak gate        block  (fail-closed)
   ● session          global  (mapping table: 2 records)
   ● ner              built-in name detection on
   ● dictionary       0 terms
   ● gateway token    required (both entrances)
     requests         2 / entities masked 2 / tokens restored 2 / unresolved 0
   ```

## Defense in depth

"Never leaves" is guaranteed structurally, not by the quality of detection.

1. **Masking layer** — replaces `messages[].content` (strings and parts) and
   `tool_calls[].function.arguments` (JSON strings are walked recursively).
   NFKC normalization folds full-width/half-width variants onto the same entity.
2. **Deny-by-default routing** — only `/v1/chat/completions` (including requests
   translated from the Anthropic entrance) and paths listed in
   `gateway.passthrough_allowlist` are forwarded. Everything else is 403, which
   structurally prevents PII from flowing through unsupported schemas such as
   embeddings.
3. **Pre-flight leak gate** — immediately before sending, the whole payload
   (including keys) and forwarded headers are walked. If any real value the
   session has ever detected is still present (NFKC-normalized, whole-word
   match), the request is discarded (fail-closed). A masking miss, an unknown
   field and a re-appearing value all converge on the same failure: not sent.
   Matching is whole-word so a value inside a longer word is not a re-mention
   (`田中` in `田中町`), and a two-character value is judged in body text only
   (`content`, `prompt`, …) — never in keys, headers or metadata such as
   `model`/`stop`.
4. **Gateway token** — set `gateway.token` and clients must present it as their
   API key. Protection when listening on a LAN; comparison is constant-time.
5. **Canary tests** — integration tests (`tests/gateway.rs`,
   `tests/agent_entry.rs`) assert that every byte a mock upstream received
   contains no known PII. Regressions stop in CI, on all three platforms.

What is guaranteed: a value the session has detected does not leave through any
field, path or header. What is not: a value that was never detected (unknown
unknowns) — that is the detection layer's job, and the canary corpus is the
regression gate. Logs and leak-block responses never contain real values:
object keys are shown as `key#<sha256-prefix>` and each leak carries a value
hash prefix. `mask check --explain` is the local opt-in that prints raw values.

## Keeping the gateway out of an AI agent's hands

mask is built for agents as *clients*: pointing a harness at a running gateway
is the whole point. The opposite direction needs a wall, because the process a
human started is where the upstream key and the live mapping table meet.

Four gates. The operator token, the `Host` check and the repository hook fail
closed on their own; the agent host guard refuses the default case and says so
when it is overridden:

| Gate | What it stops |
|---|---|
| `mask serve` refuses an agent's shell | An agent standing up an instance with your credentials: `VIBE_SESSION`, `CLAUDECODE`, `CODEX_SANDBOX` and friends are detected; `--allow-agent-host` is the explicit override |
| Operator token on `/admin/*` | Any local process (agent, script, another user's shell) pulling the mapping table: the token is printed on the gateway's terminal only, and is absent when there is no terminal |
| Loopback `Host` check | A DNS-rebinding page addressing the admin channel as `evil.example` (the name is parsed as an address, and a missing `Host` is refused too) |
| Repo contract (`AGENTS.md`) + `scripts/agent-guard.sh` | An agent working in this checkout spending your key or session from a shell: `mask serve`, `mask chat`, `mask status`, any connection to the gateway port, `cat mask.toml`, `/admin/export` — denied before the command runs (Vibe and Claude Code hooks). The client relationship stays open where it belongs: in the harness's base-URL setting |

Posture is visible without opening anything: `/status` reports
`posture.admin_channel` (`human` / `closed` / `off`), `posture.agent_host_guard`,
and the `admin_gate_refusals` counter — numbers only, as everywhere else.

## Sharing the mapping table (encrypted handoff)

The mapping table is the re-identification key. It is shared **only as
ciphertext (an envelope)**, and decryption completes inside the receiver's
gateway.

```sh
# Sender: seal the table with a passphrase (gateway.token + operator token required)
curl -s -X POST http://127.0.0.1:8080/admin/export \
  -H "Authorization: Bearer <gateway.token>" -H "x-mask-admin: <token on the gateway's terminal>" \
  -H "Content-Type: application/json" \
  -d '{"passphrase": "<team passphrase>"}' > handoff.maskbox

# Receiver: decrypt and merge into the local session — done
curl -s -X POST http://127.0.0.1:8080/admin/import \
  -H "Authorization: Bearer <gateway.token>" -H "x-mask-admin: <token on the gateway's terminal>" \
  -H "Content-Type: application/json" \
  -d "$(jq '. + {passphrase: "<passphrase>"}' handoff.maskbox)"
```

- **Human in the loop**: `mask serve` mints an operator token and prints it to
  the terminal it runs in — never to stdout, a log, or `/status`. Export and
  import require it as `x-mask-admin`, so a copied `mask.toml`, a shell history
  or an agent with this machine's credentials still cannot pull the table out.
  A gateway started without a terminal (a service unit, CI) has no token: the
  admin channel is **closed**, not open

- Crypto: argon2id (passphrase → key, 256 MiB per attempt, MODERATE) plus
  XSalsa20-Poly1305 (authenticated). The envelope is ciphertext, so any transport
  is safe; share the passphrase over a different channel (a password manager)
- **Expiry**: the envelope carries a TTL (default 1 hour, `ttl_seconds` at export
  time) sealed inside the encrypted payload. Past it, even the right passphrase
  cannot decrypt (410 Gone)
- **Lockout**: wrong passphrases are counted per envelope; at the limit (default
  3, `handoff_max_attempts`) that envelope is permanently locked (423 Locked).
  Re-export to issue a new one. Attempt counters are in-process memory only
- **Single use**: a successfully imported envelope is consumed and cannot be
  imported again (410). Export once per recipient
- **Admin API is loopback-only** by default: unless
  `gateway.admin_allow_remote = true` is set explicitly, export/import accept
  localhost only. The only thing crossing the network is the envelope file
- After import, the same value masks to the same token, so the sender's artifacts
  restore inside the receiver's gateway
- Token-ID collisions (a different value claiming the same ID) are never
  overwritten: they are reported as `conflict` and the local binding wins, which
  structurally prevents restoring to the wrong person
- Imported values also become leak-gate targets: sending them out is still refused
- Admin endpoints return 403 when `gateway.token` is unset (fail-closed). Token
  comparison is constant-time
- KDF cost is tunable (`gateway.handoff_kdf_opslimit` / `handoff_kdf_memlimit`)
  for hosts that cannot afford 256 MiB per attempt; unsealing always uses the
  cost recorded inside the envelope, so a table sealed elsewhere still opens here

Policy: handoff is a convenience feature — if it breaks, redo it. If an envelope
expires, locks or is consumed, re-mask → LLM → restore from scratch, or re-issue
the envelope. Availability yields to security.

Caveat: lockout, consumption and expiry close decryption *through the gateway*.
Someone holding a copy of the envelope and the passphrase could still brute-force
it offline with their own software; argon2id's cost (256 MiB per attempt),
passphrase strength and short TTLs are what bound that.

## Install

Three ways in. The first two need no toolchain.

### Debian / Ubuntu — one file

```sh
curl -fsSLO https://github.com/yf-1229/mask/releases/latest/download/mask_amd64.deb
sudo apt install ./mask_amd64.deb
```

`apt install ./file.deb`, not `dpkg -i`: the package depends on `libc6` and the
CA bundle (rustls reads the system root store), and apt resolves both. On ARM
the file is `mask_arm64.deb`; the versioned name (`mask_1.0.0_amd64.deb`) is what
apt records, so `apt show mask` and `apt remove mask` behave as you expect.

The package ships the binary, `man mask` and the documents under
`/usr/share/doc/mask/`. It ships **no service and no `/etc` config** on purpose:
starting the gateway is a human's act, done from a terminal the operator token
can be printed to, and the config holds your upstream API key — so it stays in
your own home directory with mode 600, outside any checkout a coding agent works
in.

The glibc floor is a declared `Depends`, taken from the symbol versions the
binary actually imports (`libc6 (>= 2.34)` for a current build), so `apt` on an
older release refuses the package instead of installing a binary that cannot
start.

### Linux / macOS — one line

```sh
curl -fsSL https://mask.branchead.com/install.sh | sh
```

Picks the build for this machine, checks it against the release's `SHA256SUMS`,
and installs to `~/.local/bin` (`/usr/local/bin` as root, `--prefix DIR`
otherwise). It writes no config, starts nothing, reads no key. Re-run it to
upgrade; `--uninstall` removes the binary and leaves your config and dictionary
alone.

Read it first if you prefer — it is POSIX `sh` and says what it will do — and
pin a version when repeatability matters:

```sh
curl -fsSL https://mask.branchead.com/install.sh -o install.sh && less install.sh
sh install.sh --dry-run      # the URL and the destination, nothing downloaded
curl -fsSL https://mask.branchead.com/install.sh | sh -s -- --version 1.0.0
```

Every asset in a release is covered by one `SHA256SUMS`, so a package downloaded
by hand can be checked the way the script checks the binary:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

Bare `mask-<target>` binaries (Windows x86_64 included) are attached to the same
release.

### From source

```sh
git clone https://github.com/yf-1229/mask.git && cd mask
cargo build --release                    # target/release/mask(.exe)

# The config holds the upstream key, so it lives outside the checkout — that
# is where coding agents run. mask.toml.example says the same at the top.
mkdir -p ~/.config/mask
cp mask.toml.example ~/.config/mask/mask.toml
chmod 600 ~/.config/mask/mask.toml
$EDITOR ~/.config/mask/mask.toml         # upstream.base_url / upstream.api_key
./target/release/mask serve              # from your own terminal
```

Resolution order, first match wins: `--config <path>`, `$MASK_CONFIG`,
`$XDG_CONFIG_HOME/mask/mask.toml` (`~/.config/mask/mask.toml` by default), then
`./mask.toml`. A checkout-local `mask.toml` still works — it is gitignored — but
it puts the key inside the tree an agent works in.

Requires the [Rust toolchain](https://rustup.rs) (1.82+). Nothing else: TLS is
rustls with bundled roots, crypto is pure Rust, and the release profile is
stripped and LTO'd (~7 MB).

Building does not put `mask` on your `PATH` — the binary stays in `target/`. If
you want the bare `mask …` commands this README uses, install it once:

```sh
cargo install --path . --root "$HOME/.local"   # -> ~/.local/bin/mask
mask --version
```

`~/.local/bin` is on `PATH` on most distributions; if `mask: command not found`
still appears, use `./target/release/mask` instead, or add the directory to your
shell profile.

### Client configuration (once)

| Client | Setting |
|---|---|
| OpenAI-compatible harness | base URL `http://127.0.0.1:8080/v1`, API key = `gateway.token` (any dummy if unset) |
| Claude Code (Anthropic-compatible) | `ANTHROPIC_BASE_URL=http://127.0.0.1:8080`, `ANTHROPIC_API_KEY=gateway.token` |
| Shell | `mask chat` / `mask check` / `mask status` |

## First run — the four things that actually go wrong

Every message here names the fix, so a refusal never looks like a broken build.

| Symptom | Why | Fix |
|---|---|---|
| `mask: command not found` | built, never installed | `cargo install --path . --root "$HOME/.local"` |
| `mask status` → `gateway … unreachable` | nothing is serving | run `mask serve` (in your own terminal) |
| `mask serve` → `refusing to start the gateway: this shell belongs to an AI agent` | you are inside an agent's shell (`VIBE_SESSION`, `CLAUDECODE`, …) — the guard from the section above | start it from a normal terminal, or pass `--allow-agent-host` deliberately |
| `admin channel closed — no operator terminal` | `mask serve` had no tty, so no operator token was minted; `/admin/*` is refused | run `mask serve` from an interactive terminal, or set `gateway.admin_require_human = false` |

## Configuration (`mask.toml`)

```toml
[server]
host = "127.0.0.1"
port = 8080

[upstream]
base_url = "https://api.openai.com/v1"
api_key = "sk-..."          # or the MASK_UPSTREAM_API_KEY environment variable

[mask]
use_ner = true              # built-in offline name detection (no model download)
dictionary = "dictionary.tsv" # extra dictionary (TSV: term<TAB>type); additions
                             # are merged live, removals apply on restart

[session]
scope = "global"            # "global": pseudonyms stay stable across the conversation
                            # "request": a fresh table per request
capacity = 256              # entities one session can bind; the request that
                            # exceeds it fails with mask_session_full (400)

[gateway]
token = ""                   # token handed to clients (empty = no auth, localhost only)
                            # accepted as Bearer (OpenAI style) and x-api-key (Anthropic style)
passthrough_allowlist = ["/v1/models"]  # extra paths to forward. Everything else is 403
leak_gate = "block"          # "block": refuse to send when a real value remains / "warn": log only
handoff_ttl_seconds = 3600   # envelope TTL (seconds); undecryptable afterwards
handoff_max_attempts = 3     # wrong passphrases before an envelope locks permanently
handoff_kdf_opslimit = 3     # argon2id passes (raise, never lower, on a capable host)
handoff_kdf_memlimit = 268435456  # argon2id memory in bytes (256 MiB)
admin_allow_remote = false   # export/import from localhost only (true lifts this)
admin_require_human = true   # export/import also need the token printed on this terminal
agent_host_guard = true      # refuse `mask serve` from an AI agent's shell
status_public = false        # publish the /status snapshot (numbers only)
                             # false means /status requires gateway.token like any entrance
```

Environment variables override the file: `MASK_SERVER_HOST`, `MASK_SERVER_PORT`,
`MASK_UPSTREAM_BASE_URL`, `MASK_UPSTREAM_API_KEY`, `MASK_GATEWAY_TOKEN`,
`MASK_LEAK_GATE`, `MASK_HANDOFF_TTL_SECONDS`, `MASK_HANDOFF_MAX_ATTEMPTS`,
`MASK_HANDOFF_KDF_OPSLIMIT`, `MASK_HANDOFF_KDF_MEMLIMIT`,
`MASK_ADMIN_ALLOW_REMOTE`, `MASK_ADMIN_REQUIRE_HUMAN`, `MASK_AGENT_HOST_GUARD`,
`MASK_ALLOW_AGENT_HOST`, `MASK_STATUS_PUBLIC`.

The config is read from `--config <path>`, then `$MASK_CONFIG`, then
`$XDG_CONFIG_HOME/mask/mask.toml` (`~/.config/mask/mask.toml`), then
`./mask.toml`. Put the real one in the config directory, mode 600: outside any
checkout, so a coding agent working in this repository is never one `read_file`
away from your upstream key.

Dictionary types: `person` / `org` / `location` / `address` / `phone` / `email` / `account`

## Current limitations

- The Anthropic-compatible entrance translates text and tool blocks. Unsupported
  blocks (images, thinking, …) are dropped — deny by default
- Built-in name detection is lexicon-based, not statistical: unfamiliar names and
  rare orthographies need an entry in `dictionary.tsv` (`mask dict add`).
  Additions are live; removals wait for a restart, so a reload cannot quietly
  lower recall. `mask audit`'s miss hint only looks at kanji runs before
  honorifics — kana names and names longer than four characters are not pointed
  at
- Paths added to the allowlist pass through unmasked (the leak gate still
  applies). Be careful adding schemas that can carry PII (embeddings, …)
- Cloud services whose base URL cannot be changed (ChatGPT web, …) are out of scope

## Tests

```sh
cargo test          # 195 tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

The suite covers the detection rules, dictionary and restore layers, the native
name detector, the OpenAI and Anthropic entrances (against a real loopback mock
upstream), the leak gate, deny-by-default routing, the indicator surfaces, the
encrypted handoff (crypto, expiry, lockout, single use, admin flow), the TOML/env
configuration, and the CLI — including the **canary suite** that proves no known
real value reaches the upstream. The corpus is data
(`tests/corpus/canary.txt`), so a case can be added without Rust, and
`tests/corpus.rs` checks that every expected value really occurs in its text.
CI runs it on Linux, macOS and Windows.

## Website

`site/index.html` — one static, self-contained page: what mask does, the three
setup steps, and an honest list of what it cannot do. No JavaScript, no CDN, no
external font; `site/_headers` enforces that with `default-src 'none'`.

The OGP card (`site/og.png`) is generated from `docs/og-card.html`:

```sh
google-chrome --headless=new --hide-scrollbars --window-size=1200,630 \
  --force-device-scale-factor=1 --screenshot=site/og.png \
  "file://$PWD/docs/og-card.html"
```

Preview it with any static file server:

```sh
python3 -m http.server 8877 -d site     # http://127.0.0.1:8877
```

Published at **https://mask.branchead.com/** as an assets-only Cloudflare Worker
on its own subdomain (`wrangler.jsonc`):

```sh
npx wrangler deploy
```

`site/_headers` ships a strict CSP (`default-src 'none'`) that blocks every
external request — including the RUM beacon Cloudflare's edge injects into HTML
responses — so "no external requests" is enforced rather than promised.

## Security

See [SECURITY.md](SECURITY.md) for the threat model and how to report a
vulnerability. Please do not open a public issue for a security report.

## License

[MIT](LICENSE) © 2026 Yuta Fujiwara
