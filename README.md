# mask — a PII pseudonymization gateway for LLM APIs

[![CI](https://github.com/yf-1229/mask/actions/workflows/ci.yml/badge.svg)](https://github.com/yf-1229/mask/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-35d0ba.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-35d0ba.svg)](pyproject.toml)

**Real names never reach the model — and mask guarantees the way back.**

`mask` is a local gateway that sits in front of an LLM API. You type names,
phone numbers and addresses as usual; what leaves the machine is an opaque
pseudonym such as `⟦人名7⟧`. The response is restored to the real values before
you see it.

```
LLM client ──(real PII)──> mask gateway ──(pseudonyms only)──> LLM API
LLM client <──(restored)── mask gateway <──(pseudonyms)─────── LLM API
```

- Speaks **both** OpenAI (`/v1/chat/completions`) and **Anthropic**
  (`/v1/messages`) protocols, so agent harnesses such as Claude Code connect by
  changing a base URL only
- The real API key lives in the gateway; clients get a dummy token
- The mapping table lives in process memory only — the LLM never sees a real value
- A `mask` CLI gives humans the same guarantee from the shell
- **Reliability indicators**: per-request `X-Mask-*` headers, a `/status`
  snapshot, and a `mask status` panel — numbers only, never values

Website: **https://branchead.com/mask/** (static, single file, zero external requests)

## Three entrances, one guarantee

Every entrance passes through the same masking layer, leak gate and indicators.
There is no weaker path.

| Entrance | For | How |
|---|---|---|
| Proxy (OpenAI-compatible) | OpenAI-style harnesses and agents | `base URL = http://127.0.0.1:8080/v1` |
| Proxy (Anthropic-compatible) | Claude Code and similar | `ANTHROPIC_BASE_URL=http://127.0.0.1:8080`, `ANTHROPIC_API_KEY=<gateway.token>` |
| Shell (CLI) | Humans | `mask chat` / `mask check` / `mask status` / `mask serve` |

### Anthropic-compatible entrance (`/v1/messages`)

The Anthropic Messages protocol is accepted in a model-agnostic way:

- Requests are translated to the OpenAI chat shape *before* masking and the
  leak gate run — no low road is created. Unsupported blocks (images, etc.) are
  dropped: deny by default
- `tools` / `tool_use` / `tool_result` agent loops are translated. Tool
  arguments are **restored** because they execute locally; tool results are
  masked on the next turn like any other input
- `stream: true` buffers the upstream response, restores it, and emits a correct
  Anthropic SSE event sequence (same as Phase A: accurate, not incremental)
- Authentication accepts both `Authorization: Bearer` and `x-api-key`

### Shell entrance (`mask` command)

```sh
uv run mask chat "call 山田太郎 for me"   # one round trip; the answer is restored
uv run mask check "090-1234-5678"        # dry run: what would be masked (no network)
uv run mask status                       # reliability indicator panel
uv run mask status --json                # raw /status snapshot
uv run mask serve                        # start the gateway (same as mask-server)
```

- `check` is a detection dry run: masked text on stdout, indicators (counts and
  types) on stderr, so it pipes cleanly
- `chat` talks to a running gateway and prints the response body to stdout, with
  a reliability footer derived from the `X-Mask-*` headers
- No API-key spoofing to worry about: the CLI only uses `gateway.token` as a Bearer

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
   explicitly turns it into a public snapshot (this is what the website widget
   reads). Fail-closed default: `false`.

3. **CLI panel (`mask status`)** — reads `/status` and renders lamps:

   ```
   ● leak gate        block  (fail-closed)
   ● session          global  (mapping table: 2 records)
   ● ner              ja_ginza detection on
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
   session has ever detected is still present (NFKC-normalized, substring match),
   the request is discarded (fail-closed). A masking miss, an unknown field and a
   re-appearing value all converge on the same failure: not sent.
4. **Gateway token** — set `gateway.token` and clients must present it as their
   API key. Protection when listening on a LAN; comparison is constant-time.
5. **Canary tests** — an integration test (`test_gateway_guard.py`) asserts that
   every byte a mock upstream received contains no known PII. Regressions stop in CI.

What is guaranteed: a value the session has detected does not leave through any
field, path or header. What is not: a value that was never detected (unknown
unknowns) — that is the detection layer's job, and the canary corpus is the
regression gate. Logs never contain real values (field paths and sha256 only).

## Sharing the mapping table (encrypted handoff)

The mapping table is the re-identification key. It is shared **only as
ciphertext (an envelope)**, and decryption completes inside the receiver's
gateway.

```sh
# Sender: seal the table with a passphrase (gateway.token required)
curl -s -X POST http://127.0.0.1:8080/admin/export \
  -H "Authorization: Bearer <gateway.token>" -H "Content-Type: application/json" \
  -d '{"passphrase": "<team passphrase>"}' > handoff.maskbox

# Receiver: decrypt and merge into the local session — done
curl -s -X POST http://127.0.0.1:8080/admin/import \
  -H "Authorization: Bearer <gateway.token>" -H "Content-Type: application/json" \
  -d "$(jq '. + {passphrase: "<passphrase>"}' handoff.maskbox)"
```

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

Policy: handoff is a convenience feature — if it breaks, redo it. If an envelope
expires, locks or is consumed, re-mask → LLM → restore from scratch, or re-issue
the envelope. Availability yields to security.

Caveat: lockout, consumption and expiry close decryption *through the gateway*.
Someone holding a copy of the envelope and the passphrase could still brute-force
it offline with their own software; argon2id's cost (256 MiB per attempt),
passphrase strength and short TTLs are what bound that.

## Install

```sh
git clone https://github.com/yf-1229/mask.git && cd mask
uv sync
cp mask.toml.example mask.toml
# edit mask.toml: upstream.base_url / upstream.api_key
uv run mask serve                 # (mask-server does the same)
```

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

### Client configuration (once)

| Client | Setting |
|---|---|
| OpenAI-compatible harness | base URL `http://127.0.0.1:8080/v1`, API key = `gateway.token` (any dummy if unset) |
| Claude Code (Anthropic-compatible) | `ANTHROPIC_BASE_URL=http://127.0.0.1:8080`, `ANTHROPIC_API_KEY=gateway.token` |
| Shell | `mask chat` / `mask check` / `mask status` |

## Configuration (`mask.toml`)

```toml
[server]
host = "127.0.0.1"
port = 8080

[upstream]
base_url = "https://api.openai.com/v1"
api_key = "sk-..."          # or the MASK_UPSTREAM_API_KEY environment variable

[mask]
use_ner = true              # named-entity extraction via ja_ginza
dictionary = "dictionary.tsv" # extra dictionary (TSV: term<TAB>type)

[session]
scope = "global"            # "global": pseudonyms stay stable across the conversation
                            # "request": a fresh table per request

[gateway]
token = ""                   # token handed to clients (empty = no auth, localhost only)
                            # accepted as Bearer (OpenAI style) and x-api-key (Anthropic style)
passthrough_allowlist = ["/v1/models"]  # extra paths to forward. Everything else is 403
leak_gate = "block"          # "block": refuse to send when a real value remains / "warn": log only
handoff_ttl_seconds = 3600   # envelope TTL (seconds); undecryptable afterwards
handoff_max_attempts = 3     # wrong passphrases before an envelope locks permanently
admin_allow_remote = false   # export/import from localhost only (true lifts this)
status_public = false        # publish the /status snapshot (for the website widget)
                             # false means /status requires gateway.token like any entrance
```

Environment variables override the file: `MASK_SERVER_HOST`, `MASK_SERVER_PORT`,
`MASK_UPSTREAM_BASE_URL`, `MASK_UPSTREAM_API_KEY`, `MASK_GATEWAY_TOKEN`,
`MASK_LEAK_GATE`, `MASK_STATUS_PUBLIC`.

Dictionary types: `person` / `org` / `location` / `address` / `phone` / `email` / `account`

## Current limitations (Phase A)

- `stream: true` works, but the upstream stream is fully buffered before the
  restored response is returned (one chunk for OpenAI-compatible, a correct event
  sequence for Anthropic-compatible). Accurate, not incremental. Incremental
  restoration is Phase B
- The Anthropic-compatible entrance translates text and tool blocks. Unsupported
  blocks (images, thinking, …) are dropped — deny by default
- Paths added to the allowlist pass through unmasked (the leak gate still
  applies). Be careful adding schemas that can carry PII (embeddings, …)
- Cloud services whose base URL cannot be changed (ChatGPT web, …) are out of scope

## Tests

```sh
uv run pytest
```

118 tests, including the canary suite that proves no real value reaches the
upstream.

## Website

`site/index.html` — static, single file, no external CDN requests (the tool's own
philosophy, practised). Architecture diagram, the three entrances, defense in
depth, envelope handoff, and a **live indicator** that reads
`http://127.0.0.1:8080/status` directly. Reading requires
`gateway.status_public = true` (fail-closed).

```sh
python3 -m http.server 8877 -d site    # e.g. http://127.0.0.1:8877
```

Published at **https://branchead.com/mask/** as an assets-only Cloudflare Worker
on a path route (`wrangler.jsonc`):

```sh
npx wrangler deploy
```

A page served over https cannot read `http://127.0.0.1` (mixed content), so the
live widget says so instead of pretending to poll. Open `site/index.html`
locally, or run `mask status`, to see live numbers.

`site/_headers` ships a strict CSP (`default-src 'none'`) that blocks every
external request — including the RUM beacon Cloudflare's edge injects into HTML
responses — so "no external requests" is enforced rather than promised.

## Security

See [SECURITY.md](SECURITY.md) for the threat model and how to report a
vulnerability. Please do not open a public issue for a security report.

## License

[MIT](LICENSE) © 2026 Yuta Fujiwara
