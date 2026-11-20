# Changelog

Notable changes to `mask`. The project is pre-1.0: the guarantee is stable, the
surface is not.

## 0.1.0 — unreleased

First public release. Everything below is new.

### Pseudonymization core

- Detection pipeline: regex rules (phone, email, account, address), a TSV
  dictionary, and `ja_ginza` NER for Japanese named entities
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

### Tests

- 118 tests, including a canary suite asserting that no known PII appears in any
  byte a mock upstream received

### Website

- `site/index.html`: static, single file, no external requests
- Published at <https://branchead.com/mask/> as an assets-only Cloudflare Worker
  on a path route (`wrangler.jsonc`)

### Known limitations

- `stream: true` buffers the upstream response before restoring it (accurate,
  not incremental)
- Unsupported Anthropic content blocks (images, thinking) are dropped
- Allowlisted paths are forwarded unmasked (the leak gate still applies)
