# Security policy

`mask` handles personal data by design, so its own failure modes matter. This
document states what the project claims to guarantee, what it explicitly does
not, and how to report a problem.

## Reporting a vulnerability

**Do not open a public issue for a security report.**

Use GitHub's private reporting: **Security → Report a vulnerability** on
<https://github.com/yf-1229/mask/security/advisories/new>.

Please include:

- the version or commit you tested
- the configuration (`mask.toml` with secrets redacted)
- a minimal reproduction — ideally a failing test
- what you expected versus what happened

You can expect an acknowledgement within 7 days and an assessment within 30
days. This is a single-maintainer project; there is no bug bounty.

## Supported versions

Only the latest release is supported; fixes land on `main` and ship in the next
tag. Prebuilt binaries for Windows, macOS and Linux are built from that same tag
in CI, so what you run is what was tested.

## What mask guarantees

For a value the session has **detected**:

- it does not leave the machine through any field, path or header of a
  forwarded request — the pre-flight leak gate discards the request instead
  (fail-closed)
- it is not written to logs (field paths and sha256 digests only)
- it is not present in the mapping table's transport: handoff envelopes are
  ciphertext (argon2id + XSalsa20-Poly1305), expire, lock after repeated wrong
  passphrases, and are single-use
- the mapping table does not leave the process **as a table** unless the
  operator at the gateway's own terminal asks for it: `/admin/export`,
  `/admin/import` and `/admin/dictionary/reload` require `x-mask-admin`, a token
  minted at startup and printed
  only to the controlling terminal (never to stdout, a log, or `/status`).
  Without a terminal there is no token, so the admin channel is closed rather
  than open. (A client of the proxy can still resolve *individual* pseudonyms by
  sending them back — that is what restoration is for; what the gate protects is
  the bulk table, which is the difference between one value and every value)

These are enforced structurally and covered by tests, including a canary suite
that asserts no known PII appears in any byte a mock upstream received.

## What mask does not guarantee

- **Undetected values.** A value the detection layer never recognised is not
  protected. This is the known-unknowns boundary; the canary corpus is the
  regression gate, not a proof of completeness
- **A compromised host.** mask runs in the same trust domain as the client. If
  the machine is compromised, the mapping table, the upstream API key and the
  plaintext are all reachable
- **Offline attacks on a stolen envelope.** Lockout, expiry and single-use close
  decryption *through the gateway*. Someone holding a copy of the envelope and
  the passphrase can still attack it offline with their own software; argon2id's
  cost (256 MiB per attempt), passphrase strength and short TTLs are what bound
  that
- **The upstream provider.** Once a request is sent, the provider's handling of
  the pseudonymized payload is outside mask's control
- **Allowlisted paths.** Paths added to `gateway.passthrough_allowlist` are
  forwarded unmasked (the leak gate still applies). Adding a schema that can
  carry PII (embeddings, …) weakens the guarantee
- **An operator who switches the guards off.** `admin_require_human = false`,
  `--allow-agent-host`, or an agent that runs inside the operator's terminal
  session becomes indistinguishable from the operator. The guards stop the
  defaults, not a human's deliberate choice
- **An agent told to do operator work, or one that re-parents itself.** Nothing
  here distinguishes "the human asked for the table" from "the agent decided
  to", and the process-ancestry check can be stepped around by a double fork or
  a service manager. `AGENTS.md` and `scripts/agent-guard.sh` make the boundary
  explicit for coding agents working in this repository; they are a contract
  plus a hook, not a sandbox
- **Anything running as your user.** The config holds the upstream key, and a
  process with your uid can read it, or start its own gateway pointing the
  upstream at a listener that keeps the `Authorization` header. Keeping the
  config out of the checkout (`~/.config/mask`, mode 600) raises the cost and
  closes the accidental paths; it is not an isolation boundary. If you need one,
  run the gateway as a different user

## AI agents work on the code, not on the running instance

`mask` exists to be used *by* agents, so the boundary is drawn around the
operator's seat rather than around the API: a harness may talk to a gateway a
human started, and a coding agent may edit, build and test this repository. It
may not start the process, read `mask.toml`, call `/admin/*`, or loosen a
guarantee. That contract lives in `AGENTS.md` (read by Vibe, Claude Code, Codex
and others) and is enforced before the command runs by `scripts/agent-guard.sh`
through Vibe hooks and `.claude/settings.json` — which load only in a folder the
human has marked trusted, so treat them as the visible half, not the fence.

The server-side half: the operator token and the loopback `Host` check do not
depend on any cooperation at all, and the agent host guard inspects the
environment *and* the parent process chain (`/proc` on Linux), so clearing a
marker variable does not get around it. All three are still fences around the
defaults, not a sandbox against a same-uid process that means it: the ancestry
walk can be defeated by a double fork, and anything running as your user can
read your config if it decides to.

## Threat model in one line

mask defends against **accidental disclosure of PII to an LLM provider** — the
common case of pasting real names, phone numbers and addresses into a chat or an
agent loop. It is not a defence against a hostile local user, a compromised
machine, or a provider that misuses what it receives.

## Hardening checklist

- Set `gateway.token` whenever the gateway listens on anything other than
  loopback; comparison is constant-time
- Keep `leak_gate = "block"` (the default). `"warn"` logs and sends
- Keep `admin_allow_remote = false` unless you genuinely need remote handoff
- Keep `status_public = false` unless you want the website widget to read
  `/status`; the snapshot contains numbers only, but it is still posture
  information
- Keep `handoff_ttl_seconds` short and share passphrases over a different channel
- Never commit `mask.toml`, `dictionary.tsv` or `*.maskbox` — they are ignored by
  `.gitignore` for this reason
- Leave `handoff_kdf_opslimit` / `handoff_kdf_memlimit` at their defaults unless
  the host genuinely cannot afford 256 MiB per attempt: every step down makes
  offline guessing against a copied envelope cheaper
- Keep `admin_require_human = true` and start `mask serve` from an interactive
  terminal; a service manager gives it no terminal, which closes `/admin/*`
- Keep `agent_host_guard = true`; reach for `--allow-agent-host` only when the
  gateway really is agent-hosted, and say so in the config rather than in a
  shell history
- Keep the real config in `~/.config/mask/mask.toml` with mode `600`, not in a
  checkout: an agent working in the repository then has to cross a directory
  boundary that agent harnesses refuse by default
- If you let coding agents work in this repository, keep `AGENTS.md`,
  `scripts/agent-guard.sh`, `.vibe/` and `.claude/` in the tree and review any
  change to them — they are the before-the-fact half of this list
- Read `/status` after a session: `posture.admin_channel` should read `human`
  while you are serving, and `admin_gate_refusals` should stay at zero
