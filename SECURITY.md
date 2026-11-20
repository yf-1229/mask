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

The project is pre-1.0 (Phase A). Only the `main` branch is supported; fixes
land there and are not backported.

## What mask guarantees

For a value the session has **detected**:

- it does not leave the machine through any field, path or header of a
  forwarded request — the pre-flight leak gate discards the request instead
  (fail-closed)
- it is not written to logs (field paths and sha256 digests only)
- it is not present in the mapping table's transport: handoff envelopes are
  ciphertext (argon2id + XSalsa20-Poly1305), expire, lock after repeated wrong
  passphrases, and are single-use

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
