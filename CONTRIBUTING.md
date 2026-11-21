# Contributing to mask

Thanks for taking a look. This is a small, opinionated project: the guarantee
("a detected value never leaves") is structural, and changes that weaken it are
rejected even when they are convenient.

## Getting set up

```sh
git clone https://github.com/yf-1229/mask.git && cd mask
cargo build            # debug binary at target/debug/mask
cargo test             # 135 tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

The [Rust toolchain](https://rustup.rs) (1.82+) is all you need: no C compiler
step, no OpenSSL, no model download. The suite is a real loopback mock upstream,
so it needs no network and no credentials.

## What a good change looks like

- **Tests first.** Every behaviour change needs a test. Security-relevant
  behaviour needs a test that fails loudly if the guarantee breaks — see
  `tests/gateway.rs` (canary corpus in `tests/common/mod.rs`) for the pattern
- **No new low roads.** If you add an entrance, a protocol or a forwarded path,
  it must pass through the same masking layer, leak gate and indicators. A
  feature that bypasses them will not be merged
- **Fail closed.** When in doubt, refuse the request. `warn` modes exist only
  where they are explicitly configured
- **Numbers, not values.** Indicators, logs and error messages must never contain
  real values, tokens or entity paths
- **No new runtime dependencies** without a clear reason. The dependency list is
  deliberately short (axum, tokio, reqwest+rustls, argon2, xsalsa20poly1305,
  regex, serde, clap): every one of them has to be auditable, and the binary has
  to stay self-contained on all three platforms

## Style

- Rust 2021, `cargo fmt` clean, `clippy -D warnings` clean
- Comments explain *why*, not *what*; the codebase is written to be read by
  someone auditing it
- Platform neutrality: no `#[cfg(unix)]`-only shortcuts, no shelling out, no
  filesystem paths that assume `/` — CI builds and tests Windows, macOS and Linux
- Japanese and English are both fine in comments and docs. User-facing CLI output
  is Japanese today; keep it consistent within a surface

## Commits and pull requests

- One logical change per commit; the subject line says what changed and why
- Run `cargo test` and `cargo clippy --all-targets -- -D warnings` before
  pushing — CI runs the same on Linux, macOS and Windows
- In the pull request, state the threat-model impact: does this widen what can
  leave the machine? If yes, say so explicitly

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## Website

`site/index.html` is a single self-contained file with no external requests —
please keep it that way (no CDN fonts, no analytics, no third-party scripts).
It is deployed to <https://mask.branchead.com/> as an assets-only Cloudflare
Worker on its own subdomain; see `wrangler.jsonc`.

```sh
python3 -m http.server 8877 -d site    # preview locally
npx wrangler deploy                    # publish (maintainers only)
```

## License

Contributions are accepted under the [MIT License](LICENSE).
