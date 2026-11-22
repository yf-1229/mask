# Contributing to mask

Thanks for taking a look. This is a small, opinionated project: the guarantee
("a detected value never leaves") is structural, and changes that weaken it are
rejected even when they are convenient.

## Getting set up

```sh
git clone https://github.com/yf-1229/mask.git && cd mask
cargo build            # debug binary at target/debug/mask
cargo test             # 159 tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check

cargo build --release && sh scripts/install-test.sh
                       # the .deb and install.sh, against a local mirror
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

## Packaging

Two front doors, one binary. Neither adds a second copy of it:

```sh
packaging/debian/build-deb.sh                       # -> dist/mask_<version>_<arch>.deb
scripts/install-test.sh                             # both doors, against a local mirror
```

- `packaging/debian/build-deb.sh` takes an already-built binary and writes a
  `.deb` with `dpkg-deb` alone — no `dpkg-buildpackage`, no debhelper. It derives
  `Architecture` from the ELF header and the `libc6` floor from the versioned
  symbols the binary imports, so the metadata cannot drift from the payload. The
  package ships the binary, the man page and the documents: **no service, no
  `/etc` configuration** — starting the gateway is a human's act, and the config
  holds the upstream key
- `scripts/install.sh` is what `https://mask.branchead.com/install.sh` serves.
  The site copy is staged from this file at deploy time (`.github/workflows/deploy-site.yml`),
  so there is one script, not two. It must stay POSIX `sh`, verify against
  `SHA256SUMS`, and fail closed when the sums are missing
- `scripts/install-test.sh` is the CI gate for both. It builds the package,
  checks the metadata and payload against what the README promises, unpacks it,
  and drives the installer through the cases that must fail. `dpkg -i` runs there
  too, on a throwaway runner, behind `MASK_TEST_DPKG_INSTALL=1`
- A release is a tag: `.github/workflows/release.yml` builds Linux inside a
  Debian 12 container (so the glibc floor is the oldest one the project supports,
  not the newest runner's), builds macOS and Windows natively, and publishes the
  binaries, the `.deb`, stable `mask_<arch>.deb` aliases and `SHA256SUMS`

## Website

`site/index.html` is a single self-contained file with no external requests —
please keep it that way (no CDN fonts, no analytics, no third-party scripts).
It is deployed to <https://mask.branchead.com/> as an assets-only Cloudflare
Worker on its own subdomain; see `wrangler.jsonc`.

```sh
cp scripts/install.sh site/install.sh   # what the deploy workflow stages
python3 -m http.server 8877 -d site    # preview locally
npx wrangler deploy                    # publish (maintainers only)
```

## License

Contributions are accepted under the [MIT License](LICENSE).
