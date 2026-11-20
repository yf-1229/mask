# Contributing to mask

Thanks for taking a look. This is a small, opinionated project: the guarantee
("a detected value never leaves") is structural, and changes that weaken it are
rejected even when they are convenient.

## Getting set up

```sh
git clone https://github.com/yf-1229/mask.git && cd mask
uv sync
uv run pytest
```

Python 3.12+ and [uv](https://docs.astral.sh/uv/) are required. The test suite
includes `ja_ginza` NER, so the first `uv sync` downloads a model.

## What a good change looks like

- **Tests first.** Every behaviour change needs a test. Security-relevant
  behaviour needs a test that fails loudly if the guarantee breaks — see
  `tests/test_gateway_guard.py` and `tests/canaries.py` for the pattern
- **No new low roads.** If you add an entrance, a protocol or a forwarded path,
  it must pass through the same masking layer, leak gate and indicators. A
  feature that bypasses them will not be merged
- **Fail closed.** When in doubt, refuse the request. `warn` modes exist only
  where they are explicitly configured
- **Numbers, not values.** Indicators, logs and error messages must never contain
  real values, tokens or entity paths
- **No new runtime dependencies** without a clear reason. The dependency list is
  deliberately short (fastapi, uvicorn, httpx, pynacl, spacy, ja_ginza)

## Style

- Python 3.12, `from __future__ import annotations`, type hints on public
  functions
- Comments explain *why*, not *what*; the codebase is written to be read by
  someone auditing it
- Japanese and English are both fine in comments and docs. User-facing CLI output
  is Japanese today; keep it consistent within a surface

## Commits and pull requests

- One logical change per commit; the subject line says what changed and why
- Run `uv run pytest` before pushing — CI runs the same suite on Python 3.12
- In the pull request, state the threat-model impact: does this widen what can
  leave the machine? If yes, say so explicitly

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## Website

`site/index.html` is a single self-contained file with no external requests —
please keep it that way (no CDN fonts, no analytics, no third-party scripts).
It is deployed to <https://branchead.com/mask/> as an assets-only Cloudflare
Worker on a path route; see `wrangler.jsonc`.

```sh
python3 -m http.server 8877 -d site    # preview locally
npx wrangler deploy                    # publish (maintainers only)
```

## License

Contributions are accepted under the [MIT License](LICENSE).
