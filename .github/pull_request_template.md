## What changed

<!-- One or two sentences. What behaviour is different now? -->

## Why

<!-- The problem this solves. Link the issue if there is one. -->

## Threat-model impact

<!--
Does this widen what can leave the machine, add a path that skips the masking
layer or the leak gate, or expose values in logs or indicators?
If yes, say so explicitly. If no, say why.
-->

## Checklist

- [ ] `uv run pytest` passes locally
- [ ] New or changed behaviour has a test
- [ ] No real personal data in code, tests, fixtures or this description
- [ ] Indicators and logs still contain numbers only — no values, tokens or entity paths
- [ ] Docs updated (`README.md`, `README.ja.md`, `SECURITY.md`) if behaviour is user-visible
