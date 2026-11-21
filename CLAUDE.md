# CLAUDE.md

Claude Code reads `CLAUDE.md`; this repository keeps one contract for every
agent, so the file is imported rather than duplicated.

@AGENTS.md

The short version, in case the import is not picked up: the running `mask`
gateway, its `mask.toml` / `~/.config/mask/mask.toml`, its `*.maskbox`
envelopes and its `/admin/*` endpoints belong to the human at the terminal. Do
not start, stop, probe or export from that instance; edit the code, run
`cargo test`, and ask before anything that touches the operator's side.
