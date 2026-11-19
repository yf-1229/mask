"""Shell entrance: the `mask` command.

The gateway is the machine's entrance (agents arrive via the proxy); the
CLI is the human's entrance from the shell:

    mask check '...'   # dry-run: what would be masked, no network, no LLM
    mask chat '...'     # one prompt, through the gateway, restored answer
    mask status         # reliability indicator panel of a running gateway
    mask serve          # start the gateway (same as mask-server)

Output discipline: masked/checked text goes to stdout so it can be piped;
indicators go to stderr so pipes stay clean; exit status is 0 even when
PII is detected (detection is the tool working, not failing).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import httpx

from mask.detect.base import DetectionResult, EntityType
from mask.gateway.config import GatewayConfig
from mask.pipeline import Session

# --- ANSI --------------------------------------------------------------------

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

TYPE_JA: dict[EntityType, str] = {
    EntityType.PERSON: "人名",
    EntityType.ORG: "組織",
    EntityType.LOCATION: "地名",
    EntityType.ADDRESS: "住所",
    EntityType.PHONE: "電話",
    EntityType.EMAIL: "メール",
    EntityType.ACCOUNT: "口座",
}


def _paint(text: str, color: str, colorize: bool) -> str:
    return f"{color}{text}{RESET}" if colorize else text


def _light(ok: bool, colorize: bool) -> str:
    return _paint("●", GREEN if ok else YELLOW, colorize)


def light(ok: bool, colorize: bool) -> str:
    """Indicator lamp: green when the guarantee holds, amber otherwise."""
    return _light(ok, colorize)


# --- session / config helpers ------------------------------------------------


def _session_for(config: GatewayConfig) -> Session:
    from mask.detect.dictionary import UserDictionary

    dictionary = (
        UserDictionary.load(config.dictionary_path)
        if config.dictionary_path
        else UserDictionary()
    )
    return Session(dictionary=dictionary, use_ner=config.use_ner)


def _gateway_url(config: GatewayConfig, url_override: str | None) -> str:
    if url_override:
        return url_override.rstrip("/")
    host = config.host
    port = config.port
    banner = "http"
    return f"{banner}://{host}:{port}"


def _fetch_snapshot(base_url: str, token: str, timeout: float) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    resp = httpx.get(f"{base_url}/status", headers=headers, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


# --- rendering ---------------------------------------------------------------


def render_status(snapshot: dict[str, Any], colorize: bool = True) -> str:
    """Indicator panel for `mask status` and the website widget (pure)."""
    posture = snapshot.get("posture", {})
    counts = snapshot.get("counts", {})
    lines: list[str] = []

    lines.append(
        _paint("mask gateway — reliability indicators", BOLD, colorize)
    )
    lines.append(_paint(f"uptime {snapshot.get('uptime_seconds', 0):.0f}s", DIM, colorize))
    lines.append("")
    lines.append(
        f"{light(posture.get('leak_gate_active', False), colorize)} "
        f"leak gate        {posture.get('leak_gate', '?')}"
        + (
            _paint("  (fail-closed)", GREEN, colorize)
            if posture.get("leak_gate_active")
            else _paint("  (warn only — PII may pass)", RED, colorize)
        )
    )
    lines.append(
        f"{light(True, colorize)} session         {posture.get('session_scope', '?')}"
        f"  (mapping table: {posture.get('mapping_records', 0)} records)"
    )
    lines.append(
        f"{light(bool(posture.get('ner')), colorize)} ner             "
        + ("ja_ginza detection on" if posture.get("ner") else "off — rules/dictionary only")
    )
    lines.append(
        f"{light(True, colorize)} dictionary      {posture.get('dictionary_terms', 0)} terms"
    )
    token_set = bool(posture.get("gateway_token"))
    lines.append(
        f"{light(token_set, colorize)} gateway token  "
        + ("required (both entrances)" if token_set else "not set (localhost only)")
    )
    lines.append("")
    for label, key in (
        ("requests", "requests_total"),
        ("entities masked", "entities_masked"),
        ("tokens restored", "tokens_restored"),
        ("leak blocks", "leak_blocks"),
        ("paths denied", "paths_denied"),
        ("auth denied", "auth_denied"),
    ):
        lines.append(f"  {label:<16}{_paint(str(counts.get(key, 0)), DIM, colorize)}")
    unresolved = counts.get("tokens_unresolved", 0)
    lines.append(
        f"  {'unresolved':<16}"
        + _paint(str(unresolved), GREEN if unresolved == 0 else RED, colorize)
    )
    fenced = counts.get("tokens_fuzzy_repaired", 0)
    if fenced:
        lines.append(
            f"  {'repaired tokens':<16}"
            + _paint(str(fenced), YELLOW, colorize)
        )
    return "\n".join(lines)


def render_check(
    masked_text: str, result: DetectionResult, colorize: bool = True
) -> str:
    """Indicator report for `mask check` (pure; text output separate)."""
    by_type: dict[str, int] = {}
    for e in result.entities:
        label = TYPE_JA.get(e.type, str(e.type))
        by_type[label] = by_type.get(label, 0) + 1
    lines = []
    lines.append(
        f"  {light(len(result.entities) > 0, colorize)} detected edge   "
        f"{_paint(str(len(result.entities)), BOLD, colorize)} entities"
        + (
            f"  ({', '.join(f'{k} {v}' for k, v in sorted(by_type.items()))})"
            if by_type
            else "  (nothing found — check the dictionary)"
        )
    )
    lines.append(
        f"  {light(True, colorize)} ready          phrases like this leave the "
        "machine only as " + _paint("⟦token⟧", DIM, colorize) + " via the "
        "gateway (if the gateway isn't running, run `mask serve` next)"
    )
    return "\n".join(lines)


# --- subcommands -------------------------------------------------------------


def cmd_check(args: argparse.Namespace, config: GatewayConfig) -> int:
    text = _read_prompt(args)
    if text is None:
        print("error: no text given (pass it as an argument or pipe via stdin)", file=sys.stderr)
        return 1
    session = _session_for(config)
    masked, result = session.masked(text)
    print(masked)
    print(_paint("[mask check]", DIM, args.color), file=sys.stderr)
    print(render_check(masked, result, colorize=args.color), file=sys.stderr)
    return 0


def cmd_chat(args: argparse.Namespace, config: GatewayConfig) -> int:
    prompt = _read_prompt(args)
    if not prompt:
        print("error: no prompt given", file=sys.stderr)
        return 1
    base = _gateway_url(config, args.url)
    token = config.gateway_token
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        resp = httpx.post(
            f"{base}/v1/chat/completions",
            headers=headers,
            json={
                "model": args.model,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=args.timeout,
        )
    except httpx.HTTPError as exc:
        print(f"error: gateway at {base} unreachable ({exc.__class__.__name__}); is `mask serve` running?", file=sys.stderr)
        return 1
    if resp.status_code != 200:
        try:
            err = resp.json()["error"]
        except (ValueError, KeyError):
            err = {"message": resp.text[:200]}
        print(f"error: gateway returned {resp.status_code}: {err.get('message')}", file=sys.stderr)
        return 1
    data = resp.json()
    content = ""
    for choice in data.get("choices", []):
        message = choice.get("message") or {}
        if isinstance(message.get("content"), str):
            content = message["content"]
            break
    print(content)
    # Instant-reliability footer: the gateway's own per-request indicators.
    masked_n = resp.headers.get("X-Mask-Masked", "?")
    restored_n = resp.headers.get("X-Mask-Restored", "?")
    unresolved_n = resp.headers.get("X-Mask-Unresolved", "0")
    clean = unresolved_n in ("0", "?")
    line = (
        f"masked {masked_n} / restored {restored_n} / unresolved {unresolved_n}"
        f" / leak gate {resp.headers.get('X-Mask-Leak-Gate', '?')}"
    )
    print(
        _paint("[mask] ", DIM, args.color)
        + _paint(line, GREEN if clean else RED, args.color),
        file=sys.stderr,
    )
    return 0


def cmd_status(args: argparse.Namespace, config: GatewayConfig) -> int:
    base = _gateway_url(config, args.url)
    token = config.gateway_token
    try:
        snapshot = _fetch_snapshot(base, token, args.timeout)
    except httpx.HTTPError as exc:
        print(
            f"error: gateway at {base} unreachable ({exc.__class__.__name__})", file=sys.stderr
        )
        return 1
    print(render_status(snapshot, colorize=args.color))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from mask.gateway import main as serve_main

    serve_argv = ["--log-level", args.log_level] + (
        ["--config", args.config] if args.config else []
    )
    serve_main(serve_argv)
    return 0


def _read_prompt(args: argparse.Namespace) -> str | None:
    """Prompt text: positional args joined, or piped stdin if no args."""
    if args.text:
        return " ".join(args.text)
    if not sys.stdin.isatty():
        return sys.stdin.read() or None
    return None


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", help="path to mask.toml (default: $MASK_CONFIG or ./mask.toml)")
    parser.add_argument("--no-color", dest="color", action="store_false", help="disable ANSI colors")
    parser.set_defaults(color=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mask",
        description="mask — PII pseudonymization: shell entrance to the mask gateway",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="dry-run mask: show what would be pseudonymized (no network)")
    _add_common(p_check)
    p_check.add_argument("text", nargs="*", help="text to check (or pipe via stdin)")
    p_check.add_argument("-", dest="stdin", action="store_true", help=argparse.SUPPRESS)

    p_chat = sub.add_parser("chat", help="one prompt through the gateway; answer is restored PII")
    _add_common(p_chat)
    p_chat.add_argument("text", nargs="*", help="prompt (or pipe via stdin)")
    p_chat.add_argument("--model", default="gpt-4o-mini", help="model for upstream (default: gpt-4o-mini)")
    p_chat.add_argument("--url", help="gateway base URL (default: config server host/port)")
    p_chat.add_argument("--timeout", type=float, default=120.0)
    p_chat.add_argument("-", dest="stdin", action="store_true", help=argparse.SUPPRESS)

    p_status = sub.add_parser("status", help="reliability indicator panel of the running gateway")
    _add_common(p_status)
    p_status.add_argument("--url", help="gateway base URL (default: config server host/port)")
    p_status.add_argument("--timeout", type=float, default=5.0)
    p_status.add_argument("--json", action="store_true", help="raw /status JSON")

    p_serve = sub.add_parser("serve", help="start the gateway (same as mask-server)")
    _add_common(p_serve)
    p_serve.add_argument("--log-level", default="info")

    args = parser.parse_args(argv)
    if args.command == "serve":
        return cmd_serve(args)

    config = GatewayConfig.load(args.config)

    if args.command == "check":
        return cmd_check(args, config)
    if args.command == "chat":
        return cmd_chat(args, config)
    if args.command == "status":
        if getattr(args, "json", False):
            base = _gateway_url(config, args.url)
            try:
                snapshot = _fetch_snapshot(base, config.gateway_token, args.timeout)
            except httpx.HTTPError as exc:
                print(f"error: gateway unreachable ({exc.__class__.__name__})", file=sys.stderr)
                return 1
            print(json.dumps(snapshot, ensure_ascii=False, indent=2))
            return 0
        return cmd_status(args, config)
    return 1


if __name__ == "__main__":
    sys.exit(main())
