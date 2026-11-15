"""Outbound leak gate: the last line of defense before anything leaves.

Masking covers the request shapes the gateway knows about; the gate is a
positive control behind it. Every payload about to leave the gateway is
walked as a JSON structure and every string in it — dict keys included —
is checked (NFKC-normalized, containment) against the raw entity values
the session has ever detected. A hit means a field the masking layer does
not cover carries real PII, so the request is refused before it reaches
the network (fail closed).

What this guarantees: no value the session has detected can leave the
machine, on any field, path, or header — even where masking missed the
spot (unanticipated fields, detection misses on repeat mentions, client
headers). What it cannot catch: values never detected anywhere; that is
the detection layer's job, regression-gated by the canary corpus.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mask.replace import normalize_key

# Shorter values are noise (single kana/kanji match everywhere).
MIN_VALUE_LEN = 2


@dataclass(frozen=True)
class Leak:
    value: str  # NFKC-normalized raw value found
    path: str   # where in the payload it was found


def find_leaks(obj: Any, values: set[str]) -> list[Leak]:
    """Return known raw values found anywhere in a JSON-like structure.

    `values` must be NFKC-normalized (PseudonymMap.raw_values() is).
    Matching is containment, so partial re-mentions are caught too.
    """
    candidates = [v for v in values if len(v) >= MIN_VALUE_LEN]
    if not candidates:
        return []
    leaks: list[Leak] = []

    def check(text: str, path: str) -> None:
        hay = normalize_key(text)
        for value in candidates:
            if value in hay:
                leaks.append(Leak(value=value, path=path))

    def walk(node: Any, path: str) -> None:
        if isinstance(node, str):
            check(node, path or "<root>")
        elif isinstance(node, dict):
            for key, child in node.items():
                child_path = f"{path}.{key}" if path else str(key)
                if isinstance(key, str):
                    check(key, f"{child_path}(key)")
                walk(child, child_path)
        elif isinstance(node, list):
            for i, child in enumerate(node):
                walk(child, f"{path}[{i}]" if path else f"[{i}]")

    walk(obj, "")
    return leaks


def find_header_leaks(headers: dict[str, str], values: set[str]) -> list[Leak]:
    """Check forwarded header values; reported as header:<name>."""
    leaks: list[Leak] = []
    for name, value in headers.items():
        if not isinstance(value, str):
            continue
        for leak in find_leaks(value, values):
            leaks.append(Leak(value=leak.value, path=f"header:{name}"))
    return leaks
