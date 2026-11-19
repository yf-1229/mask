"""Reliability indicators: process-wide counters surfaced at /status and
in X-Mask-* response headers.

Design constraints:
- Counters only. No raw values, no tokens, no pseudonyms, no field paths —
  anything that lands here must be safe to display on a website. These
  numbers are never part of any handoff and never leave as anything but
  aggregate counts.
- Every number is monotonic per process; a restart resets the window.
- The "posture" (leak gate mode, scope, NER availability, token set) is what
  tells a user how much to trust the guarantees; the counters tell them what
  the gateway has actually done.
"""

from __future__ import annotations

import secrets
import threading
import time
from typing import Any

# Counter registry. Explicit so the snapshot shape is stable for client
# parsers (CLI panel, website widget).
COUNTS: tuple[str, ...] = (
    "requests_total",
    "requests_blocked",        # refused before anything left (auth/leak/path)
    "entities_masked",         # raw PII spans replaced by tokens
    "tokens_restored",         # tokens turned back into raw values
    "tokens_fuzzy_repaired",   # mutated tokens repaired and restored
    "tokens_unresolved",       # tokens that could not be restored
    "leak_blocks",             # outbound leak gate refusals (block mode)
    "leak_warnings",           # leak gate hits in warn mode
    "paths_denied",            # deny-by-default passthrough refusals
    "auth_denied",             # bad/absent gateway token
    "stream_requests",         # SSE requests through the buffered path
    "handoff_exports",        # /admin/export successes
    "handoff_imports",         # /admin/import successes
    "handoff_locks",           # envelopes locked after failed attempts
    "handoff_expired",         # refused at expiry
    "handoff_consumed",        # refused after earlier successful import
)


class Indicators:
    """Thread-safe counter bag attached to app.state.indicators."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started_at = time.time()
        self._counts: dict[str, int] = {name: 0 for name in COUNTS}

    def incr(self, name: str, amount: int = 1) -> None:
        with self._lock:
            if name not in self._counts:
                raise KeyError(f"unknown indicator: {name}")
            self._counts[name] += amount

    def get(self, name: str) -> int:
        with self._lock:
            return self._counts[name]

    def counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def snapshot(self, posture: dict[str, Any]) -> dict[str, Any]:
        """Static posture + live counters, ready for /status."""
        return {
            "status": "ok",
            "uptime_seconds": round(time.time() - self.started_at, 1),
            "posture": posture,
            "counts": self.counts(),
        }


class RequestMeasure:
    """Per-request accumulation of the mask/restore-side indicators."""

    def __init__(self) -> None:
        self.masked: int = 0
        self.restored: int = 0
        self.fuzzy_repaired: int = 0
        self.unresolved: int = 0

    def observe_restore(self, result: Any) -> None:
        self.restored += getattr(result, "restored", 0)
        self.fuzzy_repaired += getattr(result, "fuzzy_repaired", 0)
        self.unresolved += len(getattr(result, "unresolved_tokens", []))


def build_posture(
    config: Any, mapping_records: int, dictionary_terms: int
) -> dict[str, Any]:
    """Static posture derived from config — the trust-level part of the
    indicator system. The mapping table size is a count, never contents."""
    return {
        "leak_gate": config.leak_gate,
        "leak_gate_active": config.leak_gate == "block",
        "session_scope": config.session_scope,
        "ner": bool(config.use_ner),
        "dictionary_terms": dictionary_terms,
        "mapping_records": mapping_records,
        "gateway_token": bool(config.gateway_token),
        "admin_allow_remote": bool(config.admin_allow_remote),
        "upstream": config.upstream_base_url,
    }


def request_headers(
    measure: "RequestMeasure", config: Any, entry: str
) -> dict[str, str]:
    """X-Mask-* headers appended to every proxied response.

    The client (an agent harness or a human in a shell) sees, per response,
    that masking happened and how much was restored — with zero PII, zero
    request ids, zero entropy beyond a per-response nonce proving the header
    was minted for this response and not cached upstream of a middlebox.
    """
    measure = measure or RequestMeasure()
    return {
        "X-Mask": "on",
        "X-Mask-In": entry,                # entry protocol that served the request
        "X-Mask-Leak-Gate": config.leak_gate,
        "X-Mask-Masked": str(measure.masked),
        "X-Mask-Restored": str(measure.restored),
        "X-Mask-Fuzzy-Repaired": str(measure.fuzzy_repaired),
        "X-Mask-Unresolved": str(measure.unresolved),
        "X-Mask-Nonce": secrets.token_hex(6),
    }
