"""Restore layer: token -> original value.

Pipeline applied to LLM output:
1. Exact regex replacement of well-formed tokens.
2. Repair of mutated tokens over any remaining ⟦fragment⟧s:
   a. structural core match — lost/mangled brackets and junk chars are
      tolerated as long as the (label, id) pair is recoverable; the ID must be
      exact so we never bind a token to the wrong entity.
   b. edit-distance match — only for bracket-bounded fragments whose inner
      text does not parse as (label, id). Boundaries are unambiguous here, so
      replacing the whole fragment is safe.
3. Anything unrecoverable stays verbatim + warning flag. We never invent a
   value, and a well-formed token with an unknown ID is never fuzzy-matched to
   a near-ID token (that would resurrect a different person's name).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from mask.replace import (
    TOKEN_CLOSE,
    TOKEN_OPEN,
    PseudonymMap,
    TYPE_LABELS,
    normalize_key,
)

TOKEN_LABEL_ALTS = "|".join(re.escape(l) for l in TYPE_LABELS.values())

# Well-formed token: ⟦label + digits⟧
_TOKEN_RE = re.compile(
    TOKEN_OPEN + r"(" + TOKEN_LABEL_ALTS + r")(\d+)" + re.escape(TOKEN_CLOSE)
)

# Token with damaged brackets/junk but recoverable (label, id) core. Junk
# chars never include digits so the id run stays maximal; the closing bracket
# is only consumed when it directly follows the id (trailing junk after the id
# is treated as original text and preserved).
_FRAGMENT_RE = re.compile(
    re.escape(TOKEN_OPEN)
    + r"[^⟧\n]*"
    + re.escape(TOKEN_CLOSE) + r"?"
)
_CORE_RE = re.compile(
    re.escape(TOKEN_OPEN)
    + r"[^⟧\n\d]{0,3}"
    + r"(" + TOKEN_LABEL_ALTS + r")"
    + r"[^⟧\n\d]{0,3}"
    + r"(\d{1,3})"
    + r"(?:"
    + re.escape(TOKEN_CLOSE) + r")?"
)

_FUZZY_MAX_DISTANCE = 2


def _levenshtein(a: str, b: str, cap: int = _FUZZY_MAX_DISTANCE) -> int:
    """Row-reduced Levenshtein with early cap."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        row_min = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            cur.append(v)
            row_min = min(row_min, v)
        if row_min > cap:
            return cap + 1
        prev = cur
    return prev[-1]


@dataclass
class RestoreResult:
    text: str
    restored: int = 0
    fuzzy_repaired: int = 0
    unresolved_tokens: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def restore_stream_buffer(
    buffer: str, pseudonyms: PseudonymMap | None = None
) -> tuple[str, str]:
    """Split a streaming buffer into (safe_to_emit, keep_back).

    A token or its opening bracket at the buffer tail may still be completed by
    the next chunk, so anything that could be a token prefix is held back.
    """
    last_open = buffer.rfind(TOKEN_OPEN)
    if last_open == -1:
        return buffer, ""
    if TOKEN_CLOSE in buffer[last_open:]:
        end = buffer.index(TOKEN_CLOSE, last_open) + len(TOKEN_CLOSE)
        return buffer[:end], buffer[end:]
    # unterminated token candidate: hold back while it could still complete
    plausible = 1 + 3 + 3 + 1 + 2  # open + label + digits + close + slack
    if len(buffer) - last_open <= plausible:
        return buffer[:last_open], buffer[last_open:]
    return buffer, ""


def restore(text: str, pseudonyms: PseudonymMap) -> RestoreResult:
    """Restore all tokens in `text` using the session mapping table."""
    result = RestoreResult(text="")

    def _sub(m: re.Match) -> str:
        token = m.group(0)
        value = pseudonyms.restore_value(token)
        if value is None:
            result.unresolved_tokens.append(token)
            return token
        result.restored += 1
        return value

    result.text = _TOKEN_RE.sub(_sub, text)
    _repair_fragments(result, pseudonyms)
    return result


def _repair_fragments(result: RestoreResult, pseudonyms: PseudonymMap) -> None:
    known = pseudonyms.tokens()

    def _sub(m: re.Match) -> str:
        frag = m.group(0)
        if _TOKEN_RE.fullmatch(frag):
            # well-formed but unmapped: already collected at exact-restore
            # step. Never fuzzy-match a valid token shape to another entity.
            result.warnings.append(
                f"unmapped token kept verbatim: {frag!r}"
            )
            return frag
        core = _CORE_RE.search(frag)
        if core:
            label, digits = core.group(1), core.group(2)
            token = f"{TOKEN_OPEN}{label}{digits}{TOKEN_CLOSE}"
            value = pseudonyms.restore_value(token)
            if value is not None:
                # replace the whole core (opens at the bracket); junk after the
                # id is original text and survives
                repaired = frag[: core.start()] + value + frag[core.end() :]
                result.fuzzy_repaired += 1
                result.warnings.append(
                    f"repaired mutated token {frag!r} via {token!r}"
                )
                return repaired
            result.unresolved_tokens.append(frag)
            result.warnings.append(
                f"token {frag!r} has unknown id {digits!r}; kept verbatim"
            )
            return frag
        # bracket-bounded junk: fall back to edit distance
        if frag.startswith(TOKEN_OPEN) and frag.endswith(TOKEN_CLOSE):
            best, best_d = None, _FUZZY_MAX_DISTANCE + 1
            for token in known:
                d = _levenshtein(frag, token)
                if d < best_d:
                    best, best_d = token, d
            if best is not None and best_d <= _FUZZY_MAX_DISTANCE:
                value = pseudonyms.restore_value(best)
                if value is not None:
                    result.fuzzy_repaired += 1
                    result.warnings.append(
                        f"fuzzy-repaired token {frag!r} -> {best!r} (distance {best_d})"
                    )
                    return value
        result.unresolved_tokens.append(frag)
        result.warnings.append(f"unresolved token kept verbatim: {frag!r}")
        return frag

    result.text = _FRAGMENT_RE.sub(_sub, result.text)


def audit_output(
    text_before: str, text_after: str, pseudonyms: PseudonymMap
) -> list[str]:
    """Bidirectional post-restore check:
    - no token-shaped residue remains in the restored text
    - raw entity values do not appear more often than the tokens restored
      (an extra occurrence means the model emitted PII directly, i.e. either a
      hallucination or data the detection layer never masked)
    Returns warnings (empty list = clean).
    """
    warnings: list[str] = []
    for m in _FRAGMENT_RE.finditer(text_after):
        warnings.append(f"token residue in output: {m.group(0)!r}")
    for rec in pseudonyms.records():
        restored_hits = sum(
            1 for _ in re.finditer(re.escape(rec.token), text_before)
        )
        value = normalize_key(rec.value)
        if len(value) < 2:
            continue
        leaked = sum(
            1 for _ in re.finditer(re.escape(value), normalize_key(text_after))
        )
        if leaked > restored_hits:
            warnings.append(
                f"raw entity value beyond restored occurrences: {rec.value!r}"
            )
    return warnings
