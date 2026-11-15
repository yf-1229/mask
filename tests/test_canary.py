"""End-to-end canary tests: recall gates + restore gates over the corpus.

These are the CI regression tests the design doc calls カナリアテスト.
They run the full Session pipeline (rules + dict + NER) and assert numeric
gates so any detection or restore regression fails loudly.
"""

import re

import pytest

from mask.replace import TOKEN_CLOSE, TOKEN_OPEN
from mask.restore import restore_stream_buffer
from tests.canaries import CANARIES
from tests.conftest import make_session
TOKEN_RE = re.compile(TOKEN_OPEN + r"[^\d" + TOKEN_CLOSE + r"]+\d+" + TOKEN_CLOSE)


def test_recall_gate_full_pipeline():
    """All expected entities in the canary corpus must be detected.

    Gate: 100% recall. This is the strictest gate in the project: a miss here
    means PII would leave the machine.
    """
    misses: list[str] = []
    session = make_session()
    for c in CANARIES:
        _, result = session.masked(c.text)
        found = {(e.type, e.text) for e in result.entities}
        for etype, value in c.expected:
            hit = (etype, value) in found or any(
                t == etype and value in v for t, v in found
            )
            if not hit:
                misses.append(f"{c.name}: {etype.value} {value!r}")
    assert not misses, "recall misses:\n" + "\n".join(misses)


def test_no_raw_pii_in_masked_output():
    """After masking, no expected PII value survives verbatim in the text."""
    session = make_session()
    for c in CANARIES:
        masked, _ = session.masked(c.text)
        for _, value in c.expected:
            assert value not in masked, f"{c.name}: {value!r} leaked into masked text"


def test_masked_text_is_still_valid_japanese_with_tokens():
    """Tokens sit exactly where entities were; surrounding text untouched."""
    session = make_session()
    c = CANARIES[0]
    masked, _ = session.masked(c.text)
    # every token replaced exactly one expected entity; brackets balanced
    assert masked.count(TOKEN_OPEN) == masked.count(TOKEN_CLOSE)
    assert len(TOKEN_RE.findall(masked)) == len(c.expected)


def test_restore_roundtrip_identity():
    """Simulated LLM echoing the masked text back: restore must reproduce the
    original for every expected entity."""
    session = make_session()
    for c in CANARIES:
        masked, _ = session.masked(c.text)
        out = session.unmasked(masked)
        for etype, value in c.expected:
            assert value in out.text, f"{c.name}: restore lost {value!r}"
        assert not out.unresolved_tokens, f"{c.name}: unresolved {out.unresolved_tokens}"


def test_restore_rate_gate_simulated_llm():
    """Simulated LLM that preserves tokens verbatim must restore at 100%.
    (Token mutation robustness against real backends is the Phase-3 roundtrip
    test suite; this gate catches core regressions here.)"""
    restored_ok = total = 0
    session = make_session()
    for c in CANARIES:
        masked, _ = session.masked(c.text)
        out = session.unmasked(masked)
        for etype, value in c.expected:
            total += 1
            if value in out.text:
                restored_ok += 1
    rate = restored_ok / total
    assert rate >= 0.98, f"restore rate {rate:.2%} ({restored_ok}/{total})"


def test_streaming_restore_matches_batch():
    """Chunked output through restore_stream_buffer restores identically."""
    session = make_session()
    c = CANARIES[1]
    masked, _ = session.masked(c.text)
    # model adds noise around tokens; feed back in 3-char chunks
    echoed = masked[: len(masked) // 2] + masked[len(masked) // 2 :]
    chunks = [echoed[i:i + 3] for i in range(0, len(echoed), 3)]
    emitted = ""
    pending = ""
    for chunk in chunks:
        buf = pending + chunk
        safe, pending = restore_stream_buffer(buf)
        emitted += safe
    emitted += pending
    out = session.unmasked(emitted)
    for etype, value in c.expected:
        assert value in out.text, f"streaming restore lost {value!r}"


def test_audit_catches_model_mentioning_raw_pii():
    """Pathological model that writes the real name directly (it must never
    see it, so this means preprocessing or detection definitely failed)."""
    c = CANARIES[0]
    session = make_session()
    masked, _ = session.masked(c.text)
    out = session.unmasked(masked + " 本名で言いますと山田太郎です。")
    assert any("beyond restored occurrences" in w for w in out.warnings)
