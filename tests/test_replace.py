"""Tests for the replacement layer and session mapping table."""

import re

import pytest

from mask.detect.base import Entity, EntityType
from mask.detect.pipeline import detect
from mask.replace import (
    PseudonymMap,
    TOKEN_CLOSE,
    TOKEN_OPEN,
    mask_text,
)

TOKEN_RE = re.compile(TOKEN_OPEN + r"[^\d" + TOKEN_CLOSE + r"]+\d+" + TOKEN_CLOSE)


def _ent(etype, start, end, text, source="rule", confidence=1.0):
    return Entity(
        type=etype, start=start, end=end, text=text, confidence=confidence,
        source=source,
    )


def _d(text, spans):
    return _mk(text, [
        _ent(t, s, e, text[s:e]) for t, s, e in spans
    ])


def _mk(text, entities):
    from mask.detect.base import DetectionResult

    return DetectionResult(text=text, entities=entities)


def test_same_value_same_token():
    p = PseudonymMap()
    r1 = p.assign(EntityType.PERSON, "山田太郎")
    r2 = p.assign(EntityType.PERSON, "山田太郎")
    assert r1.token == r2.token
    assert p.restore_value(r1.token) == "山田太郎"


def test_variant_unification_prevents_fragmentation():
    p = PseudonymMap()
    full = p.assign(EntityType.PERSON, "山田太郎")
    short = p.assign(EntityType.PERSON, "山田")
    # "山田" mentions must not fragment into a second person token
    assert short.token == full.token
    # the mapping keeps the longer variant for restoration
    assert p.restore_value(full.token) == "山田太郎"


def test_id_pool_is_shuffled_not_sequential():
    """人名1 must not deterministically be the first-seen person."""
    firsts = []
    for _ in range(30):
        p = PseudonymMap()
        firsts.append(p.assign(EntityType.PERSON, "山田太郎").token)
    digits = {re.search(r"\d+", t).group(0) for t in firsts}
    assert len(digits) > 5, f"ids suspiciously predictable: {digits}"


def test_mask_text_spans_shift_correctly():
    p = PseudonymMap()
    text = "山田太郎は090-1234-5678に連絡した。山田太郎のFAXはない"
    res = _d(text, [
        (EntityType.PERSON, 0, 4),
        (EntityType.PHONE, 5, 19),
        (EntityType.PERSON, 25, 29),
    ])
    masked = mask_text(res, p)
    assert "山田太郎" not in masked
    assert "090-1234-5678" not in masked
    tokens = TOKEN_RE.findall(masked)
    # one person token appears twice; phone token once
    assert len(tokens) == 3


def test_mask_text_no_leftover_of_detected():
    p = PseudonymMap()
    text = "昨日、山田太郎さんから電話がありました"
    res = _d(text, [(EntityType.PERSON, 3, 7)])
    masked = mask_text(res, p)
    assert masked.startswith("昨日、") and masked.endswith("さんから電話がありました")
    assert TOKEN_RE.search(masked)


def test_map_has_no_export_surface():
    """Invariant: the mapping table must never be serializable."""
    p = PseudonymMap()
    p.assign(EntityType.PERSON, "山田太郎")
    forbidden = ("to_json", "to_dict", "dump", "serialize", "save")
    for name in forbidden:
        assert not hasattr(p, name)
    with pytest.raises(TypeError):
        import json

        json.dumps(p)  # type: ignore[arg-type]


def test_different_types_different_tokens():
    p = PseudonymMap()
    a = p.assign(EntityType.PERSON, "山田")
    b = p.assign(EntityType.ORG, "山田")  # unlikely but must not collide
    assert a.token != b.token
