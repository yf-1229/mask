"""Unit tests for the rule-based detection layer."""

from mask.detect.base import EntityType
from mask.detect.rules import run_rule_detection
from tests.canaries import CANARIES, Canary


def _types_with_text(entities):
    return {(e.type, e.text) for e in entities}


def test_email():
    ents = run_rule_detection("連絡先は taro.yamada+Work@example.co.jp まで")
    pairs = _types_with_text(ents)
    assert (EntityType.EMAIL, "taro.yamada+Work@example.co.jp") in pairs


def test_phone_hyphen():
    ents = run_rule_detection("電話は090-1234-5678です")
    pairs = _types_with_text(ents)
    assert (EntityType.PHONE, "090-1234-5678") in pairs


def test_phone_paren():
    ents = run_rule_detection("(03) 1234-5678 に電話")
    pairs = _types_with_text(ents)
    assert (EntityType.PHONE, "(03) 1234-5678") in pairs


def test_postal_and_address():
    ents = run_rule_detection("〒160-0022 東京都新宿区新宿三丁目1番1号サカエビル203")
    pairs = _types_with_text(ents)
    address_hits = [t for t in pairs if t[0] == EntityType.ADDRESS]
    assert address_hits, ents
    full = sorted(address_hits, key=lambda p: len(p[1]))[-1][1]
    assert "東京都新宿区" in full


def test_ward_only_address():
    ents = run_rule_detection("港区赤坂一丁目2番3号のマンション103号室です")
    pairs = _types_with_text(ents)
    assert any(t == EntityType.ADDRESS and "赤坂" in a for t, a in pairs), pairs


def test_bank_account():
    ents = run_rule_detection("普通 1234567 に振込")
    pairs = _types_with_text(ents)
    assert (EntityType.ACCOUNT, "普通 1234567") in pairs


def test_card_number():
    ents = run_rule_detection("カードは4242-4242-4242-4242")
    pairs = _types_with_text(ents)
    assert any(t == EntityType.ACCOUNT and "4242" in a for t, a in pairs)


def test_dates_not_flagged_as_phone():
    ents = run_rule_detection("納期は 2019-04-01 です。第2019-04号ではありません")
    pairs = [t for t in _types_with_text(ents) if t[0] == EntityType.PHONE]
    assert all("2019-04-01" not in a for a in [a for _, a in pairs]), pairs


def test_recall_on_canaries_rules_only():
    """Structural entities must be found by rules alone."""
    hits = misses = 0
    for c in CANARIES:
        found = _types_with_text(run_rule_detection(c.text))
        for etype, value in c.expected:
            if etype in (EntityType.PERSON, EntityType.ORG):
                continue  # NER territory
            if (etype, value) in found or any(
                t == etype and value in v for t, v in found
            ):
                hits += 1
            else:
                misses += 1
                print(f"MISS(rules) {c.name}: {etype.value} {value!r}")
    total = hits + misses
    recall = hits / total if total else 1.0
    assert recall >= 0.95, f"rule recall {recall:.2%} ({hits}/{total})"
