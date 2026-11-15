"""Tests for the restore layer: exact restore, fuzzy repair, stream buffer,
audit, and the never-guess guarantee."""

from mask.detect.base import EntityType
from mask.replace import PseudonymMap
from mask.restore import (
    restore,
    restore_stream_buffer,
    audit_output,
    _levenshtein,
)


def _mapped_pair(value: str = "山田太郎"):
    p = PseudonymMap()
    rec = p.assign(EntityType.PERSON, value)
    return p, rec


def test_exact_restore():
    p, rec = _mapped_pair()
    out = restore(f"ご担当者は{rec.token}様ですね", p)
    assert out.text == "ご担当者は山田太郎様ですね"
    assert out.restored == 1
    assert not out.warnings


def test_multi_token_restore():
    p, rec = _mapped_pair()
    addr = p.assign(EntityType.ADDRESS, "港区赤坂一丁目2番3号")
    out = restore(f"{rec.token}様は{addr.token}在住です", p)
    assert out.text == "山田太郎様は港区赤坂一丁目2番3号在住です"


def test_mutated_token_fuzzy_repaired_with_warning():
    p, rec = _mapped_pair()
    mutated = rec.token.replace("⟧", "")  # lost closing bracket
    out = restore(f"担当は{mutated}です", p)
    # never guessed silently: either repaired with a warning or kept verbatim
    assert out.fuzzy_repaired == 1 or out.unresolved_tokens
    if out.fuzzy_repaired:
        assert out.text == "担当は山田太郎です"
        assert out.warnings


def test_hallucinated_token_never_guesses_other_entity():
    """A well-formed token that maps to nothing stays verbatim. It must not
    be fuzzy-matched to a different token's value."""
    p = PseudonymMap()
    p.assign(EntityType.PERSON, "山田太郎")   # ⟦人名X⟧ for some X
    out = restore("担当は⟦人名999⟧です", p)
    assert "⟦人名999⟧" in out.text
    assert "山田太郎" not in out.text


def test_stream_buffer_holds_partial_tokens():
    assert restore_stream_buffer("こんにちは⟦人名", None) == ("こんにちは", "⟦人名")
    assert restore_stream_buffer("こんにちは⟦人名17⟧", None) == ("こんにちは⟦人名17⟧", "")


def test_stream_buffer_no_hold_when_no_token_start():
    assert restore_stream_buffer("普通のテキスト", None) == ("普通のテキスト", "")


def test_levenshtein_cap():
    assert _levenshtein("⟦人名17⟧", "⟦人名17⟧") == 0
    assert _levenshtein("⟦人名17", "⟦人名17⟧") == 1
    assert _levenshtein("あいうえおかきくけこ", "全然違う文字列です") > 2


def test_audit_flags_direct_leak():
    """If the model emitted the real value by itself, audit must flag it."""
    p = PseudonymMap()
    p.assign(EntityType.PERSON, "山田太郎")
    # model hallucinated the raw value without ever receiving a token for it
    warnings = audit_output(
        text_before="担当は⟦人名999⟧です",
        text_after="担当は山田太郎です",
        pseudonyms=p,
    )
    assert any("beyond restored occurrences" in w for w in warnings)


def test_audit_flags_token_residue():
    p = PseudonymMap()
    p.assign(EntityType.PERSON, "山田太郎")
    warnings = audit_output("x", "残骸⟦人名999⟧残り", p)
    assert any("token residue" in w for w in warnings)


def test_restore_failure_keeps_placeholder_not_guess():
    """Restore miss → placeholder stays, warning set, no invented value."""
    p, rec = _mapped_pair()
    out = restore("⟦住所77⟧の近くで会いましょう", p)
    assert "⟦住所77⟧" in out.text
    assert out.unresolved_tokens == ["⟦住所77⟧"]
    assert out.warnings
