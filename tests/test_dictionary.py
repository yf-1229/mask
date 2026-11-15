"""Tests for the user dictionary layer."""

import textwrap

from mask.detect.base import EntityType
from mask.pipeline import Session
from tests.conftest import make_session_with_dict


def test_exact_term_detected():
    s = make_session_with_dict({"山田太郎": "person"})
    masked, result = s.masked("昨日、山田太郎さんから電話がありました")
    assert any(
        e.type == EntityType.PERSON and e.text == "山田太郎"
        for e in result.entities
    )
    assert "山田太郎" not in masked
    # and round-trips
    out = s.unmasked(masked)
    assert "山田太郎" in out.text


def test_longest_match_wins():
    s = make_session_with_dict({"山田": "person", "山田太郎": "person"})
    _, result = s.masked("山田太郎の弟の山田次郎")
    texts = [e.text for e in result.entities if e.type == EntityType.PERSON]
    assert "山田太郎" in texts  # longest form detected, not split 山田/太郎
    assert "山田太郎" == next(t for t in texts if "太郎" in t)


def test_covered_substring_not_double_detected():
    s = make_session_with_dict({"山田": "person", "山田太郎": "person"})
    _, result = s.masked("山田太郎に会った")
    p = [e for e in result.entities if e.source == "dict"]
    assert len(p) == 1 and p[0].text == "山田太郎"


def test_load_tsv(tmp_path):
    f = tmp_path / "dict.tsv"
    f.write_text(
        textwrap.dedent(
            """\
            # comment lines are ignored
            鈴木一郎\tperson
            ○○銀行\torg
            """
        ),
        encoding="utf-8",
    )
    from mask.detect.dictionary import UserDictionary

    d = UserDictionary.load(f)
    s = Session(dictionary=d)
    masked, _ = s.masked("鈴木一郎は○○銀行の融資を受けた")
    assert "鈴木一郎" not in masked and "○○銀行" not in masked


def test_missing_file_is_empty_dict():
    from mask.detect.dictionary import UserDictionary

    d = UserDictionary.load("/nonexistent/dict.tsv")
    assert d.scan("山田太郎です") == []
