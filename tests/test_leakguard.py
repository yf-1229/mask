"""Unit tests for the outbound leak gate."""

from mask.detect.base import EntityType
from mask.gateway.leakguard import find_header_leaks, find_leaks
from mask.replace import PseudonymMap, TOKEN_CLOSE, TOKEN_OPEN


def test_finds_value_in_nested_structure():
    body = {
        "messages": [
            {
                "role": "user",
                "content": f"{TOKEN_OPEN}人名1{TOKEN_CLOSE}です",
                "metadata": {"owner": "山田太郎"},
            }
        ]
    }
    leaks = find_leaks(body, {"山田太郎"})
    assert [(l.value, l.path) for l in leaks] == [
        ("山田太郎", "messages[0].metadata.owner")
    ]


def test_checks_dict_keys_too():
    leaks = find_leaks({"data": {"山田太郎": 1}}, {"山田太郎"})
    assert leaks
    assert leaks[0].path == "data.山田太郎(key)"


def test_nfkc_matches_fullwidth_variants():
    leaks = find_leaks({"user": "０９０－１２３４－５６７８"}, {"090-1234-5678"})
    assert leaks


def test_short_values_are_ignored():
    assert find_leaks({"a": "山"}, {"山"}) == []


def test_empty_values_is_noop():
    assert find_leaks({"a": "anything"}, set()) == []


def test_root_string_payload():
    leaks = find_leaks("山田太郎です", {"山田太郎"})
    assert leaks and leaks[0].path == "<root>"


def test_header_values_are_checked():
    leaks = find_header_leaks({"x-title": "山田太郎の相談"}, {"山田太郎"})
    assert leaks and leaks[0].path == "header:x-title"


def test_pseudonym_map_tracks_every_variant():
    pm = PseudonymMap()
    pm.assign(EntityType.PERSON, "山田太郎")
    pm.assign(EntityType.PERSON, "山田")  # containment variant
    pm.assign(EntityType.PERSON, "山田太郎")
    assert pm.raw_values() == {"山田太郎", "山田"}
