"""Encrypted handoff tests: seal/unseal, table merge policy, admin flow.

The handoff scenario: teammate A masks a conversation, seals the mapping
table, sends the envelope over any channel; teammate B's gateway unseals
and merges it — after which the same person masks to the same token on
both sides, and A's artifacts restore on B's gateway.
"""

import base64
import json

import pytest
from nacl.exceptions import CryptoError

from mask.detect.base import EntityType
from mask.gateway.sharing import seal, unseal
from mask.replace import PseudonymMap, TOKEN_CLOSE, TOKEN_OPEN
from tests.test_gateway_guard import _make_client, _post

AUTH = {"Authorization": "Bearer team-secret"}


# --- envelope crypto ---------------------------------------------------------


def test_seal_unseal_roundtrip():
    payload = {
        "v": 1,
        "records": [
            {"token": f"{TOKEN_OPEN}人名17{TOKEN_CLOSE}", "value": "山田太郎", "occurrences": 2}
        ],
    }
    envelope = seal(payload, "team-pass")
    assert envelope["v"] == 1
    assert unseal(envelope, "team-pass") == payload


def test_wrong_passphrase_raises():
    envelope = seal({"a": 1}, "right")
    with pytest.raises(CryptoError):
        unseal(envelope, "wrong")


def test_tampered_ciphertext_raises():
    envelope = seal({"a": 1}, "right")
    boxed = bytearray(base64.b64decode(envelope["boxed"]))
    boxed[-1] ^= 1
    envelope["boxed"] = base64.b64encode(bytes(boxed)).decode("ascii")
    with pytest.raises(CryptoError):
        unseal(envelope, "right")


def test_seal_rejects_empty_passphrase():
    with pytest.raises(ValueError):
        seal({"a": 1}, "")


def test_unseal_rejects_unknown_version():
    with pytest.raises(ValueError):
        unseal({"v": 99}, "x")


# --- table merge policy --------------------------------------------------------


def test_export_import_roundtrip_preserves_tokens():
    src = PseudonymMap()
    src.assign(EntityType.PERSON, "山田太郎")
    src.assign(EntityType.EMAIL, "taro@example.com")
    dst = PseudonymMap()
    for rec in src.export_records():
        assert dst.import_record(rec["token"], rec["value"]) == "imported"
    # same value -> same token on the receiving side
    assert dst.assign(EntityType.PERSON, "山田太郎").token == (
        src.assign(EntityType.PERSON, "山田太郎").token
    )


def test_import_never_rebinds_a_token():
    pm = PseudonymMap()
    pm.assign(EntityType.PERSON, "山田太郎")
    token = pm.export_records()[0]["token"]
    assert pm.import_record(token, "別の人物") == "conflict"
    assert pm.restore_value(token) == "山田太郎"  # local binding wins


def test_import_same_value_is_already():
    pm = PseudonymMap()
    pm.assign(EntityType.PERSON, "山田太郎")
    token = pm.export_records()[0]["token"]
    assert pm.import_record(token, "山田太郎") == "already"


def test_import_rejects_malformed_records():
    pm = PseudonymMap()
    assert pm.import_record("人名17", "x") == "invalid"  # no brackets
    assert pm.import_record(f"{TOKEN_OPEN}人名17{TOKEN_CLOSE}", "") == "invalid"
    assert pm.import_record(f"{TOKEN_OPEN}謎label17{TOKEN_CLOSE}", "x") == "invalid"


def test_imported_values_feed_the_leak_gate():
    pm = PseudonymMap()
    pm.import_record(f"{TOKEN_OPEN}人名17{TOKEN_CLOSE}", "山田太郎")
    assert pm.raw_values() == {"山田太郎"}


# --- gateway admin flow --------------------------------------------------------


def test_export_import_handoff_between_gateways(tmp_path):
    # teammate A: masks a conversation, then seals the table
    src_client, src_captured = _make_client(
        tmp_path, [("山田太郎", "person")], gateway_token="team-secret"
    )
    resp = _post(src_client, "山田太郎さんの件", headers=AUTH)
    assert resp.status_code == 200
    src_masked = json.loads(src_captured["request"].content)["messages"][0]["content"]

    resp = src_client.post("/admin/export", json={"passphrase": "handoff"}, headers=AUTH)
    assert resp.status_code == 200
    assert resp.json()["count"] == 1
    envelope = resp.json()["envelope"]

    # teammate B: fresh gateway, same dictionary, unseals and merges
    dst_client, dst_captured = _make_client(
        tmp_path, [("山田太郎", "person")], gateway_token="team-secret"
    )
    resp = dst_client.post(
        "/admin/import",
        json={"passphrase": "handoff", "envelope": envelope},
        headers=AUTH,
    )
    assert resp.status_code == 200
    assert resp.json()["result"] == {
        "imported": 1,
        "already": 0,
        "conflict": 0,
        "invalid": 0,
    }

    # same person -> same token on both sides
    resp = _post(dst_client, "山田太郎さんの件", headers=AUTH)
    assert resp.status_code == 200
    dst_masked = json.loads(dst_captured["request"].content)["messages"][0]["content"]
    assert dst_masked == src_masked
    # and A's artifact restores on B's gateway
    assert "山田太郎" in resp.json()["choices"][0]["message"]["content"]


def test_admin_disabled_without_gateway_token(tmp_path):
    client, _ = _make_client(tmp_path)
    resp = client.post("/admin/export", json={"passphrase": "x"})
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "mask_admin_disabled"


def test_admin_requires_auth_header(tmp_path):
    client, _ = _make_client(tmp_path, gateway_token="team-secret")
    resp = client.post("/admin/export", json={"passphrase": "x"})
    assert resp.status_code == 401


def test_export_requires_passphrase(tmp_path):
    client, _ = _make_client(tmp_path, gateway_token="team-secret")
    resp = client.post("/admin/export", json={}, headers=AUTH)
    assert resp.status_code == 400


def test_import_wrong_passphrase_is_rejected(tmp_path):
    src_client, _ = _make_client(
        tmp_path, [("山田太郎", "person")], gateway_token="team-secret"
    )
    _post(src_client, "山田太郎さんの件", headers=AUTH)
    envelope = src_client.post(
        "/admin/export", json={"passphrase": "right"}, headers=AUTH
    ).json()["envelope"]

    dst_client, _ = _make_client(tmp_path, gateway_token="team-secret")
    resp = dst_client.post(
        "/admin/import",
        json={"passphrase": "wrong", "envelope": envelope},
        headers=AUTH,
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "mask_unseal_failed"


def test_admin_rejects_request_scope(tmp_path):
    client, _ = _make_client(
        tmp_path, gateway_token="team-secret", session_scope="request"
    )
    resp = client.post("/admin/export", json={"passphrase": "x"}, headers=AUTH)
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "mask_scope_unsupported"
