"""Encrypted handoff tests: seal/unseal, expiry, lockout, merge, admin flow.

The handoff scenario: teammate A masks a conversation, seals the mapping
table, sends the envelope over any channel; teammate B's gateway unseals
and merges it — after which the same person masks to the same token on
both sides, and A's artifacts restore on B's gateway.

Decryption becomes impossible in two ways (this is the security gate):
- 時間切れ: the sealed expiry passes → 410, refused even with the right
  passphrase
- 認証失敗: wrong passphrase attempts are counted per envelope; at the
  limit the envelope is locked for good (423), even for the right one
"""

import base64
import json
import time

import pytest
from nacl import pwhash, secret
from nacl.exceptions import CryptoError

import mask.gateway.sharing as sharing
from mask.detect.base import EntityType
from mask.gateway.config import GatewayConfig
from mask.gateway.sharing import (
    EnvelopeExpired,
    envelope_fingerprint,
    seal,
    unseal,
)
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
    result = unseal(envelope, "team-pass")
    assert result["records"] == payload["records"]
    assert result["exp"] == envelope["exp"]  # sealed expiry roundtrips


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


def test_seal_rejects_bad_ttl():
    with pytest.raises(ValueError):
        seal({"a": 1}, "p", ttl_seconds=0)
    with pytest.raises(ValueError):
        seal({"a": 1}, "p", ttl_seconds=-5)


def test_unseal_rejects_unknown_version():
    with pytest.raises(ValueError):
        unseal({"v": 99}, "x")


# --- expiry (時間切れ) ---------------------------------------------------------


def test_expired_envelope_is_refused(monkeypatch):
    now = time.time()
    monkeypatch.setattr(sharing.time, "time", lambda: now)
    envelope = seal({"v": 1, "records": []}, "p", ttl_seconds=10)
    monkeypatch.setattr(sharing.time, "time", lambda: now + 11)
    with pytest.raises(EnvelopeExpired):
        unseal(envelope, "p")


def test_rewound_clear_expiry_fast_fails():
    envelope = seal({"v": 1, "records": []}, "p", ttl_seconds=60)
    envelope["exp"] = int(time.time()) - 1  # rewind the clear copy only
    with pytest.raises(EnvelopeExpired):
        unseal(envelope, "p")


def test_payload_without_expiry_fails_closed():
    # hand-crafted envelope whose sealed payload lacks exp: refused even
    # though the clear copy claims a future expiry
    salt = b"\x00" * pwhash.argon2id.SALTBYTES
    key = pwhash.argon2id.kdf(
        secret.SecretBox.KEY_SIZE,
        b"p",
        salt,
        opslimit=sharing.KDF_OPSLIMIT,
        memlimit=sharing.KDF_MEMLIMIT,
    )
    boxed = secret.SecretBox(key).encrypt(
        json.dumps({"v": 1, "records": []}).encode("utf-8")
    )
    envelope = {
        "v": 1,
        "exp": int(time.time()) + 3600,
        "kdf": {
            "name": "argon2id",
            "salt": base64.b64encode(salt).decode("ascii"),
            "opslimit": sharing.KDF_OPSLIMIT,
            "memlimit": sharing.KDF_MEMLIMIT,
        },
        "boxed": base64.b64encode(bytes(boxed)).decode("ascii"),
    }
    with pytest.raises(EnvelopeExpired):
        unseal(envelope, "p")


def test_fingerprint_is_stable_for_copies_and_unique_per_envelope():
    e1 = seal({"a": 1}, "p")
    assert envelope_fingerprint(e1) == envelope_fingerprint(
        json.loads(json.dumps(e1))
    )
    e2 = seal({"a": 1}, "p")
    assert envelope_fingerprint(e1) != envelope_fingerprint(e2)


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


def test_export_carries_expiry(tmp_path):
    client, _ = _make_client(tmp_path, gateway_token="team-secret")
    resp = client.post(
        "/admin/export",
        json={"passphrase": "p", "ttl_seconds": 60},
        headers=AUTH,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["envelope"]["exp"] == body["expires_at"]
    assert body["expires_at"] > time.time()


def test_export_rejects_bad_ttl(tmp_path):
    client, _ = _make_client(tmp_path, gateway_token="team-secret")
    resp = client.post(
        "/admin/export", json={"passphrase": "p", "ttl_seconds": 0}, headers=AUTH
    )
    assert resp.status_code == 400


def test_import_expired_envelope_is_gone(tmp_path, monkeypatch):
    src_client, _ = _make_client(
        tmp_path, [("山田太郎", "person")], gateway_token="team-secret"
    )
    real = time.time
    monkeypatch.setattr(sharing.time, "time", lambda: real() - 3600)
    resp = src_client.post(
        "/admin/export", json={"passphrase": "p", "ttl_seconds": 60}, headers=AUTH
    )
    monkeypatch.setattr(sharing.time, "time", real)
    envelope = resp.json()["envelope"]

    dst_client, _ = _make_client(tmp_path, gateway_token="team-secret")
    resp = dst_client.post(
        "/admin/import", json={"passphrase": "p", "envelope": envelope}, headers=AUTH
    )
    assert resp.status_code == 410
    assert resp.json()["error"]["code"] == "mask_envelope_expired"


def test_lockout_after_failed_attempts(tmp_path):
    src_client, _ = _make_client(
        tmp_path, [("山田太郎", "person")], gateway_token="team-secret"
    )
    _post(src_client, "山田太郎さんの件", headers=AUTH)
    envelope = src_client.post(
        "/admin/export", json={"passphrase": "right"}, headers=AUTH
    ).json()["envelope"]

    dst_client, _ = _make_client(tmp_path, gateway_token="team-secret")
    r1 = dst_client.post(
        "/admin/import", json={"passphrase": "w1", "envelope": envelope}, headers=AUTH
    )
    assert r1.status_code == 400
    assert r1.json()["error"]["attempts_remaining"] == 2
    r2 = dst_client.post(
        "/admin/import", json={"passphrase": "w2", "envelope": envelope}, headers=AUTH
    )
    assert r2.status_code == 400
    assert r2.json()["error"]["attempts_remaining"] == 1
    r3 = dst_client.post(
        "/admin/import", json={"passphrase": "w3", "envelope": envelope}, headers=AUTH
    )
    assert r3.status_code == 423
    assert r3.json()["error"]["code"] == "mask_envelope_locked"

    # the correct passphrase is now impossible too
    r4 = dst_client.post(
        "/admin/import", json={"passphrase": "right", "envelope": envelope}, headers=AUTH
    )
    assert r4.status_code == 423


def test_lockout_is_per_envelope(tmp_path):
    src_client, _ = _make_client(
        tmp_path, [("山田太郎", "person")], gateway_token="team-secret"
    )
    _post(src_client, "山田太郎さんの件", headers=AUTH)
    env_a = src_client.post(
        "/admin/export", json={"passphrase": "p"}, headers=AUTH
    ).json()["envelope"]
    env_b = src_client.post(
        "/admin/export", json={"passphrase": "p"}, headers=AUTH
    ).json()["envelope"]

    dst_client, _ = _make_client(tmp_path, gateway_token="team-secret")
    for _ in range(3):
        dst_client.post(
            "/admin/import", json={"passphrase": "wrong", "envelope": env_a}, headers=AUTH
        )
    resp = dst_client.post(
        "/admin/import", json={"passphrase": "p", "envelope": env_b}, headers=AUTH
    )
    assert resp.status_code == 200
    assert resp.json()["result"]["imported"] == 1


def test_successful_import_resets_attempt_counter(tmp_path):
    src_client, _ = _make_client(
        tmp_path, [("山田太郎", "person")], gateway_token="team-secret"
    )
    _post(src_client, "山田太郎さんの件", headers=AUTH)
    envelope = src_client.post(
        "/admin/export", json={"passphrase": "p"}, headers=AUTH
    ).json()["envelope"]

    dst_client, _ = _make_client(tmp_path, gateway_token="team-secret")
    dst_client.post(
        "/admin/import", json={"passphrase": "wrong", "envelope": envelope}, headers=AUTH
    )
    resp = dst_client.post(
        "/admin/import", json={"passphrase": "p", "envelope": envelope}, headers=AUTH
    )
    assert resp.status_code == 200
    resp = dst_client.post(
        "/admin/import", json={"passphrase": "wrong", "envelope": envelope}, headers=AUTH
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["attempts_remaining"] == 2  # counter was reset


def test_single_attempt_policy(tmp_path):
    src_client, _ = _make_client(
        tmp_path,
        [("山田太郎", "person")],
        gateway_token="team-secret",
        handoff_max_attempts=1,
    )
    _post(src_client, "山田太郎さんの件", headers=AUTH)
    envelope = src_client.post(
        "/admin/export", json={"passphrase": "p"}, headers=AUTH
    ).json()["envelope"]

    dst_client, _ = _make_client(
        tmp_path, gateway_token="team-secret", handoff_max_attempts=1
    )
    resp = dst_client.post(
        "/admin/import", json={"passphrase": "wrong", "envelope": envelope}, headers=AUTH
    )
    assert resp.status_code == 423  # locked on the first failure


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


# --- config -----------------------------------------------------------------


def test_handoff_config_loads_from_toml(tmp_path):
    cfg_file = tmp_path / "mask.toml"
    cfg_file.write_text(
        "[gateway]\nhandoff_ttl_seconds = 3600\nhandoff_max_attempts = 5\n",
        encoding="utf-8",
    )
    cfg = GatewayConfig.load(cfg_file)
    assert cfg.handoff_ttl_seconds == 3600
    assert cfg.handoff_max_attempts == 5


def test_invalid_handoff_config_rejected():
    with pytest.raises(ValueError):
        GatewayConfig(handoff_ttl_seconds=0)
    with pytest.raises(ValueError):
        GatewayConfig(handoff_max_attempts=0)
