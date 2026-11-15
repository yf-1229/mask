"""Gateway guard tests: leak gate, deny-by-default passthrough, token auth.

The mock upstream records everything it receives, so these tests prove the
negative property the gateway exists for: known raw values never reach it.
"""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from mask.gateway import create_app
from mask.gateway.config import GatewayConfig
from mask.replace import TOKEN_OPEN
from tests.canaries import CANARIES
from tests.test_gateway import _dictionary_file, _fake_upstream


def _make_client(tmp_path, dictionary_terms=None, **overrides):
    dictionary_path = (
        _dictionary_file(tmp_path, dictionary_terms) if dictionary_terms else None
    )
    kwargs = dict(
        upstream_base_url="https://upstream.test/v1",
        upstream_api_key="sk-real",
        use_ner=False,
        dictionary_path=dictionary_path,
        session_scope="global",
        # TestClient's client host is "testclient", not loopback; admin
        # tests opt in explicitly where needed.
        admin_allow_remote=True,
    )
    kwargs.update(overrides)
    config = GatewayConfig(**kwargs)
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return _fake_upstream(request)

    http = httpx.AsyncClient(
        base_url=config.upstream_base_url,
        transport=httpx.MockTransport(handler),
        timeout=None,
    )
    return TestClient(create_app(config, client=http)), captured


def _post(client, content, headers=None, **extra):
    return client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": content}],
            **extra,
        },
        headers=headers,
    )


# --- outbound leak gate ----------------------------------------------------


def test_pii_in_unmasked_field_is_blocked_before_sending(tmp_path):
    client, captured = _make_client(tmp_path, [("山田太郎", "person")])
    resp = _post(client, "山田太郎さんの件", user="山田太郎")
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "mask_leak_blocked"
    assert err["fields"] == ["user"]
    assert err["values"] == ["山田太郎"]
    assert captured == {}  # nothing left the process


def test_leak_gate_warn_mode_sends_anyway(tmp_path):
    client, captured = _make_client(
        tmp_path, [("山田太郎", "person")], leak_gate="warn"
    )
    resp = _post(client, "山田太郎さんの件", user="山田太郎")
    assert resp.status_code == 200
    assert "request" in captured


def test_fullwidth_variant_in_unmasked_field_is_blocked(tmp_path):
    client, _ = _make_client(tmp_path, [("090-1234-5678", "phone")])
    resp = _post(client, "090-1234-5678に電話して", user="０９０－１２３４－５６７８")
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "mask_leak_blocked"


def test_pii_in_forwarded_header_is_blocked(tmp_path):
    client, captured = _make_client(tmp_path, [("taro@example.com", "email")])
    resp = _post(
        client,
        "taro@example.com に送って",
        headers={"X-Title": "about taro@example.com"},
    )
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "mask_leak_blocked"
    assert "header:x-title" in err["fields"]
    assert captured == {}


# --- tool_calls masking ----------------------------------------------------


def test_tool_call_arguments_are_masked(tmp_path):
    client, captured = _make_client(tmp_path, [("山田太郎", "person")])
    arguments = json.dumps({"name": "山田太郎", "note": "よろしく"}, ensure_ascii=False)
    resp = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt",
            "messages": [
                {"role": "user", "content": "山田太郎さんに折返し電話"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {"name": "dial", "arguments": arguments},
                        }
                    ],
                },
            ],
        },
    )
    assert resp.status_code == 200
    sent = json.loads(captured["request"].content)
    got = sent["messages"][1]["tool_calls"][0]["function"]["arguments"]
    assert "山田太郎" not in got
    assert TOKEN_OPEN in got
    parsed = json.loads(got)
    assert parsed["note"] == "よろしく"  # non-PII survives masking


# --- deny-by-default passthrough -------------------------------------------


def test_unknown_path_is_denied_by_default(tmp_path):
    client, captured = _make_client(tmp_path)
    resp = client.post("/v1/embeddings", json={"input": "山田太郎", "model": "e"})
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "mask_path_blocked"
    assert captured == {}


def test_allowlisted_passthrough_forwards(tmp_path):
    client, captured = _make_client(tmp_path, passthrough_allowlist=["/v1/embeddings"])
    resp = client.post("/v1/embeddings", json={"input": "hello", "model": "e"})
    assert resp.status_code == 404  # mock upstream has no such route
    assert captured["request"].url.path == "/v1/embeddings"


def test_allowlisted_passthrough_is_leak_gated(tmp_path):
    client, _ = _make_client(
        tmp_path, [("山田太郎", "person")], passthrough_allowlist=["/v1/embeddings"]
    )
    _post(client, "山田太郎さんの件")  # seed the session table
    resp = client.post("/v1/embeddings", json={"input": "山田太郎", "model": "e"})
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "mask_leak_blocked"


# --- gateway token ----------------------------------------------------------


def test_gateway_token_required(tmp_path):
    client, _ = _make_client(
        tmp_path, [("山田太郎", "person")], gateway_token="team-secret"
    )
    resp = _post(client, "山田太郎さんの件")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "mask_unauthorized"

    resp = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt",
            "messages": [{"role": "user", "content": "山田太郎さんの件"}],
        },
        headers={"Authorization": "Bearer team-secret"},
    )
    assert resp.status_code == 200


def test_gateway_token_protects_passthrough_too(tmp_path):
    client, captured = _make_client(tmp_path, gateway_token="team-secret")
    resp = client.get("/v1/models")
    assert resp.status_code == 401
    assert captured == {}


# --- config -----------------------------------------------------------------


def test_gateway_section_loads_from_toml(tmp_path):
    cfg_file = tmp_path / "mask.toml"
    cfg_file.write_text(
        "[gateway]\n"
        'token = "tok"\n'
        'passthrough_allowlist = ["/v1/a", "/v1/b"]\n'
        'leak_gate = "warn"\n',
        encoding="utf-8",
    )
    cfg = GatewayConfig.load(cfg_file)
    assert cfg.gateway_token == "tok"
    assert cfg.passthrough_allowlist == ["/v1/a", "/v1/b"]
    assert cfg.leak_gate == "warn"


def test_invalid_leak_gate_rejected():
    with pytest.raises(ValueError):
        GatewayConfig(leak_gate="nope")


# --- end-to-end zero-leak proof ----------------------------------------------


def _canary_terms():
    return [
        (value, etype.value)
        for canary in CANARIES
        for etype, value in canary.expected
    ]


def test_canary_corpus_never_reaches_upstream(tmp_path):
    """For every canary, nothing the mock upstream receives — body decoded,
    keys included — contains any expected raw value."""
    client, captured = _make_client(tmp_path, _canary_terms())
    for canary in CANARIES:
        resp = _post(client, canary.text)
        assert resp.status_code == 200, canary.name
        sent = json.dumps(
            json.loads(captured["request"].content), ensure_ascii=False
        )
        for _, value in canary.expected:
            assert value not in sent, f"{canary.name}: {value!r} reached upstream"


def test_canary_streaming_never_reaches_upstream(tmp_path):
    client, captured = _make_client(tmp_path, _canary_terms())
    canary = CANARIES[0]
    resp = _post(client, canary.text, stream=True)
    assert resp.status_code == 200
    sent = json.dumps(json.loads(captured["request"].content), ensure_ascii=False)
    for _, value in canary.expected:
        assert value not in sent, f"{value!r} reached upstream"
