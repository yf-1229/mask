"""Indicator system tests: /status, X-Mask-* headers, posture snapshot.

The whole point of the indicators is reliability visibility, so these
tests pin the contract: counts only (never contents), stable shape, and
monotonic behavior across request types.
"""

import json

import httpx
from fastapi.testclient import TestClient

from mask.gateway import create_app
from mask.gateway.config import GatewayConfig
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
        admin_allow_remote=True,
    )
    kwargs.update(overrides)
    config = GatewayConfig(**kwargs)

    def handler(request: httpx.Request) -> httpx.Response:
        return _fake_upstream(request)

    http = httpx.AsyncClient(
        base_url=config.upstream_base_url,
        transport=httpx.MockTransport(handler),
        timeout=None,
    )
    return TestClient(create_app(config, client=http))


def test_status_reports_posture_and_counts(tmp_path):
    client = _make_client(tmp_path, [("山田太郎", "person")])
    r = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "山田太郎さんの件"}],
        },
    )
    assert r.status_code == 200

    status = client.get("/status").json()
    assert status["status"] == "ok"
    posture = status["posture"]
    assert posture["leak_gate"] == "block"
    assert posture["leak_gate_active"] is True
    assert posture["session_scope"] == "global"
    assert posture["ner"] is False
    assert posture["dictionary_terms"] == 1
    assert posture["mapping_records"] == 1  # the person masked above
    assert posture["gateway_token"] is False
    counts = status["counts"]
    assert counts["requests_total"] == 1
    assert counts["entities_masked"] == 1
    assert counts["tokens_restored"] == 1  # upstream echoed it back
    assert counts["leak_blocks"] == 0


def test_status_counts_are_counts_only(tmp_path):
    """The /status snapshot must never carry raw values or tokens."""
    client = _make_client(tmp_path, [("山田太郎", "person"), ("090-1234-5678", "phone")])
    client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "user", "content": "山田太郎と090-1234-5678の件"}
            ],
        },
    )
    blob = json.dumps(client.get("/status").json(), ensure_ascii=False)
    assert "山田" not in blob
    assert "090-" not in blob
    assert "⟦" not in blob


def test_leak_block_and_denied_paths_show_in_counts(tmp_path):
    client = _make_client(tmp_path, [("山田太郎", "person")], gateway_token="tok")
    # bad token -> auth denied
    client.post("/v1/chat/completions", json={"messages": []})
    # known PII in an unmasked field -> leak block
    client.post(
        "/v1/chat/completions",
        json={
            "model": "m",
            "messages": [{"role": "user", "content": "山田太郎さんの件"}],
            "user": "山田太郎",
        },
        headers={"Authorization": "Bearer tok"},
    )
    # non-allowlisted path -> 403
    client.post(
        "/v1/embeddings",
        json={"input": "x"},
        headers={"Authorization": "Bearer tok"},
    )

    counts = client.get("/status", headers={"Authorization": "Bearer tok"}).json()[
        "counts"
    ]
    assert counts["auth_denied"] == 1
    assert counts["leak_blocks"] == 1
    assert counts["paths_denied"] == 1
    assert counts["requests_blocked"] == 3


def test_status_requires_gateway_token_when_set(tmp_path):
    client = _make_client(tmp_path, gateway_token="team-secret")
    assert client.get("/status").status_code == 401
    ok = client.get("/status", headers={"Authorization": "Bearer team-secret"})
    assert ok.status_code == 200
    # Anthropic-style header works too
    ok2 = client.get("/status", headers={"x-api-key": "team-secret"})
    assert ok2.status_code == 200


def test_status_public_adds_cors(tmp_path):
    private = _make_client(tmp_path)
    assert "access-control-allow-origin" not in private.get("/status").headers
    public = _make_client(tmp_path, status_public=True)
    assert public.get("/status").headers["access-control-allow-origin"] == "*"


def test_status_public_skips_token_when_opted_in(tmp_path):
    """status_public is an explicit opt-in to publish the PII-free snapshot;
    with it off, the gateway token gates /status like every other entrance."""
    closed = _make_client(
        tmp_path, gateway_token="team-secret", status_public=False
    )
    assert closed.get("/status").status_code == 401
    authed = closed.get("/status", headers={"Authorization": "Bearer team-secret"})
    assert authed.status_code == 200
    open_client = _make_client(
        tmp_path, gateway_token="team-secret", status_public=True
    )
    r = open_client.get("/status", headers={"Origin": "http://site.test"})
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == "*"
    assert open_client.get("/status").json()["status"] == "ok"


def test_chat_response_carries_indicator_headers(tmp_path):
    client = _make_client(tmp_path, [("山田太郎", "person")])
    r = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "山田太郎さんの件"}],
        },
    )
    assert r.headers["X-Mask"] == "on"
    assert r.headers["X-Mask-In"] == "v1/chat"
    assert r.headers["X-Mask-Leak-Gate"] == "block"
    assert r.headers["X-Mask-Masked"] == "1"
    assert r.headers["X-Mask-Restored"] == "1"
    assert r.headers["X-Mask-Unresolved"] == "0"
    assert len(r.headers["X-Mask-Nonce"]) == 12


def test_leak_blocked_response_is_marked(tmp_path):
    client = _make_client(tmp_path, [("山田太郎", "person")])
    r = client.post(
        "/v1/chat/completions",
        json={
            "model": "m",
            "messages": [{"role": "user", "content": "山田太郎さんの件"}],
            "user": "山田太郎",
        },
    )
    assert r.status_code == 400
    assert r.headers["X-Mask-Leak-Blocked"] == "true"
