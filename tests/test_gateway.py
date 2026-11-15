"""Gateway tests against a mocked upstream (no network, no NER model)."""

import json

import httpx
from fastapi.testclient import TestClient

from mask.gateway import create_app
from mask.gateway.config import GatewayConfig
from mask.replace import TOKEN_CLOSE, TOKEN_OPEN


def _fake_upstream(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/v1/chat/completions":
        body = json.loads(request.content)
        contents = [
            m["content"]
            for m in body.get("messages", [])
            if isinstance(m.get("content"), str)
        ]
        if not contents:
            return httpx.Response(
                401, json={"error": {"message": "bad key", "code": "invalid_api_key"}}
            )
        content = " ".join(contents)
        if body.get("stream"):
            chunks = [
                {"role": "assistant", "content": content[:5]},
                {"content": content[5:]},
            ]
            lines = []
            for delta in chunks:
                lines.append(
                    "data: "
                    + json.dumps(
                        {
                            "id": "chatcmpl-1",
                            "object": "chat.completion.chunk",
                            "created": 1,
                            "model": body.get("model", "gpt"),
                            "choices": [
                                {"index": 0, "delta": delta, "finish_reason": None}
                            ],
                        }
                    )
                )
            lines.append("data: [DONE]")
            return httpx.Response(
                200,
                text="\n\n".join(lines) + "\n\n",
                headers={"content-type": "text/event-stream"},
            )
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-1",
                "object": "chat.completion",
                "model": body.get("model", "gpt"),
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }
                ],
            },
        )
    return httpx.Response(404, json={"error": "not found"})


def _make_client(tmp_path, dictionary_terms=None):
    dictionary_path = None
    if dictionary_terms:
        dictionary_path = _dictionary_file(tmp_path, dictionary_terms)
    config = GatewayConfig(
        upstream_base_url="https://upstream.test/v1",
        upstream_api_key="sk-real",
        use_ner=False,
        dictionary_path=dictionary_path,
        session_scope="global",
    )
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return _fake_upstream(request)

    http = httpx.AsyncClient(
        base_url=config.upstream_base_url,
        transport=httpx.MockTransport(handler),
        timeout=None,
    )
    app = create_app(config, client=http)
    return TestClient(app), captured


def _dictionary_file(tmp_path, terms):
    d = tmp_path / "dictionary.tsv"
    d.write_text(
        "\n".join(f"{term}\t{typ}" for term, typ in terms), encoding="utf-8"
    )
    return str(d)


def _post(client, content, **extra):
    return client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": content}],
            **extra,
        },
    )


def test_request_is_masked_upstream_sees_pseudonyms(tmp_path):
    client, captured = _make_client(tmp_path, [("山田太郎", "person")])
    resp = _post(client, "山田太郎さんと090-1234-5678の件")
    assert resp.status_code == 200

    sent = json.loads(captured["request"].content)
    upstream_text = sent["messages"][0]["content"]
    assert "山田太郎" not in upstream_text
    assert "090-1234-5678" not in upstream_text
    assert TOKEN_OPEN in upstream_text and TOKEN_CLOSE in upstream_text
    # the real key is injected; the client's dummy key is not forwarded
    assert captured["request"].headers["authorization"] == "Bearer sk-real"


def test_response_is_restored_for_the_user(tmp_path):
    client, _ = _make_client(tmp_path, [("山田太郎", "person")])
    resp = _post(client, "山田太郎さんと090-1234-5678の件")
    content = resp.json()["choices"][0]["message"]["content"]
    assert "山田太郎" in content
    assert "090-1234-5678" in content
    assert TOKEN_OPEN not in content


def test_streaming_request_gets_restored_sse(tmp_path):
    client, _ = _make_client(tmp_path, [("山田太郎", "person")])
    resp = _post(client, "山田太郎さんの件", stream=True)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")

    body = resp.text
    assert "data: [DONE]" in body
    assert "山田太郎" in body
    assert TOKEN_OPEN not in body


def test_upstream_error_passes_through(tmp_path):
    client, _ = _make_client(tmp_path)
    resp = client.post(
        "/v1/chat/completions",
        json={"model": "gpt", "messages": []},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "invalid_api_key"


def test_passthrough_models_endpoint(tmp_path):
    client, captured = _make_client(tmp_path)
    resp = client.get("/v1/models")
    assert resp.status_code == 404  # mocked upstream has no such route
    assert captured["request"].url.path == "/v1/models"


def test_global_scope_keeps_tokens_stable_across_requests(tmp_path):
    client, captured = _make_client(tmp_path, [("山田太郎", "person")])
    tokens = []
    for _ in range(2):
        _post(client, "山田太郎さんの件")
        sent = json.loads(captured["request"].content)
        tokens.append(sent["messages"][0]["content"])
    assert tokens[0] == tokens[1]
