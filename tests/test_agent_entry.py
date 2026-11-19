"""Agent entrance tests: Anthropic-protocol /v1/messages through the proxy.

Claude Code and friends enter here. The canary property must hold on this
entrance exactly as on the OpenAI one: nothing the session detected ever
reaches the mock upstream.
"""

import json
import re

import httpx
from fastapi.testclient import TestClient

from mask.gateway import create_app
from mask.gateway.config import GatewayConfig
from tests.test_gateway import _dictionary_file


def _upstream(request: httpx.Request) -> httpx.Response:
    """OpenAI-shaped upstream echo.

    Emits a tool_call echoing the first masked token when the request
    defines tools (agent flow); otherwise echoes the masked text back.
    """
    if request.url.path != "/v1/chat/completions":
        return httpx.Response(404, json={"error": {"message": "not found"}})
    body = json.loads(request.content)
    texts = [
        m["content"]
        for m in body.get("messages", [])
        if isinstance(m.get("content"), str)
    ]
    content = " ".join(texts) or "(echo)"

    if body.get("stream"):
        lines = []
        for delta in ({"role": "assistant", "content": content[:3]}, {"content": content[3:]}):
            lines.append(
                "data: "
                + json.dumps(
                    {
                        "id": "chatcmpl-1",
                        "object": "chat.completion.chunk",
                        "created": 1,
                        "model": body.get("model", "gpt"),
                        "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
                    }
                )
            )
        lines.append("data: [DONE]")
        return httpx.Response(
            200,
            text="\n\n".join(lines) + "\n\n",
            headers={"content-type": "text/event-stream"},
        )

    token_match = re.search(r"⟦[^⟧]+⟧", content)
    last_role = ""
    if body.get("messages"):
        last_role = body["messages"][-1].get("role", "")
    if body.get("tools") and token_match and last_role != "tool":
        message = {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "lookup",
                        "arguments": json.dumps(
                            {"who": token_match.group(0)}, ensure_ascii=False
                        ),
                    },
                }
            ],
        }
        finish = "tool_calls"
    else:
        message = {"role": "assistant", "content": content}
        finish = "stop"
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "model": body.get("model", "gpt"),
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 9},
        },
    )


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
    )
    kwargs.update(overrides)
    config = GatewayConfig(**kwargs)
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["request"] = request
        return _upstream(request)

    http = httpx.AsyncClient(
        base_url=config.upstream_base_url,
        transport=httpx.MockTransport(handler),
        timeout=None,
    )
    return TestClient(create_app(config, client=http)), captured


def _post_messages(client, body, headers=None):
    return client.post("/v1/messages", json=body, headers=headers)


def test_messages_request_is_masked_and_restored(tmp_path):
    client, captured = _make_client(tmp_path, [("山田太郎", "person")])
    r = _post_messages(
        client,
        {
            "model": "claude-x",
            "max_tokens": 100,
            "system": "丁寧に",
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "山田太郎さんの件"}]}
            ],
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["type"] == "message"
    assert data["role"] == "assistant"
    # translated + masked reached the upstream; the raw name never did
    sent = json.loads(captured["request"].content)
    assert "山田" not in captured["request"].content.decode()
    assert sent["messages"][0]["role"] == "system"
    assert any(t.startswith("⟦人名") for m in sent["messages"] for t in [m.get("content", "")])
    # the answer is restored for the user
    text_blocks = [b for b in data["content"] if b["type"] == "text"]
    assert "山田太郎" in text_blocks[0]["text"]
    assert data["stop_reason"] == "end_turn"
    assert data["usage"]["input_tokens"] == 7
    # indicators present on this entrance too
    assert r.headers["X-Mask-In"] == "v1/messages"
    assert r.headers["X-Mask-Masked"] == "1"


def test_messages_tool_use_round_trip(tmp_path):
    """tool_use arguments are restored on the way out (tools run locally)."""
    client, captured = _make_client(tmp_path, [("山田太郎", "person")])
    # first establish the mapping with a chat turn
    r = _post_messages(
        client,
        {
            "model": "claude-x",
            "max_tokens": 100,
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "山田太郎さんの件"}]}
            ],
            "tools": [
                {
                    "name": "lookup",
                    "description": "d",
                    "input_schema": {"type": "object"},
                }
            ],
        },
    )
    assert r.status_code == 200
    data = r.json()
    tool_blocks = [b for b in data["content"] if b["type"] == "tool_use"]
    assert tool_blocks, data
    assert tool_blocks[0]["name"] == "lookup"
    # upstream only ever saw the token; the user-visible tool input is real
    assert "⟦人名" in captured["request"].content.decode()
    assert tool_blocks[0]["input"]["who"] == "山田太郎"
    assert data["stop_reason"] == "tool_use"


def test_messages_translates_tool_results_and_uses_tools(tmp_path):
    """A full agent loop: assistant tool_use -> user tool_result -> upstream."""
    client, captured = _make_client(tmp_path, [("山田太郎", "person")])
    # turn 1: establish the mapping
    _post_messages(
        client,
        {
            "model": "claude-x",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": "山田太郎さんの連絡先"}],
        },
    )
    # turn 2: harness sends back a tool_result (as Claude Code does)
    r = _post_messages(
        client,
        {
            "model": "claude-x",
            "max_tokens": 100,
            "tools": [{"name": "lookup", "description": "d", "input_schema": {"type": "object"}}],
            "messages": [
                {"role": "user", "content": "山田太郎さんの連絡先"},
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_1",
                            "name": "lookup",
                            "input": {"who": "山田太郎"},
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_1",
                            "content": "山田太郎の電話は090-1234-5678",
                        }
                    ],
                },
            ],
        },
    )
    assert r.status_code == 200
    sent = json.loads(captured["request"].content)
    roles = [m["role"] for m in sent["messages"]]
    assert "tool" in roles
    tool_msg = next(m for m in sent["messages"] if m["role"] == "tool")
    assert tool_msg["tool_call_id"] == "toolu_1"
    # the tool result was masked on the way in
    assert "090-1234-5678" not in tool_msg["content"]
    # tools were translated to OpenAI shape
    assert sent["tools"][0]["type"] == "function"
    # answer restored
    data = r.json()
    assert "山田太郎" in data["content"][0]["text"]


def test_messages_leak_gate_wrapped_in_anthropic_error(tmp_path):
    client, captured = _make_client(tmp_path, [("山田太郎", "person")])
    r = _post_messages(
        client,
        {
            "model": "claude-x",
            "max_tokens": 10,
            # stop_sequences is translated but not masked: a known raw
            # value here is exactly what the gate exists for
            "stop_sequences": ["山田太郎"],
            "messages": [{"role": "user", "content": "山田太郎さんの件"}],
        },
    )
    assert r.status_code == 400
    err = r.json()
    assert err["type"] == "error"
    assert err["error"]["mask_code"] == "mask_leak_blocked"
    assert err["error"]["mask_values"] == ["山田太郎"]
    assert captured == {}  # nothing left the process


def test_messages_stream_emits_anthropic_event_sequence(tmp_path):
    client, _captured = _make_client(tmp_path, [("山田太郎", "person")])
    r = _post_messages(
        client,
        {
            "model": "claude-x",
            "max_tokens": 100,
            "stream": True,
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "山田太郎さん"}]}
            ],
        },
    )
    assert r.status_code == 200
    assert "X-Mask-In" in r.headers and r.headers["X-Mask-In"] == "v1/messages"
    body = r.text
    for event_type in (
        "message_start",
        "content_block_start",
        "content_block_delta",
        "content_block_stop",
        "message_delta",
        "message_stop",
    ):
        assert f"event: {event_type}" in body
    # text delta carries the restored value, streaming body has no raw send
    assert "山田太郎" in body
    data_lines = [line for line in body.splitlines() if line.startswith("data: ")]
    parsed = [json.loads(line[len("data: ") :]) for line in data_lines]
    delta = next(p for p in parsed if p["type"] == "content_block_delta")
    assert delta["delta"]["type"] == "text_delta"
    assert "山田太郎" in delta["delta"]["text"]


def test_messages_gateway_token_via_x_api_key(tmp_path):
    client, captured = _make_client(tmp_path, gateway_token="team-secret")
    denied = _post_messages(
        client,
        {"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]},
    )
    assert denied.status_code == 401
    ok = _post_messages(
        client,
        {"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": "hi"}]},
        headers={"x-api-key": "team-secret", "anthropic-version": "2023-06-01"},
    )
    assert ok.status_code == 200
    # the anthropic key slot and version headers never travel upstream
    assert "x-api-key" not in captured["request"].headers
    assert "anthropic-version" not in captured["request"].headers
    assert captured["request"].headers["authorization"] == "Bearer sk-real"