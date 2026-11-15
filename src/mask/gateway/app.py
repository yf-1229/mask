"""OpenAI-compatible gateway: mask on the way in, restore on the way out.

The harness sits between an LLM client ("harness") and the real LLM API:

    client --(OpenAI-compatible request)--> gateway --(masked)--> upstream
    client <--(restored response)---------- gateway <--(pseudo)--- upstream

Phase A scope:
- /v1/chat/completions, non-streaming: full mask/restore.
- /v1/chat/completions with stream=true: the upstream SSE stream is
  buffered to completion, restored as a whole, and returned as a single
  SSE chunk. Correct but not incremental; incremental restore is Phase B.
- Every other /v1/* path is forwarded verbatim (no PII expected there).
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from mask.detect.dictionary import UserDictionary
from mask.gateway.config import GatewayConfig
from mask.pipeline import Session

logger = logging.getLogger("mask.gateway")

# Request headers never forwarded upstream: the client's Authorization is a
# dummy by design (the real key lives only in the gateway config).
_HOP_BY_HOP = {
    "host",
    "authorization",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "accept-encoding",
}


def _mask_text(text: str, session: Session) -> str:
    masked, result = session.masked(text)
    if result.entities:
        logger.info(
            "masked %d entities: %s",
            len(result.entities),
            ", ".join(sorted({e.type.value for e in result.entities})),
        )
    return masked


def _mask_content(content: Any, session: Session) -> Any:
    if isinstance(content, str):
        return _mask_text(content, session)
    if isinstance(content, list):
        return [
            (
                {**part, "text": _mask_text(part["text"], session)}
                if isinstance(part, dict) and isinstance(part.get("text"), str)
                else part
            )
            for part in content
        ]
    return content


def mask_chat_request(body: dict[str, Any], session: Session) -> dict[str, Any]:
    """Return a copy of the request body with PII in messages replaced."""
    masked = dict(body)
    messages = masked.get("messages")
    if isinstance(messages, list):
        masked["messages"] = [
            (
                {**m, "content": _mask_content(m.get("content"), session)}
                if isinstance(m, dict)
                else m
            )
            for m in messages
        ]
    return masked


def _restore_text(text: str, session: Session) -> str:
    restored = session.unmasked(text)
    for warning in restored.warnings:
        logger.warning("restore: %s", warning)
    return restored.text


def restore_chat_response(data: dict[str, Any], session: Session) -> dict[str, Any]:
    """Restore pseudonyms in choices[*].message.content, in place."""
    for choice in data.get("choices", []):
        message = choice.get("message") if isinstance(choice, dict) else None
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            message["content"] = _restore_text(message["content"], session)
    return data


def _delta_content(chunk: dict[str, Any]) -> str:
    parts: list[str] = []
    for choice in chunk.get("choices", []):
        delta = choice.get("delta") if isinstance(choice, dict) else None
        if isinstance(delta, dict) and isinstance(delta.get("content"), str):
            parts.append(delta["content"])
    return "".join(parts)


def _sse_line(payload: dict[str, Any] | str) -> str:
    data = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    return f"data: {data}\n\n"


def _upstream_headers(request: Request, config: GatewayConfig) -> dict[str, str]:
    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }
    if config.upstream_api_key:
        headers["Authorization"] = f"Bearer {config.upstream_api_key}"
    return headers


def create_app(
    config: GatewayConfig,
    client: httpx.AsyncClient | None = None,
) -> FastAPI:
    """Build the gateway app. `client` is injectable for tests."""
    app = FastAPI(title="mask gateway", docs_url=None, openapi_url=None)
    app.state.config = config
    app.state.http = client or httpx.AsyncClient(
        base_url=config.upstream_base_url, timeout=None
    )
    dictionary = (
        UserDictionary.load(config.dictionary_path)
        if config.dictionary_path
        else UserDictionary()
    )
    app.state.dictionary = dictionary
    if config.session_scope == "global":
        # NER model loads once here, not per request.
        app.state.session = Session(dictionary=dictionary, use_ner=config.use_ner)

    def get_session() -> Session:
        if config.session_scope == "global":
            return app.state.session
        return Session(dictionary=dictionary, use_ner=config.use_ner)

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {
            "status": "ok",
            "upstream": config.upstream_base_url,
            "session_scope": config.session_scope,
        }

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        body = await request.json()
        session = get_session()
        masked = mask_chat_request(body, session)
        headers = _upstream_headers(request, config)
        url = "/chat/completions"

        if body.get("stream"):
            return await _proxy_streaming(app, masked, headers, url, session)

        upstream = await app.state.http.post(url, json=masked, headers=headers)
        if upstream.status_code >= 400:
            return Response(
                content=upstream.content,
                status_code=upstream.status_code,
                media_type=upstream.headers.get("content-type"),
            )
        data = upstream.json()
        restore_chat_response(data, session)
        return JSONResponse(data)

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    )
    async def passthrough(request: Request, path: str) -> Response:
        """Forward anything else (e.g. /v1/models) verbatim, unmasked.

        The local /v1 prefix is stripped because upstream_base_url already
        carries the version segment.
        """
        if path.startswith("v1/"):
            path = path[len("v1/"):]
        headers = _upstream_headers(request, config)
        body = await request.body()
        upstream = await app.state.http.request(
            request.method, f"/{path}", content=body, headers=headers
        )
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers={
                k: v
                for k, v in upstream.headers.items()
                if k.lower() not in _HOP_BY_HOP
            },
        )

    return app


async def _proxy_streaming(
    app: FastAPI,
    masked_body: dict[str, Any],
    headers: dict[str, str],
    url: str,
    session: Session,
) -> Response:
    """Buffer the upstream SSE stream, restore it whole, emit one chunk."""
    req = app.state.http.build_request("POST", url, json=masked_body, headers=headers)
    upstream = await app.state.http.send(req, stream=True)
    if upstream.status_code >= 400:
        content = await upstream.aread()
        await upstream.aclose()
        return Response(
            content=content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type"),
        )

    meta: dict[str, Any] = {}
    parts: list[str] = []
    try:
        async for line in upstream.aiter_lines():
            if not line.startswith("data:"):
                continue
            payload = line[len("data:"):].strip()
            if payload == "[DONE]":
                break
            chunk = json.loads(payload)
            for key in ("id", "object", "created", "model", "system_fingerprint"):
                if chunk.get(key) is not None:
                    meta.setdefault(key, chunk[key])
            parts.append(_delta_content(chunk))
    finally:
        await upstream.aclose()

    restored = _restore_text("".join(parts), session)
    meta["object"] = "chat.completion.chunk"

    def generate():
        first = {
            **meta,
            "choices": [
                {
                    "index": 0,
                    "delta": {"role": "assistant", "content": restored},
                    "finish_reason": None,
                }
            ],
        }
        last = {
            **meta,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        }
        yield _sse_line(first)
        yield _sse_line(last)
        yield _sse_line("[DONE]")

    return StreamingResponse(generate(), media_type="text/event-stream")
