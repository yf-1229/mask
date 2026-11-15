"""OpenAI-compatible gateway: mask on the way in, restore on the way out.

The harness sits between an LLM client ("harness") and the real LLM API:

    client --(OpenAI-compatible request)--> gateway --(masked)--> upstream
    client <--(restored response)---------- gateway <--(pseudo)--- upstream

Phase A scope:
- /v1/chat/completions, non-streaming: full mask/restore.
- /v1/chat/completions with stream=true: the upstream SSE stream is
  buffered to completion, restored as a whole, and returned as a single
  SSE chunk. Correct but not incremental; incremental restore is Phase B.
- tool_calls function arguments are masked (JSON strings are parsed and
  every string inside is masked).
- Every other path is refused unless allowlisted in gateway config
  (deny by default); allowlisted paths are forwarded but still pass the
  outbound leak gate.
- Before anything is sent, the outbound leak gate walks the payload and
  forwarded headers for raw values the session has detected; a hit
  refuses the request (fail closed). See leakguard.py.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from nacl.exceptions import CryptoError

from mask.detect.dictionary import UserDictionary
from mask.gateway.config import GatewayConfig
from mask.gateway.leakguard import find_header_leaks, find_leaks
from mask.gateway.sharing import (
    EnvelopeExpired,
    envelope_fingerprint,
    seal,
    unseal,
)
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


def _mask_strings(node: Any, session: Session) -> Any:
    """Mask every string inside a parsed JSON argument blob."""
    if isinstance(node, str):
        return _mask_text(node, session)
    if isinstance(node, dict):
        return {k: _mask_strings(v, session) for k, v in node.items()}
    if isinstance(node, list):
        return [_mask_strings(v, session) for v in node]
    return node


def _mask_json_string(raw: str, session: Session) -> str:
    """Mask a JSON-encoded string; non-JSON strings are masked as text."""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return _mask_text(raw, session)
    return json.dumps(_mask_strings(parsed, session), ensure_ascii=False)


def _mask_tool_calls(tool_calls: Any, session: Session) -> Any:
    """Mask PII inside tool_calls[*].function.arguments."""
    if not isinstance(tool_calls, list):
        return tool_calls
    out = []
    for call in tool_calls:
        if not isinstance(call, dict):
            out.append(call)
            continue
        fn = call.get("function")
        if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
            call = {
                **call,
                "function": {
                    **fn,
                    "arguments": _mask_json_string(fn["arguments"], session),
                },
            }
        out.append(call)
    return out


def mask_chat_request(body: dict[str, Any], session: Session) -> dict[str, Any]:
    """Return a copy of the request body with PII in messages replaced."""
    masked = dict(body)
    messages = masked.get("messages")
    if isinstance(messages, list):
        out = []
        for m in messages:
            if isinstance(m, dict):
                m = {**m, "content": _mask_content(m.get("content"), session)}
                if "tool_calls" in m:
                    m = {**m, "tool_calls": _mask_tool_calls(m["tool_calls"], session)}
            out.append(m)
        masked["messages"] = out
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
    # Failed-passphrase attempts per envelope fingerprint (lockout state).
    # Process-local by design: restarting the gateway resets counters, but
    # the sealed expiry still bounds the envelope's life.
    app.state.handoff_failures: dict[str, int] = {}
    if config.session_scope == "global":
        # NER model loads once here, not per request.
        app.state.session = Session(dictionary=dictionary, use_ner=config.use_ner)

    def get_session() -> Session:
        if config.session_scope == "global":
            return app.state.session
        return Session(dictionary=dictionary, use_ner=config.use_ner)

    def _authorized(request: Request) -> Response | None:
        """Gateway token check; unset token means no auth (localhost only)."""
        if not config.gateway_token:
            return None
        if request.headers.get("authorization") == f"Bearer {config.gateway_token}":
            return None
        return JSONResponse(
            status_code=401,
            content={
                "error": {
                    "message": "gateway token required (send it as the API key)",
                    "code": "mask_unauthorized",
                }
            },
        )

    def _gate(
        payload: Any, session: Session, headers: dict[str, str], source: str
    ) -> Response | None:
        """Refuse the request if a known raw value would leave the process.

        The client-facing error echoes the offending values: the client is
        the trusted local user and sent them in the first place. Logs carry
        only field paths and a value hash, never the raw value.
        """
        values = session.pseudonyms.raw_values()
        if not values:
            return None
        leaks = find_leaks(payload, values) + find_header_leaks(headers, values)
        if not leaks:
            return None
        for leak in leaks:
            logger.warning(
                "leak gate: %s in %s (value sha256:%s)",
                source,
                leak.path,
                hashlib.sha256(leak.value.encode("utf-8")).hexdigest()[:12],
            )
        if config.leak_gate == "warn":
            return None
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": (
                        "mask gateway: unmasked PII detected in the request; "
                        "nothing was sent to the upstream"
                    ),
                    "code": "mask_leak_blocked",
                    "fields": [leak.path for leak in leaks],
                    "values": [leak.value for leak in leaks],
                }
            },
        )

    def _scope_unsupported() -> Response:
        return JSONResponse(
            status_code=409,
            content={
                "error": {
                    "message": "admin endpoints require session.scope = 'global'",
                    "code": "mask_scope_unsupported",
                }
            },
        )

    def _bad_request(message: str) -> Response:
        return JSONResponse(
            status_code=400,
            content={"error": {"message": message, "code": "mask_bad_request"}},
        )

    def _admin_authorized(request: Request) -> Response | None:
        """Admin endpoints stay disabled until gateway.token is set."""
        if not config.gateway_token:
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": "admin endpoints require gateway.token to be set",
                        "code": "mask_admin_disabled",
                    }
                },
            )
        return _authorized(request)

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {
            "status": "ok",
            "upstream": config.upstream_base_url,
            "session_scope": config.session_scope,
        }

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        denied = _authorized(request)
        if denied is not None:
            return denied
        body = await request.json()
        session = get_session()
        masked = mask_chat_request(body, session)
        headers = _upstream_headers(request, config)
        blocked = _gate(masked, session, headers, "chat/completions")
        if blocked is not None:
            return blocked
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

    @app.post("/admin/export")
    async def admin_export(request: Request) -> Response:
        """Seal the session mapping table under a passphrase (team handoff).

        The response envelope is ciphertext with a sealed expiry: it can
        travel over any channel, dies at the expiry, and the passphrase
        travels separately (password manager, in person). Raw values never
        appear in logs.
        """
        denied = _admin_authorized(request)
        if denied is not None:
            return denied
        if config.session_scope != "global":
            return _scope_unsupported()
        body = await request.json()
        passphrase = body.get("passphrase") if isinstance(body, dict) else None
        if not isinstance(passphrase, str) or not passphrase:
            return _bad_request("passphrase required")
        ttl = config.handoff_ttl_seconds
        if isinstance(body, dict) and body.get("ttl_seconds") is not None:
            ttl = body["ttl_seconds"]
        if not isinstance(ttl, int) or ttl <= 0:
            return _bad_request("ttl_seconds must be a positive integer")
        records = app.state.session.pseudonyms.export_records()
        envelope = seal({"v": 1, "records": records}, passphrase, ttl_seconds=ttl)
        logger.info("admin export: %d records sealed", len(records))
        return JSONResponse(
            {
                "count": len(records),
                "expires_at": envelope["exp"],
                "envelope": envelope,
            }
        )

    @app.post("/admin/import")
    async def admin_import(request: Request) -> Response:
        """Unseal an exported envelope and merge it into the session table.

        This completes the handoff in the receiving process: after import,
        the same values mask to the same tokens and imported artifacts
        restore. Security posture: a sealed expiry (時間切れ) refuses
        decryption outright, and failed passphrase attempts (認証失敗) are
        counted per envelope — at the configured limit the envelope is
        locked for good, even for the correct passphrase. Token clashes
        with different values are never rebound; they are reported as
        conflicts.
        """
        denied = _admin_authorized(request)
        if denied is not None:
            return denied
        if config.session_scope != "global":
            return _scope_unsupported()
        body = await request.json()
        envelope = body.get("envelope") if isinstance(body, dict) else None
        passphrase = body.get("passphrase") if isinstance(body, dict) else None
        if not isinstance(envelope, dict) or not isinstance(passphrase, str):
            return _bad_request("passphrase and envelope required")
        kdf = envelope.get("kdf")
        if (
            not isinstance(kdf, dict)
            or not isinstance(kdf.get("salt"), str)
            or not isinstance(envelope.get("boxed"), str)
        ):
            return _bad_request("malformed envelope")

        fingerprint = envelope_fingerprint(envelope)
        failures = app.state.handoff_failures
        if failures.get(fingerprint, 0) >= config.handoff_max_attempts:
            logger.warning("admin import: envelope locked (fp %s)", fingerprint[:12])
            return JSONResponse(
                status_code=423,
                content={
                    "error": {
                        "message": (
                            "envelope locked after too many failed attempts; "
                            "request a fresh export"
                        ),
                        "code": "mask_envelope_locked",
                    }
                },
            )
        try:
            payload = unseal(envelope, passphrase)
        except EnvelopeExpired:
            logger.warning("admin import: envelope expired (fp %s)", fingerprint[:12])
            return JSONResponse(
                status_code=410,
                content={
                    "error": {
                        "message": "envelope expired; request a fresh export",
                        "code": "mask_envelope_expired",
                    }
                },
            )
        except (CryptoError, ValueError, KeyError, TypeError):
            attempts = failures.get(fingerprint, 0) + 1
            failures[fingerprint] = attempts
            remaining = config.handoff_max_attempts - attempts
            logger.warning(
                "admin import: unseal failed (fp %s, attempt %d, %d remaining)",
                fingerprint[:12],
                attempts,
                max(remaining, 0),
            )
            if remaining <= 0:
                return JSONResponse(
                    status_code=423,
                    content={
                        "error": {
                            "message": (
                                "envelope locked after too many failed attempts; "
                                "request a fresh export"
                            ),
                            "code": "mask_envelope_locked",
                        }
                    },
                )
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "message": "wrong passphrase or corrupted envelope",
                        "code": "mask_unseal_failed",
                        "attempts_remaining": remaining,
                    }
                },
            )
        failures.pop(fingerprint, None)
        records = payload.get("records") if isinstance(payload, dict) else None
        if not isinstance(records, list):
            return _bad_request("envelope payload has no records")
        counts = {"imported": 0, "already": 0, "conflict": 0, "invalid": 0}
        conflicts: list[str] = []
        for rec in records:
            if not isinstance(rec, dict):
                counts["invalid"] += 1
                continue
            status = app.state.session.pseudonyms.import_record(
                rec.get("token", ""), rec.get("value", ""),
                int(rec.get("occurrences", 0)),
            )
            counts[status] += 1
            if status == "conflict":
                conflicts.append(rec.get("token", ""))
        logger.info("admin import: %s", counts)  # counts only, never values
        return JSONResponse({"result": counts, "conflicts": conflicts})

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    )
    async def passthrough(request: Request, path: str) -> Response:
        """Forward allowlisted paths verbatim; refuse everything else.

        Deny by default: only paths in gateway.passthrough_allowlist reach
        the upstream. Allowlisted bodies are not masked (their schemas are
        not OpenAI chat), but they still pass the outbound leak gate, so a
        known raw value refuses the request instead of leaving the machine.
        The local /v1 prefix is stripped because upstream_base_url already
        carries the version segment.
        """
        denied = _authorized(request)
        if denied is not None:
            return denied
        route = f"/{path}"
        if route not in config.passthrough_allowlist:
            logger.warning("passthrough denied: %s", route)
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": (
                            f"path {route} is not allowlisted; add it to "
                            "gateway.passthrough_allowlist if it must pass"
                        ),
                        "code": "mask_path_blocked",
                    }
                },
            )
        body = await request.body()
        headers = _upstream_headers(request, config)
        if config.session_scope == "global":
            try:
                payload: Any = json.loads(body) if body else None
            except (json.JSONDecodeError, UnicodeDecodeError):
                payload = body.decode("utf-8", "replace")
            blocked = _gate(payload, app.state.session, headers, route)
            if blocked is not None:
                return blocked
        forward = path[len("v1/"):] if path.startswith("v1/") else path
        upstream = await app.state.http.request(
            request.method, f"/{forward}", content=body, headers=headers
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
