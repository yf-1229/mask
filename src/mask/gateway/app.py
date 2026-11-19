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
import hmac
import json
import logging
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from nacl.exceptions import CryptoError

from mask.detect.dictionary import UserDictionary
from mask.gateway.agent import (
    anthropic_stream_events,
    anthropic_to_openai,
    openai_to_anthropic,
    restored_strings,
)
from mask.gateway.config import GatewayConfig
from mask.gateway.indicators import (
    Indicators,
    RequestMeasure,
    build_posture,
    request_headers,
)
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
# dummy by design (the real key lives only in the gateway config). The
# Anthropic-style slots (x-api-key / anthropic-* headers) are entry-protocol
# headers: the gateway token rides in them, so they terminate here too.
_HOP_BY_HOP = {
    "host",
    "authorization",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "accept-encoding",
    "x-api-key",
    "anthropic-version",
    "anthropic-beta",
}

# Entry protocols served by the gateway; shown in the X-Mask-In header and
# the /status snapshot so a user can see how agents and humans entered.
ENTRY_OPENAI = "v1/chat"
ENTRY_ANTHROPIC = "v1/messages"
ENTRY_PASSTHROUGH = "passthrough"


def _mask_text(
    text: str, session: Session, measure: RequestMeasure | None = None
) -> str:
    masked, result = session.masked(text)
    if measure is not None:
        measure.masked += len(result.entities)
    if result.entities:
        logger.info(
            "masked %d entities: %s",
            len(result.entities),
            ", ".join(sorted({e.type.value for e in result.entities})),
        )
    return masked


def _mask_content(
    content: Any, session: Session, measure: RequestMeasure | None = None
) -> Any:
    if isinstance(content, str):
        return _mask_text(content, session, measure)
    if isinstance(content, list):
        return [
            (
                {**part, "text": _mask_text(part["text"], session, measure)}
                if isinstance(part, dict) and isinstance(part.get("text"), str)
                else part
            )
            for part in content
        ]
    return content


def _mask_strings(
    node: Any, session: Session, measure: RequestMeasure | None = None
) -> Any:
    """Mask every string inside a parsed JSON argument blob."""
    if isinstance(node, str):
        return _mask_text(node, session, measure)
    if isinstance(node, dict):
        return {k: _mask_strings(v, session, measure) for k, v in node.items()}
    if isinstance(node, list):
        return [_mask_strings(v, session, measure) for v in node]
    return node


def _mask_json_string(
    raw: str, session: Session, measure: RequestMeasure | None = None
) -> str:
    """Mask a JSON-encoded string; non-JSON strings are masked as text."""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return _mask_text(raw, session, measure)
    return json.dumps(_mask_strings(parsed, session, measure), ensure_ascii=False)


def _mask_tool_calls(
    tool_calls: Any, session: Session, measure: RequestMeasure | None = None
) -> Any:
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
                    "arguments": _mask_json_string(fn["arguments"], session, measure),
                },
            }
        out.append(call)
    return out


def mask_chat_request(
    body: dict[str, Any],
    session: Session,
    measure: RequestMeasure | None = None,
) -> dict[str, Any]:
    """Return a copy of the request body with PII in messages replaced."""
    masked = dict(body)
    messages = masked.get("messages")
    if isinstance(messages, list):
        out = []
        for m in messages:
            if isinstance(m, dict):
                m = {**m, "content": _mask_content(m.get("content"), session, measure)}
                if "tool_calls" in m:
                    m = {
                        **m,
                        "tool_calls": _mask_tool_calls(
                            m["tool_calls"], session, measure
                        ),
                    }
            out.append(m)
        masked["messages"] = out
    return masked


def _restore_text(
    text: str, session: Session, measure: RequestMeasure | None = None
) -> str:
    restored = session.unmasked(text)
    if measure is not None:
        measure.observe_restore(restored)
    for warning in restored.warnings:
        logger.warning("restore: %s", warning)
    return restored.text


def restore_chat_response(
    data: dict[str, Any],
    session: Session,
    measure: RequestMeasure | None = None,
) -> dict[str, Any]:
    """Restore pseudonyms in choices[*].message.content, in place."""
    for choice in data.get("choices", []):
        message = choice.get("message") if isinstance(choice, dict) else None
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            message["content"] = _restore_text(message["content"], session, measure)
    return data


def _fold_measure(app: FastAPI, measure: RequestMeasure) -> None:
    """Fold a finished request's measurements into the process counters."""
    ind = app.state.indicators
    ind.incr("entities_masked", measure.masked)
    ind.incr("tokens_restored", measure.restored)
    ind.incr("tokens_fuzzy_repaired", measure.fuzzy_repaired)
    ind.incr("tokens_unresolved", measure.unresolved)


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
    # Reliability indicators: process-wide counters surfaced at /status and
    # in X-Mask-* response headers. Counts only, never contents.
    app.state.indicators = Indicators()
    # Handoff state, process-local by design: failed-passphrase attempts
    # per envelope fingerprint, and fingerprints of consumed (single-use)
    # envelopes. Restarting the gateway resets these, but the sealed
    # expiry still bounds every envelope's life.
    app.state.handoff_failures: dict[str, int] = {}
    app.state.handoff_consumed: set[str] = set()
    if config.session_scope == "global":
        # NER model loads once here, not per request.
        app.state.session = Session(dictionary=dictionary, use_ner=config.use_ner)

    def get_session() -> Session:
        if config.session_scope == "global":
            return app.state.session
        return Session(dictionary=dictionary, use_ner=config.use_ner)

    ind: Indicators = app.state.indicators

    def _posture() -> dict[str, Any]:
        """Live posture for /status; counts only, no contents."""
        records = (
            len(app.state.session.pseudonyms.records())
            if config.session_scope == "global"
            else 0
        )
        return build_posture(config, records, dictionary.size())

    def _record(measure: RequestMeasure) -> None:
        """Fold a finished request's measurements into the counters."""
        ind.incr("entities_masked", measure.masked)
        ind.incr("tokens_restored", measure.restored)
        ind.incr("tokens_fuzzy_repaired", measure.fuzzy_repaired)
        ind.incr("tokens_unresolved", measure.unresolved)

    def _authorized(request: Request) -> Response | None:
        """Gateway token check; unset token means no auth (localhost only).

        The token may arrive as `Authorization: Bearer <token>` (OpenAI
        style) or as `x-api-key: <token>` (Anthropic style): the same
        secret protects both entrances. The comparison is constant-time:
        the token is a long-lived shared secret, so no early-exit string
        comparison.
        """
        if not config.gateway_token:
            return None
        expected = config.gateway_token.encode("utf-8")
        provided = request.headers.get("authorization", "")
        api_key = request.headers.get("x-api-key", "")
        ok = False
        if provided.startswith("Bearer "):
            ok = hmac.compare_digest(
                provided[len("Bearer "):].encode("utf-8"), expected
            )
        if not ok and api_key:
            ok = hmac.compare_digest(api_key.encode("utf-8"), expected)
        if ok:
            return None
        ind.incr("auth_denied")
        ind.incr("requests_blocked")
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
            ind.incr("leak_warnings")
            return None
        ind.incr("leak_blocks")
        ind.incr("requests_blocked")
        return JSONResponse(
            status_code=400,
            headers={"X-Mask-Leak-Blocked": "true"},
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
        """Admin endpoints: disabled without a token, loopback-only by
        default. The envelope file travels between teammates; the admin
        API itself never needs to be reachable from the network."""
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
        if not config.admin_allow_remote:
            host = request.client.host if request.client else ""
            if host not in ("127.0.0.1", "::1", "localhost"):
                logger.warning("admin refused from non-loopback client: %s", host)
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": {
                            "message": (
                                "admin endpoints accept loopback clients only "
                                "(set gateway.admin_allow_remote to override)"
                            ),
                            "code": "mask_admin_local_only",
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

    @app.get("/status")
    async def status(request: Request) -> Response:
        """Reliability indicators: posture + live counters.

        Counts only — the response is designed to be publishable (website
        widget, clipboard, chat). Gated by the gateway token like the proxy
        entrances when one is set — unless `gateway.status_public = true`
        explicitly opts into publishing: the snapshot is PII-free by
        construction, and opting into publishing means exactly that.
        """
        if not config.status_public:
            denied = _authorized(request)
            if denied is not None:
                return denied
        snapshot = ind.snapshot(_posture())
        headers = {"Cache-Control": "no-store"}
        if config.status_public:
            headers["Access-Control-Allow-Origin"] = "*"
        return JSONResponse(snapshot, headers=headers)

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        denied = _authorized(request)
        if denied is not None:
            return denied
        ind.incr("requests_total")
        body = await request.json()
        session = get_session()
        measure = RequestMeasure()
        masked = mask_chat_request(body, session, measure)
        headers = _upstream_headers(request, config)
        blocked = _gate(masked, session, headers, "chat/completions")
        if blocked is not None:
            return blocked
        url = "/chat/completions"

        if body.get("stream"):
            ind.incr("stream_requests")
            return await _proxy_streaming(
                app, masked, headers, url, session, measure, ENTRY_OPENAI
            )

        upstream = await app.state.http.post(url, json=masked, headers=headers)
        if upstream.status_code >= 400:
            return Response(
                content=upstream.content,
                status_code=upstream.status_code,
                media_type=upstream.headers.get("content-type"),
            )
        data = upstream.json()
        restore_chat_response(data, session, measure)
        _record(measure)
        return JSONResponse(
            data, headers=request_headers(measure, config, ENTRY_OPENAI)
        )

    @app.post("/v1/messages")
    async def messages(request: Request) -> Response:
        """Agent entrance: Anthropic Messages protocol (e.g. Claude Code).

        The payload is translated to OpenAI chat for the upstream and flows
        through exactly the same mask layer and outbound leak gate — there
        is no second, weaker code path to the network. Responses are
        restored (tool arguments included: they execute locally) and
        translated back to the Anthropic shape. `stream: true` buffers the
        upstream and emits a correct Anthropic SSE sequence in one shot
        (Phase A parity).
        """
        denied = _authorized(request)
        if denied is not None:
            return denied
        ind.incr("requests_total")

        def _anthropic_error(
            status_code: int, etype: str, message: str, **detail: Any
        ) -> Response:
            err: dict[str, Any] = {"type": etype, "message": message}
            err.update(detail)
            return JSONResponse(
                status_code=status_code,
                content={"type": "error", "error": err},
            )

        body: Any
        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _anthropic_error(400, "invalid_request_error", "malformed JSON body")
        if not isinstance(body, dict):
            return _anthropic_error(400, "invalid_request_error", "invalid body")

        session = get_session()
        measure = RequestMeasure()
        openai_body = anthropic_to_openai(body)
        masked = mask_chat_request(openai_body, session, measure)
        headers = _upstream_headers(request, config)
        blocked = _gate(masked, session, headers, "v1/messages")
        if blocked is not None:
            # Re-wrap the gate decision in the Anthropic error envelope; the
            # offending values go to the trusted local client only.
            err = json.loads(blocked.body)["error"]
            return _anthropic_error(
                blocked.status_code,
                "invalid_request_error",
                err.get("message", "blocked by the mask gateway"),
                mask_code=err.get("code"),
                mask_fields=err.get("fields"),
                mask_values=err.get("values"),
            )

        if openai_body.get("stream"):
            ind.incr("stream_requests")
            status_code, raw, collected, ct = await _collect_chat_stream(
                app, masked, headers, "/chat/completions"
            )
            if status_code >= 400:
                return Response(
                    content=raw, status_code=status_code, media_type=ct
                )
            restored_text = _restore_text(collected["text"], session, measure)
            tool_uses: list[dict[str, Any]] = []
            for tc in collected["tool_calls"]:
                fn = tc.get("function") or {}
                raw_args = fn.get("arguments") or "{}"
                try:
                    args = json.loads(raw_args)
                except json.JSONDecodeError:
                    args = {"_raw": raw_args}
                tool_uses.append(
                    {
                        "id": tc.get("id") or "toolu_mask",
                        "name": fn.get("name") or "",
                        "input": restored_strings(args, session, measure),
                    }
                )
            message = {
                "id": collected["meta"].get("id") or "msg_mask",
                "type": "message",
                "role": "assistant",
                "model": collected["meta"].get("model") or body.get("model") or "",
                "content": [],
                "stop_reason": "tool_use" if tool_uses else "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 0, "output_tokens": 0},
            }
            _record(measure)
            return Response(
                content=anthropic_stream_events(
                    message, restored_text, tool_uses
                ),
                media_type="text/event-stream",
                headers=request_headers(measure, config, ENTRY_ANTHROPIC),
            )

        upstream = await app.state.http.post("/chat/completions", json=masked, headers=headers)
        if upstream.status_code >= 400:
            try:
                err = upstream.json().get("error", {})
                return _anthropic_error(
                    upstream.status_code,
                    "api_error",
                    err.get("message", "upstream error"),
                )
            except (ValueError, AttributeError):
                return _anthropic_error(
                    upstream.status_code, "api_error", "upstream error"
                )
        data = upstream.json()
        choices = data.get("choices") or [{}]
        choice0 = choices[0] if isinstance(choices[0], dict) else {}
        message0 = choice0.get("message") if isinstance(choice0, dict) else {}
        content = (
            message0.get("content")
            if isinstance(message0, dict) and isinstance(message0.get("content"), str)
            else ""
        )
        restored_text = _restore_text(content, session, measure) if content else ""
        out = openai_to_anthropic(data, restored_text, session, measure)
        _record(measure)
        return JSONResponse(
            out, headers=request_headers(measure, config, ENTRY_ANTHROPIC)
        )

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
        ind.incr("handoff_exports")
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
        decryption outright, failed passphrase attempts (認証失敗) are
        counted per envelope — at the configured limit the envelope is
        locked for good, even for the correct passphrase — and a
        successful import consumes the envelope (single use). Token
        clashes with different values are never rebound; they are
        reported as conflicts.
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
        if fingerprint in app.state.handoff_consumed:
            logger.warning("admin import: envelope consumed (fp %s)", fingerprint[:12])
            ind.incr("handoff_consumed")
            return JSONResponse(
                status_code=410,
                content={
                    "error": {
                        "message": (
                            "envelope already imported; single use — "
                            "request a fresh export"
                        ),
                        "code": "mask_envelope_consumed",
                    }
                },
            )
        failures = app.state.handoff_failures
        if failures.get(fingerprint, 0) >= config.handoff_max_attempts:
            logger.warning("admin import: envelope locked (fp %s)", fingerprint[:12])
            ind.incr("handoff_locks")
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
            ind.incr("handoff_expired")
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
                ind.incr("handoff_locks")
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
        if payload.get("v") != 1 or not isinstance(records, list):
            return _bad_request("envelope payload has no records")
        counts = {"imported": 0, "already": 0, "conflict": 0, "invalid": 0}
        conflicts: list[str] = []
        for rec in records:
            if not isinstance(rec, dict):
                counts["invalid"] += 1
                continue
            token = rec.get("token")
            value = rec.get("value")
            if not isinstance(token, str) or not isinstance(value, str):
                counts["invalid"] += 1
                continue
            try:
                occurrences = int(rec.get("occurrences", 0))
            except (TypeError, ValueError):
                occurrences = 0
            status = app.state.session.pseudonyms.import_record(
                token, value, occurrences
            )
            counts[status] += 1
            if status == "conflict":
                conflicts.append(token)
        # single use: this envelope will never import again
        app.state.handoff_consumed.add(fingerprint)
        ind.incr("handoff_imports")
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
        ind.incr("requests_total")
        route = f"/{path}"
        if route not in config.passthrough_allowlist:
            logger.warning("passthrough denied: %s", route)
            ind.incr("paths_denied")
            ind.incr("requests_blocked")
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


async def _collect_chat_stream(
    app: FastAPI,
    masked_body: dict[str, Any],
    headers: dict[str, str],
    url: str,
) -> tuple[int, bytes, dict[str, Any]]:
    """Buffer an upstream OpenAI SSE stream to completion.

    Returns (status, raw_body, collected, content_type) where `collected` is
    populated only on 200: {"meta": {...}, "text": str, "tool_calls": [merged calls]}.
    Tool-call fragments are stitched by index so the merged arguments JSON
    survives chunk boundaries; masking already happened upstream of this.
    """
    req = app.state.http.build_request("POST", url, json=masked_body, headers=headers)
    upstream = await app.state.http.send(req, stream=True)
    if upstream.status_code >= 400:
        content = await upstream.aread()
        ct = upstream.headers.get("content-type", "application/json")
        await upstream.aclose()
        return upstream.status_code, content, {}, ct

    meta: dict[str, Any] = {}
    parts: list[str] = []
    tool_calls: dict[int, dict[str, Any]] = {}
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
            for choice in chunk.get("choices", []):
                if not isinstance(choice, dict):
                    continue
                delta = choice.get("delta")
                if not isinstance(delta, dict):
                    continue
                for tc in delta.get("tool_calls") or []:
                    if not isinstance(tc, dict):
                        continue
                    idx = int(tc.get("index", 0))
                    acc = tool_calls.setdefault(
                        idx, {"id": "", "type": "function", "function": {}}
                    )
                    if tc.get("id"):
                        acc["id"] = tc["id"]
                    fn = tc.get("function") or {}
                    if fn.get("name"):
                        # first fragment carries the (possibly cut) name
                        acc["function"]["name"] = fn["name"]
                    if fn.get("arguments"):
                        acc["function"]["arguments"] = (
                            acc["function"].get("arguments", "") + fn["arguments"]
                        )
    finally:
        await upstream.aclose()

    merged = [
        {
            "id": tc["id"],
            "type": "function",
            "function": tc["function"],
        }
        for _, tc in sorted(tool_calls.items())
        if tc["function"].get("name") or tc["function"].get("arguments")
    ]
    collected = {"meta": meta, "text": "".join(parts), "tool_calls": merged}
    return 200, b"", collected, ""


async def _proxy_streaming(
    app: FastAPI,
    masked_body: dict[str, Any],
    headers: dict[str, str],
    url: str,
    session: Session,
    measure: RequestMeasure | None = None,
    entry: str = ENTRY_OPENAI,
) -> Response:
    """Buffer the upstream SSE stream, restore it whole, emit OpenAI chunks."""
    measure = measure or RequestMeasure()
    status, raw, collected, ct = await _collect_chat_stream(
        app, masked_body, headers, url
    )
    if status >= 400:
        return Response(content=raw, status_code=status, media_type=ct)

    restored = _restore_text(collected["text"], session, measure)
    _fold_measure(app, measure)
    meta = collected["meta"]
    meta["object"] = "chat.completion.chunk"
    tool_calls = collected["tool_calls"]
    finish_reason = "tool_calls" if tool_calls else "stop"

    def generate():
        first = {
            **meta,
            "choices": [],
        }
        delta: dict[str, Any] = {"role": "assistant", "content": restored}
        if tool_calls:
            first["choices"] = [
                {
                    "index": 0,
                    "delta": {**delta, "tool_calls": tool_calls},
                    "finish_reason": None,
                }
            ]
        else:
            first["choices"] = [
                {"index": 0, "delta": delta, "finish_reason": None}
            ]
        last = {
            **meta,
            "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
        }
        yield _sse_line(first)
        yield _sse_line(last)
        yield _sse_line("[DONE]")

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers=request_headers(measure, app.state.config, entry),
    )
