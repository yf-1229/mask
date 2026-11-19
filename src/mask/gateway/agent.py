"""Agent entrance: Anthropic-protocol (/v1/messages) entry with translation.

Claude Code and other agent harnesses speak the Anthropic Messages API and
can point their base URL at this gateway (ANTHROPIC_BASE_URL). The gateway
translates Anthropic -> OpenAI chat for the upstream, masks everything on
the way in (same Session/leak gate as the OpenAI path), restores on the way
out, and translates back.

Invariant identical to the OpenAI path: everything crossing the wire to the
upstream is masked and leak-gated; everything returned to the local client
is restored — including tool_use inputs, because those tools execute on
the user's machine and must see real values (their results flow back in and
get masked like any other input).

Out of scope for Phase A: images/thinking blocks are dropped, and
stream=true buffers the upstream to completion before emitting the event
sequence (one text delta with the fully restored text). Correct, not
incremental — same tradeoff as the OpenAI streaming path.
"""

from __future__ import annotations

import json
from typing import Any

from mask.gateway.indicators import RequestMeasure
from mask.pipeline import Session


# --- request translation (Anthropic -> OpenAI chat) ------------------------


def _system_text(system: Any) -> str | None:
    if isinstance(system, str) and system:
        return system
    if isinstance(system, list):
        parts = [
            b.get("text", "")
            for b in system
            if isinstance(b, dict) and isinstance(b.get("text"), str)
        ]
        return "\n".join(parts) if parts else None
    return None


def _block_text(content: Any) -> str:
    """Flatten a tool_result content field (str or block list) to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            b.get("text", "")
            for b in content
            if isinstance(b, dict) and isinstance(b.get("text"), str)
        )
    return ""


def _tool_call(u: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": u.get("id") or "call_mask",
        "type": "function",
        "function": {
            "name": u.get("name") or "",
            "arguments": json.dumps(u.get("input") or {}, ensure_ascii=False),
        },
    }


def anthropic_to_openai(body: dict[str, Any]) -> dict[str, Any]:
    """Translate an Anthropic Messages request body to OpenAI chat format.

    The result goes through the normal mask_chat_request + leak gate before
    touching the network. Unknown/unsupported blocks are dropped rather than
    forwarded verbatim: deny by default, same as path routing.
    """
    out: dict[str, Any] = {}
    if isinstance(body.get("model"), str):
        out["model"] = body["model"]

    messages: list[dict[str, Any]] = []
    system = _system_text(body.get("system"))
    if system:
        messages.append({"role": "system", "content": system})

    for m in body.get("messages") or []:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        if role not in ("user", "assistant"):
            continue
        content = m.get("content")

        if isinstance(content, str):
            messages.append({"role": role, "content": content})
            continue
        if not isinstance(content, list):
            continue

        texts: list[str] = []
        tool_results: list[dict[str, Any]] = []
        tool_uses: list[dict[str, Any]] = []
        for b in content:
            if not isinstance(b, dict):
                continue
            btype = b.get("type")
            if btype == "text" and isinstance(b.get("text"), str):
                texts.append(b["text"])
            elif btype == "tool_result":
                tool_results.append(b)
            elif btype == "tool_use":
                tool_uses.append(b)
            # images / thinking / unknown blocks: dropped (deny by default)

        if role == "assistant":
            msg: dict[str, Any] = {"role": "assistant"}
            joined = "\n".join(texts)
            if joined:
                msg["content"] = joined
            if tool_uses:
                msg["tool_calls"] = [_tool_call(u) for u in tool_uses]
            if "content" in msg or "tool_calls" in msg:
                messages.append(msg)
        else:
            # tool_result blocks become OpenAI tool messages, order preserved
            for tr in tool_results:
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tr.get("tool_use_id") or "",
                        "content": _block_text(tr.get("content")),
                    }
                )
            joined = "\n".join(texts)
            if joined:
                messages.append({"role": "user", "content": joined})

    if messages:
        out["messages"] = messages

    tools = body.get("tools")
    if isinstance(tools, list) and tools:
        mapped = []
        for t in tools:
            if not isinstance(t, dict) or not t.get("name"):
                continue
            mapped.append(
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t.get("description", ""),
                        "parameters": t.get("input_schema") or {"type": "object"},
                    },
                }
            )
        if mapped:
            out["tools"] = mapped

    tc = body.get("tool_choice")
    if isinstance(tc, dict):
        tct = tc.get("type")
        if tct == "auto":
            out["tool_choice"] = "auto"
        elif tct == "any":
            out["tool_choice"] = "required"
        elif tct == "tool" and tc.get("name"):
            out["tool_choice"] = {"type": "function", "function": {"name": tc["name"]}}
        elif tct == "none":
            out["tool_choice"] = "none"

    if isinstance(body.get("max_tokens"), int):
        out["max_tokens"] = body["max_tokens"]
    for key in ("temperature", "top_p"):
        if isinstance(body.get(key), (int, float)):
            out[key] = body[key]
    if isinstance(body.get("stop_sequences"), list) and body["stop_sequences"]:
        out["stop"] = [s for s in body["stop_sequences"] if isinstance(s, str)]
    if body.get("stream"):
        out["stream"] = True
    return out


# --- response translation (OpenAI chat -> Anthropic) ------------------------


def restored_strings(node: Any, session: Session, measure: RequestMeasure) -> Any:
    """Restore tokens inside tool arguments so local tools see real values."""
    if isinstance(node, str):
        restored = session.unmasked(node)
        measure.observe_restore(restored)
        return restored.text
    if isinstance(node, dict):
        return {k: restored_strings(v, session, measure) for k, v in node.items()}
    if isinstance(node, list):
        return [restored_strings(v, session, measure) for v in node]
    return node


_FINISH_MAP = {
    "length": "max_tokens",
    "content_filter": "refusal",
    "tool_calls": "tool_use",
}


def openai_to_anthropic(
    data: dict[str, Any], restored_text: str, session: Session, measure: RequestMeasure
) -> dict[str, Any]:
    """Translate an OpenAI chat response to the Anthropic message shape.

    `restored_text` is the already-restored text content; tool arguments are
    restored here (nested strings) because they execute locally.
    """
    choice = None
    choices = data.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        choice = choices[0]
    message = choice.get("message") if isinstance(choice, dict) else None
    tool_calls = message.get("tool_calls") if isinstance(message, dict) else None

    blocks: list[dict[str, Any]] = []
    if restored_text:
        blocks.append({"type": "text", "text": restored_text})
    if isinstance(tool_calls, list):
        for call in tool_calls:
            if not isinstance(call, dict):
                continue
            fn = call.get("function")
            if not isinstance(fn, dict) or not fn.get("name"):
                continue
            raw_args = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            except json.JSONDecodeError:
                args = {"_raw": raw_args}
            blocks.append(
                {
                    "type": "tool_use",
                    "id": call.get("id") or "toolu_mask",
                    "name": fn.get("name"),
                    "input": restored_strings(args, session, measure)
                    if isinstance(args, (dict, list))
                    else args,
                }
            )

    finish = choice.get("finish_reason") if isinstance(choice, dict) else None
    stop_reason = _FINISH_MAP.get(finish, "end_turn")
    if any(b["type"] == "tool_use" for b in blocks):
        stop_reason = "tool_use"

    usage = data.get("usage") or {}
    return {
        "id": data.get("id") or "msg_mask",
        "type": "message",
        "role": "assistant",
        "model": data.get("model") or "",
        "content": blocks or [{"type": "text", "text": ""}],
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {
            "input_tokens": usage.get("prompt_tokens", 0) or 0,
            "output_tokens": usage.get("completion_tokens", 0) or 0,
        },
    }


# --- streaming translation ---------------------------------------------------


def anthropic_stream_events(message: dict[str, Any], text: str, tool_uses: list[dict[str, Any]]) -> list[str]:
    """Anthropic SSE event sequence for a buffered (fully restored) response.

    Phase A parity with the OpenAI streaming path: upstream chunks are
    buffered, restored as a whole, then emitted as a correct Anthropic
    event stream. Latency is all-at-once; ordering and shapes are what
    agent harnesses expect.
    """
    lines: list[str] = []

    def event(etype: str, payload: dict[str, Any]) -> None:
        lines.append(f"event: {etype}")
        lines.append("data: " + json.dumps(payload, ensure_ascii=False))
        lines.append("")

    skeleton = {**message, "content": []}
    event("message_start", {"type": "message_start", "message": skeleton})
    index = 0
    if text:
        event(
            "content_block_start",
            {"type": "content_block_start", "index": index, "content_block": {"type": "text", "text": ""}},
        )
        event(
            "content_block_delta",
            {"type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": text}},
        )
        event("content_block_stop", {"type": "content_block_stop", "index": index})
        index += 1
    for i, call in enumerate(tool_uses):
        event(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": index,
                "content_block": {
                    "type": "tool_use",
                    "id": call.get("id") or "toolu_mask",
                    "name": call.get("name") or "",
                    "input": {},
                },
            },
        )
        event(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": index,
                "delta": {
                    "type": "input_json_delta",
                    "partial_json": json.dumps(call.get("input") or {}, ensure_ascii=False),
                },
            },
        )
        event("content_block_stop", {"type": "content_block_stop", "index": index})
        index += 1
    event(
        "message_delta",
        {
            "type": "message_delta",
            "delta": {
                "stop_reason": message.get("stop_reason", "end_turn"),
                "stop_sequence": None,
            },
            "usage": message.get("usage") or {},
        },
    )
    event("message_stop", {"type": "message_stop"})
    return "\n".join(lines)
