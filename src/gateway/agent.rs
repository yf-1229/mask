//! Agent entrance: Anthropic-protocol (`/v1/messages`) entry with translation.
//!
//! Claude Code and other agent harnesses speak the Anthropic Messages API and
//! can point their base URL at this gateway (`ANTHROPIC_BASE_URL`). The gateway
//! translates Anthropic -> OpenAI chat for the upstream, masks everything on
//! the way in (same Session/leak gate as the OpenAI path), restores on the way
//! out, and translates back.
//!
//! Invariant identical to the OpenAI path: everything crossing the wire to the
//! upstream is masked and leak-gated; everything returned to the local client
//! is restored — including tool_use inputs, because those tools execute on the
//! user's machine and must see real values (their results flow back in and get
//! masked like any other input).
//!
//! Scope: images/thinking blocks are dropped, and `stream: true` buffers the
//! upstream to completion before emitting the event sequence (one text delta
//! with the fully restored text). Correct, not incremental — same tradeoff as
//! the OpenAI streaming path.

use serde_json::{json, Map, Value};

use crate::gateway::indicators::RequestMeasure;
use crate::session::Session;

// --- request translation (Anthropic -> OpenAI chat) -------------------------

fn system_text(system: Option<&Value>) -> Option<String> {
    match system {
        Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
        Some(Value::Array(blocks)) => {
            let parts: Vec<String> = blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .map(str::to_string)
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join("\n"))
            }
        }
        _ => None,
    }
}

/// Flatten a tool_result content field (string or block list) to text.
fn block_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn tool_call(block: &Value) -> Value {
    let input = block.get("input").cloned().unwrap_or_else(|| json!({}));
    json!({
        "id": block.get("id").and_then(Value::as_str).unwrap_or("call_mask"),
        "type": "function",
        "function": {
            "name": block.get("name").and_then(Value::as_str).unwrap_or(""),
            "arguments": serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_string()),
        },
    })
}

/// Translate an Anthropic Messages request body to OpenAI chat format.
///
/// The result goes through the normal mask + leak gate before touching the
/// network. Unknown/unsupported blocks are dropped rather than forwarded
/// verbatim: deny by default, same as path routing.
pub fn anthropic_to_openai(body: &Value) -> Value {
    let mut out = Map::new();
    if let Some(model) = body.get("model").and_then(Value::as_str) {
        out.insert("model".to_string(), json!(model));
    }

    let mut messages: Vec<Value> = Vec::new();
    if let Some(system) = system_text(body.get("system")) {
        messages.push(json!({"role": "system", "content": system}));
    }

    if let Some(list) = body.get("messages").and_then(Value::as_array) {
        for m in list {
            let Some(role) = m.get("role").and_then(Value::as_str) else {
                continue;
            };
            if role != "user" && role != "assistant" {
                continue;
            }
            let content = m.get("content").cloned().unwrap_or(Value::Null);

            if let Some(text) = content.as_str() {
                messages.push(json!({"role": role, "content": text}));
                continue;
            }
            let Some(blocks) = content.as_array() else {
                continue;
            };

            let mut texts: Vec<String> = Vec::new();
            let mut tool_results: Vec<Value> = Vec::new();
            let mut tool_uses: Vec<Value> = Vec::new();
            for b in blocks {
                match b.get("type").and_then(Value::as_str) {
                    Some("text") => {
                        if let Some(text) = b.get("text").and_then(Value::as_str) {
                            texts.push(text.to_string());
                        }
                    }
                    Some("tool_result") => tool_results.push(b.clone()),
                    Some("tool_use") => tool_uses.push(b.clone()),
                    // images / thinking / unknown blocks: dropped (deny by default)
                    _ => {}
                }
            }

            if role == "assistant" {
                let mut msg = Map::new();
                msg.insert("role".to_string(), json!("assistant"));
                let joined = texts.join("\n");
                if !joined.is_empty() {
                    msg.insert("content".to_string(), json!(joined));
                }
                if !tool_uses.is_empty() {
                    msg.insert(
                        "tool_calls".to_string(),
                        Value::Array(tool_uses.iter().map(tool_call).collect()),
                    );
                }
                if msg.contains_key("content") || msg.contains_key("tool_calls") {
                    messages.push(Value::Object(msg));
                }
            } else {
                // tool_result blocks become OpenAI tool messages, order preserved
                for tr in &tool_results {
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": tr.get("tool_use_id").and_then(Value::as_str).unwrap_or(""),
                        "content": block_text(tr.get("content")),
                    }));
                }
                let joined = texts.join("\n");
                if !joined.is_empty() {
                    messages.push(json!({"role": "user", "content": joined}));
                }
            }
        }
    }
    if !messages.is_empty() {
        out.insert("messages".to_string(), Value::Array(messages));
    }

    if let Some(tools) = body.get("tools").and_then(Value::as_array) {
        let mapped: Vec<Value> = tools
            .iter()
            .filter(|t| t.get("name").and_then(Value::as_str).is_some())
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.get("name").and_then(Value::as_str).unwrap_or(""),
                        "description": t.get("description").and_then(Value::as_str).unwrap_or(""),
                        "parameters": t.get("input_schema").cloned().unwrap_or_else(|| json!({"type": "object"})),
                    },
                })
            })
            .collect();
        if !mapped.is_empty() {
            out.insert("tools".to_string(), Value::Array(mapped));
        }
    }

    if let Some(tc) = body.get("tool_choice").and_then(Value::as_object) {
        match tc.get("type").and_then(Value::as_str) {
            Some("auto") => {
                out.insert("tool_choice".to_string(), json!("auto"));
            }
            Some("any") => {
                out.insert("tool_choice".to_string(), json!("required"));
            }
            Some("tool") => {
                if let Some(name) = tc.get("name").and_then(Value::as_str) {
                    out.insert(
                        "tool_choice".to_string(),
                        json!({"type": "function", "function": {"name": name}}),
                    );
                }
            }
            Some("none") => {
                out.insert("tool_choice".to_string(), json!("none"));
            }
            _ => {}
        }
    }

    if let Some(max_tokens) = body.get("max_tokens").and_then(Value::as_i64) {
        out.insert("max_tokens".to_string(), json!(max_tokens));
    }
    for key in ["temperature", "top_p"] {
        if let Some(value) = body.get(key) {
            if value.is_number() {
                out.insert(key.to_string(), value.clone());
            }
        }
    }
    if let Some(stop) = body.get("stop_sequences").and_then(Value::as_array) {
        let stops: Vec<Value> = stop.iter().filter(|s| s.is_string()).cloned().collect();
        if !stops.is_empty() {
            out.insert("stop".to_string(), Value::Array(stops));
        }
    }
    if body.get("stream").and_then(Value::as_bool).unwrap_or(false) {
        out.insert("stream".to_string(), json!(true));
    }
    Value::Object(out)
}

// --- response translation (OpenAI chat -> Anthropic) ------------------------

/// Restore tokens inside tool arguments so local tools see real values.
pub fn restored_strings(
    node: &Value,
    session: &mut Session,
    measure: &mut RequestMeasure,
) -> Value {
    match node {
        Value::String(text) => {
            let restored = session.unmasked(text);
            measure.observe_restore(&restored);
            Value::String(restored.text)
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), restored_strings(v, session, measure)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| restored_strings(v, session, measure))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn finish_reason(value: Option<&str>) -> &'static str {
    match value {
        Some("length") => "max_tokens",
        Some("content_filter") => "refusal",
        Some("tool_calls") => "tool_use",
        _ => "end_turn",
    }
}

/// Translate an OpenAI chat response to the Anthropic message shape.
///
/// `restored_text` is the already-restored text content; tool arguments are
/// restored here (nested strings) because they execute locally.
pub fn openai_to_anthropic(
    data: &Value,
    restored_text: &str,
    session: &mut Session,
    measure: &mut RequestMeasure,
) -> Value {
    let choice = data
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .cloned()
        .unwrap_or(Value::Null);
    let message = choice.get("message").cloned().unwrap_or(Value::Null);
    let tool_calls = message.get("tool_calls").and_then(Value::as_array);

    let mut blocks: Vec<Value> = Vec::new();
    if !restored_text.is_empty() {
        blocks.push(json!({"type": "text", "text": restored_text}));
    }
    if let Some(tool_calls) = tool_calls {
        for call in tool_calls {
            let Some(function) = call.get("function") else {
                continue;
            };
            let Some(name) = function.get("name").and_then(Value::as_str) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let raw_args = function
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!("{}"));
            let args: Value = match raw_args {
                Value::String(text) => {
                    serde_json::from_str(&text).unwrap_or_else(|_| json!({"_raw": text}))
                }
                other => other,
            };
            let input = if args.is_object() || args.is_array() {
                restored_strings(&args, session, measure)
            } else {
                args
            };
            blocks.push(json!({
                "type": "tool_use",
                "id": call.get("id").and_then(Value::as_str).unwrap_or("toolu_mask"),
                "name": name,
                "input": input,
            }));
        }
    }

    let mut stop_reason = finish_reason(choice.get("finish_reason").and_then(Value::as_str));
    if blocks
        .iter()
        .any(|b| b.get("type").and_then(Value::as_str) == Some("tool_use"))
    {
        stop_reason = "tool_use";
    }

    let usage = data.get("usage").cloned().unwrap_or_else(|| json!({}));
    let content = if blocks.is_empty() {
        vec![json!({"type": "text", "text": ""})]
    } else {
        blocks
    };

    json!({
        "id": data.get("id").and_then(Value::as_str).unwrap_or("msg_mask"),
        "type": "message",
        "role": "assistant",
        "model": data.get("model").and_then(Value::as_str).unwrap_or(""),
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": Value::Null,
        "usage": {
            "input_tokens": usage.get("prompt_tokens").and_then(Value::as_i64).unwrap_or(0),
            "output_tokens": usage.get("completion_tokens").and_then(Value::as_i64).unwrap_or(0),
        },
    })
}

// --- streaming translation ---------------------------------------------------

/// Anthropic SSE event sequence for a buffered (fully restored) response.
///
/// Parity with the OpenAI streaming path: upstream chunks are buffered,
/// restored as a whole, then emitted as a correct Anthropic event stream.
/// Latency is all-at-once; ordering and shapes are what agent harnesses expect.
pub fn anthropic_stream_events(message: &Value, text: &str, tool_uses: &[Value]) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut event = |etype: &str, payload: Value| {
        lines.push(format!("event: {etype}"));
        lines.push(format!("data: {payload}"));
        lines.push(String::new());
    };

    let mut skeleton = message.clone();
    if let Value::Object(map) = &mut skeleton {
        map.insert("content".to_string(), json!([]));
    }
    event(
        "message_start",
        json!({"type": "message_start", "message": skeleton}),
    );

    let mut index = 0usize;
    if !text.is_empty() {
        event(
            "content_block_start",
            json!({"type": "content_block_start", "index": index,
                   "content_block": {"type": "text", "text": ""}}),
        );
        event(
            "content_block_delta",
            json!({"type": "content_block_delta", "index": index,
                   "delta": {"type": "text_delta", "text": text}}),
        );
        event(
            "content_block_stop",
            json!({"type": "content_block_stop", "index": index}),
        );
        index += 1;
    }

    for call in tool_uses {
        event(
            "content_block_start",
            json!({
                "type": "content_block_start",
                "index": index,
                "content_block": {
                    "type": "tool_use",
                    "id": call.get("id").and_then(Value::as_str).unwrap_or("toolu_mask"),
                    "name": call.get("name").and_then(Value::as_str).unwrap_or(""),
                    "input": {},
                },
            }),
        );
        let input = call.get("input").cloned().unwrap_or_else(|| json!({}));
        event(
            "content_block_delta",
            json!({
                "type": "content_block_delta",
                "index": index,
                "delta": {
                    "type": "input_json_delta",
                    "partial_json": serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_string()),
                },
            }),
        );
        event(
            "content_block_stop",
            json!({"type": "content_block_stop", "index": index}),
        );
        index += 1;
    }

    event(
        "message_delta",
        json!({
            "type": "message_delta",
            "delta": {
                "stop_reason": message.get("stop_reason").and_then(Value::as_str).unwrap_or("end_turn"),
                "stop_sequence": Value::Null,
            },
            "usage": message.get("usage").cloned().unwrap_or_else(|| json!({})),
        }),
    );
    event("message_stop", json!({"type": "message_stop"}));
    lines.join("\n")
}
