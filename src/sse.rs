//! Streamed provider responses (server-sent events).
//!
//! A streamed reply arrives as many small events, and a tool call is spread
//! across them: the name in one, the arguments in pieces over several more.
//! `StreamCapture` reassembles the events into the same shape a non-streamed
//! reply has, so the same policy check applies. `chat_stream` and
//! `responses_stream` turn a rewritten reply back into a stream.
//!
//! `LiveGate` lets the start of a reply through as it arrives, as long as it
//! is only text, and holds everything back from the first event that could
//! carry a tool call. `chat_tail` and `responses_tail` rebuild the held part
//! to fit after what the agent already received.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use crate::openai::array;

/// Splits a byte stream into the `data` payloads of its events.
#[derive(Default)]
struct EventReader {
    /// Bytes received after the last complete line.
    pending: Vec<u8>,
    /// `data:` lines of the event being read.
    data: Vec<String>,
}

impl EventReader {
    fn feed(&mut self, bytes: &[u8], payloads: &mut Vec<String>) {
        self.pending.extend_from_slice(bytes);
        let mut start = 0;
        while let Some(offset) = self.pending[start..].iter().position(|&b| b == b'\n') {
            let line = self.pending[start..start + offset].to_vec();
            start += offset + 1;
            self.line(&line, payloads);
        }
        self.pending.drain(..start);
    }

    fn line(&mut self, line: &[u8], payloads: &mut Vec<String>) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            // A blank line ends the event.
            self.dispatch(payloads);
        } else if let Some(rest) = line.strip_prefix(b"data:") {
            let rest = rest.strip_prefix(b" ").unwrap_or(rest);
            self.data.push(String::from_utf8_lossy(rest).into_owned());
        }
        // `event:`, `id:`, `retry:` and comment lines carry nothing needed here.
    }

    fn dispatch(&mut self, payloads: &mut Vec<String>) {
        if !self.data.is_empty() {
            payloads.push(self.data.join("\n"));
            self.data.clear();
        }
    }

    /// Flush whatever is left when the stream ends without a final blank line.
    fn finish(&mut self, payloads: &mut Vec<String>) {
        if !self.pending.is_empty() {
            let line = std::mem::take(&mut self.pending);
            self.line(&line, payloads);
        }
        self.dispatch(payloads);
    }
}

/// What a finished stream turned out to contain.
#[derive(Debug)]
pub enum Captured {
    /// A Chat Completions stream, reassembled into a non-streamed completion.
    Chat(Value),
    /// A Responses API stream: its final event name and full response object.
    Responses { event: String, response: Value },
    /// It looks like a provider stream but cannot be checked. The reason is
    /// for the log.
    Unreadable(&'static str),
    /// Nothing in it could carry a tool call.
    Nothing,
}

/// Reads a streamed provider response as it passes and reassembles it.
#[derive(Default)]
pub struct StreamCapture {
    reader: EventReader,
    chat: ChatAccumulator,
    saw_chat: bool,
    saw_responses: bool,
    terminal: Option<(String, Value)>,
    malformed: bool,
}

impl StreamCapture {
    pub fn feed(&mut self, bytes: &[u8]) {
        let mut payloads = Vec::new();
        self.reader.feed(bytes, &mut payloads);
        for payload in payloads {
            self.payload(&payload);
        }
    }

    pub fn finish(mut self) -> Captured {
        let mut payloads = Vec::new();
        self.reader.finish(&mut payloads);
        for payload in payloads {
            self.payload(&payload);
        }
        self.result()
    }

    fn result(self) -> Captured {
        if self.malformed {
            return Captured::Unreadable("the stream contained data that is not valid JSON");
        }
        if self.saw_responses {
            return match self.terminal {
                Some((event, response)) => Captured::Responses { event, response },
                None => Captured::Unreadable("the stream ended without its final response event"),
            };
        }
        if self.saw_chat {
            return Captured::Chat(self.chat.into_completion());
        }
        Captured::Nothing
    }

    fn payload(&mut self, payload: &str) {
        let payload = payload.trim();
        if payload.is_empty() || payload == "[DONE]" {
            return;
        }
        let Ok(event) = serde_json::from_str::<Value>(payload) else {
            self.malformed = true;
            return;
        };

        let kind = event["type"].as_str().unwrap_or("");
        if kind.starts_with("response.") {
            // Responses API. The last event carries the whole response.
            self.saw_responses = true;
            let is_terminal = matches!(
                kind,
                "response.completed" | "response.incomplete" | "response.failed"
            );
            if is_terminal && event["response"].is_object() {
                self.terminal = Some((kind.to_string(), event["response"].clone()));
            }
        } else if event["object"] == "chat.completion.chunk"
            || array(&event, "choices")
                .iter()
                .any(|choice| choice.get("delta").is_some())
        {
            self.saw_chat = true;
            self.chat.add(&event);
        }
    }
}

/// Fields a Chat Completions choice may carry in an event that is let
/// through live. Anything else holds the rest of the stream back.
const LIVE_CHOICE_FIELDS: [&str; 4] = ["index", "delta", "finish_reason", "logprobs"];

/// Text fields of a Chat Completions delta. None of them can hold a call.
const LIVE_TEXT_FIELDS: [&str; 4] = ["content", "refusal", "reasoning", "reasoning_content"];

/// Delta fields that are not read as tool calls by `StreamCapture`, and so
/// carry nothing a policy would judge.
const LIVE_OTHER_FIELDS: [&str; 2] = ["reasoning_details", "annotations"];

/// Responses API events that only carry text, reasoning or status.
const LIVE_RESPONSE_EVENTS: [&str; 14] = [
    "response.content_part.added",
    "response.content_part.done",
    "response.output_text.delta",
    "response.output_text.done",
    "response.output_text.annotation.added",
    "response.refusal.delta",
    "response.refusal.done",
    "response.reasoning_text.delta",
    "response.reasoning_text.done",
    "response.reasoning_summary_part.added",
    "response.reasoning_summary_part.done",
    "response.reasoning_summary_text.delta",
    "response.reasoning_summary_text.done",
    "response.reasoning.delta",
];

/// What the agent already received of a streamed reply, so that the held
/// part can be rebuilt to follow on from it.
#[derive(Default, Debug)]
pub struct Sent {
    /// Chat Completions: the text sent so far, by choice index.
    content: BTreeMap<u64, String>,
    /// Chat Completions: choices whose `role` was sent.
    role: BTreeSet<u64>,
    /// Responses API: the `response.created` event was sent.
    started: bool,
    /// Responses API: output items whose `output_item.added` was sent.
    added: BTreeSet<u64>,
    /// Responses API: output items whose `output_item.done` was sent.
    done: BTreeSet<u64>,
    /// Responses API: the highest `sequence_number` sent.
    sequence: Option<u64>,
}

impl Sent {
    /// Whether this event can go to the agent before the reply is checked,
    /// noting what it carries if so. Only text and status pass. A tool call,
    /// a finish, anything unknown or anything unreadable does not.
    fn admit(&mut self, payload: &str) -> bool {
        let Ok(event) = serde_json::from_str::<Value>(payload.trim()) else {
            return false; // `[DONE]` too: it ends the stream, so it waits
        };
        match event.get("type") {
            None => self.admit_chat(&event),
            Some(kind) => match kind.as_str() {
                Some(kind) if kind.starts_with("response.") => self.admit_response(kind, &event),
                _ => false,
            },
        }
    }

    fn admit_chat(&mut self, chunk: &Value) -> bool {
        let Some(choices) = chunk.get("choices").and_then(Value::as_array) else {
            return false;
        };
        let harmless = choices.iter().all(|choice| {
            let Some(fields) = choice.as_object() else {
                return false;
            };
            let known = fields
                .iter()
                .all(|(key, value)| LIVE_CHOICE_FIELDS.contains(&key.as_str()) || value.is_null());
            let delta_ok = match choice.get("delta") {
                None | Some(Value::Null) => true,
                Some(Value::Object(delta)) => delta.iter().all(|(key, value)| match key.as_str() {
                    "role" => value.is_null() || value == "assistant",
                    key if LIVE_TEXT_FIELDS.contains(&key) => value.is_null() || value.is_string(),
                    key if LIVE_OTHER_FIELDS.contains(&key) => true,
                    // `tool_calls: null` and the like carry nothing.
                    _ => value.is_null(),
                }),
                Some(_) => false,
            };
            known
                && delta_ok
                && choice["finish_reason"].is_null()
                && (choice.get("index").is_none() || choice["index"].is_u64())
        });
        if !harmless {
            return false;
        }
        for choice in choices {
            let index = choice["index"].as_u64().unwrap_or(0);
            let delta = &choice["delta"];
            if delta["role"].is_string() {
                self.role.insert(index);
            }
            if let Some(text) = delta["content"].as_str() {
                self.content.entry(index).or_default().push_str(text);
            }
        }
        true
    }

    fn admit_response(&mut self, kind: &str, event: &Value) -> bool {
        let harmless = match kind {
            "response.created" | "response.in_progress" | "response.queued" => {
                array(&event["response"], "output").is_empty()
            }
            "response.output_item.added" | "response.output_item.done" => {
                matches!(
                    event["item"]["type"].as_str(),
                    Some("message" | "reasoning")
                )
            }
            kind => LIVE_RESPONSE_EVENTS.contains(&kind),
        };
        if !harmless {
            return false;
        }
        if kind == "response.created" {
            self.started = true;
        }
        if let Some(index) = event["output_index"].as_u64() {
            match kind {
                "response.output_item.added" => {
                    self.added.insert(index);
                }
                "response.output_item.done" => {
                    self.done.insert(index);
                }
                _ => {}
            }
        }
        if let Some(sequence) = event["sequence_number"].as_u64() {
            self.sequence = Some(self.sequence.map_or(sequence, |last| last.max(sequence)));
        }
        true
    }
}

/// Splits a provider stream as it arrives: events that only carry text go
/// to the agent at once, and from the first event that could carry a tool
/// call on, everything is held until the reply is complete and checked.
/// Events keep their original bytes.
#[derive(Default)]
pub struct LiveGate {
    capture: StreamCapture,
    /// Bytes after the last complete line.
    pending: Vec<u8>,
    /// The raw bytes of the event being read, and its `data:` lines.
    event: Vec<u8>,
    data: Vec<String>,
    /// Set at the first event that cannot go out live. Never unset.
    holding: bool,
    held: Vec<u8>,
    sent: Sent,
}

impl LiveGate {
    /// Read bytes from the provider. Returns the bytes the agent may have now.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        self.pending.extend_from_slice(bytes);
        let mut start = 0;
        while let Some(offset) = self.pending[start..].iter().position(|&b| b == b'\n') {
            let end = start + offset + 1;
            let line = self.pending[start..end].to_vec();
            start = end;
            self.line(&line, &mut out);
        }
        self.pending.drain(..start);
        out
    }

    /// Whether the stream is a Responses API stream, as far as it was read.
    pub fn is_responses(&self) -> bool {
        self.capture.saw_responses
    }

    fn line(&mut self, raw: &[u8], out: &mut Vec<u8>) {
        self.event.extend_from_slice(raw);
        let text = raw.strip_suffix(b"\n").unwrap_or(raw);
        let text = text.strip_suffix(b"\r").unwrap_or(text);
        if text.is_empty() {
            self.dispatch(out);
        } else if let Some(rest) = text.strip_prefix(b"data:") {
            let rest = rest.strip_prefix(b" ").unwrap_or(rest);
            self.data.push(String::from_utf8_lossy(rest).into_owned());
        }
    }

    fn dispatch(&mut self, out: &mut Vec<u8>) {
        let raw = std::mem::take(&mut self.event);
        if !self.data.is_empty() {
            let payload = self.data.join("\n");
            self.data.clear();
            self.capture.payload(&payload);
            if !self.holding && !self.sent.admit(&payload) {
                self.holding = true;
            }
        }
        // Comment lines and empty events carry nothing and go out as they are,
        // unless the stream is already being held, which keeps the order.
        if self.holding {
            self.held.extend_from_slice(&raw);
        } else {
            out.extend_from_slice(&raw);
        }
    }

    /// The stream has ended. Returns the reassembled reply, the bytes that
    /// were held back, and what the agent already received.
    pub fn finish(mut self) -> (Captured, Vec<u8>, Sent) {
        // An event that ends without its blank line is still read, and held.
        self.holding = true;
        if !self.pending.is_empty() {
            let line = std::mem::take(&mut self.pending);
            let mut ignored = Vec::new();
            self.line(&line, &mut ignored);
        }
        if !self.event.is_empty() || !self.data.is_empty() {
            let mut ignored = Vec::new();
            self.dispatch(&mut ignored);
        }
        (self.capture.result(), self.held, self.sent)
    }
}

#[derive(Default)]
struct ChatAccumulator {
    /// `id`, `created`, `model` and `system_fingerprint`, from the first chunk
    /// that has them.
    head: Map<String, Value>,
    usage: Option<Value>,
    choices: BTreeMap<u64, ChoiceAccumulator>,
}

#[derive(Default)]
struct ChoiceAccumulator {
    content: String,
    tool_calls: Vec<ToolCallAccumulator>,
    function_call: Option<(String, String)>,
    finish_reason: Value,
}

#[derive(Default)]
struct ToolCallAccumulator {
    index: Option<u64>,
    id: String,
    kind: String,
    name: String,
    arguments: String,
}

const HEAD_FIELDS: [&str; 4] = ["id", "created", "model", "system_fingerprint"];

impl ChatAccumulator {
    fn add(&mut self, chunk: &Value) {
        for field in HEAD_FIELDS {
            if !self.head.contains_key(field) {
                if let Some(value) = chunk.get(field).filter(|value| !value.is_null()) {
                    self.head.insert(field.to_string(), value.clone());
                }
            }
        }
        if let Some(usage) = chunk.get("usage").filter(|usage| usage.is_object()) {
            self.usage = Some(usage.clone());
        }

        for choice in array(chunk, "choices") {
            let index = choice["index"].as_u64().unwrap_or(0);
            let entry = self.choices.entry(index).or_default();
            if !choice["finish_reason"].is_null() {
                entry.finish_reason = choice["finish_reason"].clone();
            }
            let delta = &choice["delta"];
            if let Some(text) = delta["content"].as_str() {
                entry.content.push_str(text);
            }
            for call in array(delta, "tool_calls") {
                entry.add_tool_call(call);
            }
            if delta["function_call"].is_object() {
                let (name, arguments) = entry.function_call.get_or_insert_with(Default::default);
                name.push_str(delta["function_call"]["name"].as_str().unwrap_or(""));
                arguments.push_str(delta["function_call"]["arguments"].as_str().unwrap_or(""));
            }
        }
    }

    fn into_completion(self) -> Value {
        let mut completion = self.head;
        completion.insert("object".to_string(), json!("chat.completion"));

        let choices: Vec<Value> = self
            .choices
            .into_iter()
            .map(|(index, choice)| {
                let mut message = json!({ "role": "assistant", "content": null });
                if !choice.content.is_empty() {
                    message["content"] = json!(choice.content);
                }
                if !choice.tool_calls.is_empty() {
                    let calls: Vec<Value> = choice
                        .tool_calls
                        .into_iter()
                        .map(ToolCallAccumulator::into_call)
                        .collect();
                    message["tool_calls"] = json!(calls);
                }
                if let Some((name, arguments)) = choice.function_call {
                    message["function_call"] = json!({ "name": name, "arguments": arguments });
                }
                json!({
                    "index": index,
                    "message": message,
                    "finish_reason": choice.finish_reason,
                })
            })
            .collect();
        completion.insert("choices".to_string(), json!(choices));

        if let Some(usage) = self.usage {
            completion.insert("usage".to_string(), usage);
        }
        Value::Object(completion)
    }
}

impl ChoiceAccumulator {
    /// Merge one tool-call fragment into the call it belongs to.
    fn add_tool_call(&mut self, fragment: &Value) {
        let index = fragment["index"].as_u64();
        let id = fragment["id"].as_str().filter(|id| !id.is_empty());

        // Providers identify the call by `index`. A few omit it, so fall back
        // to the id, and failing that to the call most recently started.
        let position = match (index, id) {
            (Some(index), _) => self
                .tool_calls
                .iter()
                .position(|call| call.index == Some(index)),
            (None, Some(id)) => self.tool_calls.iter().position(|call| call.id == id),
            (None, None) => self.tool_calls.len().checked_sub(1),
        };
        let position = position.unwrap_or_else(|| {
            self.tool_calls.push(ToolCallAccumulator {
                index,
                ..Default::default()
            });
            self.tool_calls.len() - 1
        });
        let call = &mut self.tool_calls[position];

        if call.id.is_empty() {
            call.id = id.unwrap_or("").to_string();
        }
        if let Some(kind) = fragment["type"].as_str() {
            call.kind = kind.to_string();
        }
        if fragment["custom"].is_object() {
            call.kind = "custom".to_string();
            call.name
                .push_str(fragment["custom"]["name"].as_str().unwrap_or(""));
            call.arguments
                .push_str(fragment["custom"]["input"].as_str().unwrap_or(""));
        } else {
            call.name
                .push_str(fragment["function"]["name"].as_str().unwrap_or(""));
            call.arguments
                .push_str(fragment["function"]["arguments"].as_str().unwrap_or(""));
        }
    }
}

impl ToolCallAccumulator {
    fn into_call(self) -> Value {
        if self.kind == "custom" {
            json!({
                "id": self.id,
                "type": "custom",
                "custom": { "name": self.name, "input": self.arguments },
            })
        } else {
            json!({
                "id": self.id,
                "type": "function",
                "function": { "name": self.name, "arguments": self.arguments },
            })
        }
    }
}

fn event(out: &mut String, name: Option<&str>, data: &Value) {
    if let Some(name) = name {
        out.push_str("event: ");
        out.push_str(name);
        out.push('\n');
    }
    out.push_str("data: ");
    out.push_str(&data.to_string());
    out.push_str("\n\n");
}

/// Turn a completion back into a Chat Completions stream. Each choice becomes
/// one chunk with its whole message and one chunk with its finish reason.
pub fn chat_stream(completion: &Value) -> String {
    chat_tail(completion, &Sent::default())
}

/// The rest of a Chat Completions stream, after what `sent` says the agent
/// already received: per choice, the text not sent yet, the tool calls that
/// remain, and the finish reason.
pub fn chat_tail(completion: &Value, sent: &Sent) -> String {
    let chunk = |choices: Value| {
        let mut chunk = json!({ "object": "chat.completion.chunk", "choices": choices });
        for field in HEAD_FIELDS {
            if let Some(value) = completion.get(field) {
                chunk[field] = value.clone();
            }
        }
        chunk
    };

    let mut out = String::new();
    let choices = array(completion, "choices");
    for (position, choice) in choices.iter().enumerate() {
        let message = &choice["message"];
        let choice_index = choice["index"].as_u64().unwrap_or(0);
        let mut delta = json!({});
        // Clients join every field they are sent, so a role sent twice
        // would read "assistantassistant".
        if !sent.role.contains(&choice_index) {
            delta["role"] = json!("assistant");
        }
        if let Some(text) = message["content"].as_str() {
            // Notes about blocked calls only ever go after the model's text,
            // so what was sent is the start of the checked text.
            let already = sent.content.get(&choice_index).map_or("", String::as_str);
            let rest = text.strip_prefix(already).unwrap_or(text);
            if !rest.is_empty() {
                delta["content"] = json!(rest);
            }
        }
        let calls: Vec<Value> = array(message, "tool_calls")
            .iter()
            .enumerate()
            .map(|(index, call)| {
                let mut call = call.clone();
                call["index"] = json!(index);
                call
            })
            .collect();
        if !calls.is_empty() {
            delta["tool_calls"] = json!(calls);
        }
        if message["function_call"].is_object() {
            delta["function_call"] = message["function_call"].clone();
        }

        let index = &choice["index"];
        if delta.as_object().is_some_and(|delta| !delta.is_empty()) {
            event(
                &mut out,
                None,
                &chunk(json!([{ "index": index, "delta": delta, "finish_reason": null }])),
            );
        }

        let mut last = chunk(json!([{
            "index": index,
            "delta": {},
            "finish_reason": choice["finish_reason"],
        }]));
        if position + 1 == choices.len() {
            if let Some(usage) = completion.get("usage") {
                last["usage"] = usage.clone();
            }
        }
        event(&mut out, None, &last);
    }
    out.push_str("data: [DONE]\n\n");
    out
}

/// Turn a response object back into a Responses API stream: a start event,
/// each output item whole, then the final event with the full response.
pub fn responses_stream(final_event: &str, response: &Value) -> String {
    responses_tail(final_event, response, &Sent::default())
}

/// The rest of a Responses API stream, after what `sent` says the agent
/// already received: each output item not finished yet, whole, then the
/// final event with the full checked response.
pub fn responses_tail(final_event: &str, response: &Value, sent: &Sent) -> String {
    let mut out = String::new();
    let mut sequence = sent.sequence.map_or(0, |last| last.saturating_add(1));
    let mut emit = |out: &mut String, name: &str, mut data: Value| {
        data["type"] = json!(name);
        data["sequence_number"] = json!(sequence);
        sequence = sequence.saturating_add(1);
        event(out, Some(name), &data);
    };

    if !sent.started {
        let mut started = response.clone();
        started["status"] = json!("in_progress");
        started["output"] = json!([]);
        emit(&mut out, "response.created", json!({ "response": started }));
    }

    for (index, item) in array(response, "output").iter().enumerate() {
        let position = index as u64;
        if sent.done.contains(&position) {
            continue;
        }
        if !sent.added.contains(&position) {
            emit(
                &mut out,
                "response.output_item.added",
                json!({ "output_index": index, "item": item }),
            );
        }
        emit(
            &mut out,
            "response.output_item.done",
            json!({ "output_index": index, "item": item }),
        );
    }

    emit(&mut out, final_event, json!({ "response": response }));
    out
}

/// An error at the end of a stream whose start already went out, so the
/// status can no longer say it. OpenAI SDKs raise it as an API error.
pub fn stream_error(responses: bool, code: &str, message: &str) -> String {
    let error = json!({ "message": message, "type": "razorwire_error", "code": code });
    let mut out = String::new();
    if responses {
        let data = json!({ "type": "error", "code": code, "message": message, "error": error });
        event(&mut out, Some("error"), &data);
    } else {
        event(&mut out, None, &json!({ "error": error }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openai::{inspect_response, History};
    use crate::policy::Policy;

    const EXAMPLE: &str = include_str!("../policy/example.policy.yaml");

    fn capture(stream: &str) -> Captured {
        let mut capture = StreamCapture::default();
        capture.feed(stream.as_bytes());
        capture.finish()
    }

    /// A stream the way a provider sends it: the tool call's name in one
    /// chunk and its arguments split over the next ones.
    fn drop_stream(databases: &[&str]) -> String {
        let mut out = String::new();
        let chunk = |delta: Value, finish: Value| {
            json!({
                "id": "chatcmpl-1",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "gpt-test",
                "choices": [{ "index": 0, "delta": delta, "finish_reason": finish }],
            })
        };
        event(
            &mut out,
            None,
            &chunk(json!({ "role": "assistant", "content": null }), Value::Null),
        );
        for (index, database) in databases.iter().enumerate() {
            event(
                &mut out,
                None,
                &chunk(
                    json!({ "tool_calls": [{
                        "index": index,
                        "id": format!("call_{database}"),
                        "type": "function",
                        "function": { "name": "db_drop", "arguments": "" },
                    }] }),
                    Value::Null,
                ),
            );
            let arguments = json!({ "database": database }).to_string();
            let (first, second) = arguments.split_at(arguments.len() / 2);
            for piece in [first, second] {
                event(
                    &mut out,
                    None,
                    &chunk(
                        json!({ "tool_calls": [{ "index": index, "function": { "arguments": piece } }] }),
                        Value::Null,
                    ),
                );
            }
        }
        event(&mut out, None, &chunk(json!({}), json!("tool_calls")));
        out.push_str("data: [DONE]\n\n");
        out
    }

    #[test]
    fn events_are_read_across_any_split() {
        let stream = "data: {\"a\":1}\r\n\r\n: comment\nevent: x\ndata: first\ndata: second\n\ndata: [DONE]\n\n";
        let whole = {
            let mut reader = EventReader::default();
            let mut payloads = Vec::new();
            reader.feed(stream.as_bytes(), &mut payloads);
            reader.finish(&mut payloads);
            payloads
        };
        assert_eq!(whole, vec!["{\"a\":1}", "first\nsecond", "[DONE]"]);

        // Feeding one byte at a time must give the same events.
        let mut reader = EventReader::default();
        let mut payloads = Vec::new();
        for byte in stream.as_bytes() {
            reader.feed(&[*byte], &mut payloads);
        }
        reader.finish(&mut payloads);
        assert_eq!(payloads, whole);
    }

    #[test]
    fn an_event_without_a_final_blank_line_is_still_read() {
        let mut reader = EventReader::default();
        let mut payloads = Vec::new();
        reader.feed(b"data: tail", &mut payloads);
        assert!(payloads.is_empty());
        reader.finish(&mut payloads);
        assert_eq!(payloads, vec!["tail"]);
    }

    #[test]
    fn a_tool_call_split_over_chunks_is_reassembled() {
        let Captured::Chat(completion) = capture(&drop_stream(&["staging", "production"])) else {
            panic!("expected a chat stream");
        };

        assert_eq!(completion["id"], "chatcmpl-1");
        assert_eq!(completion["model"], "gpt-test");
        let choice = &completion["choices"][0];
        assert_eq!(choice["finish_reason"], "tool_calls");
        let calls = choice["message"]["tool_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["id"], "call_staging");
        assert_eq!(calls[0]["function"]["name"], "db_drop");
        assert_eq!(
            calls[0]["function"]["arguments"],
            "{\"database\":\"staging\"}"
        );
        assert_eq!(
            calls[1]["function"]["arguments"],
            "{\"database\":\"production\"}"
        );
    }

    #[test]
    fn text_is_joined_and_usage_is_kept() {
        let stream = concat!(
            "data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hel\"}}]}\n\n",
            "data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"total_tokens\":7}}\n\n",
            "data: [DONE]\n\n",
        );
        let Captured::Chat(completion) = capture(stream) else {
            panic!("expected a chat stream");
        };
        assert_eq!(completion["choices"][0]["message"]["content"], "Hello");
        assert_eq!(completion["choices"][0]["finish_reason"], "stop");
        assert_eq!(completion["usage"]["total_tokens"], 7);
        assert!(completion["choices"][0]["message"]
            .get("tool_calls")
            .is_none());
    }

    #[test]
    fn tool_call_fragments_without_an_index_still_join() {
        let stream = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"id\":\"call_a\",\"function\":{\"name\":\"db_drop\",\"arguments\":\"{\\\"database\\\":\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"\\\"production\\\"}\"}}]}}]}\n\n",
        );
        let Captured::Chat(completion) = capture(stream) else {
            panic!("expected a chat stream");
        };
        let calls = completion["choices"][0]["message"]["tool_calls"]
            .as_array()
            .unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0]["function"]["arguments"],
            "{\"database\":\"production\"}"
        );
    }

    #[test]
    fn a_blocked_call_is_gone_from_the_rebuilt_stream() {
        let policy = Policy::parse(EXAMPLE).expect("example policy should parse");
        let Captured::Chat(mut completion) = capture(&drop_stream(&["staging", "production"]))
        else {
            panic!("expected a chat stream");
        };
        let inspection = inspect_response(&mut completion, Some(&policy), "", &History::default());
        assert_eq!(inspection.blocked, 1);

        // Read the rebuilt stream back the way a client would.
        let rebuilt = chat_stream(&completion);
        assert!(rebuilt.ends_with("data: [DONE]\n\n"));
        assert!(!rebuilt.contains("call_production"));
        let Captured::Chat(seen) = capture(&rebuilt) else {
            panic!("the rebuilt stream should be a chat stream");
        };
        let choice = &seen["choices"][0];
        let calls = choice["message"]["tool_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["id"], "call_staging");
        assert_eq!(
            calls[0]["function"]["arguments"],
            "{\"database\":\"staging\"}"
        );
        assert_eq!(choice["finish_reason"], "tool_calls");
        assert!(choice["message"]["content"]
            .as_str()
            .unwrap()
            .contains("[razorwire] Blocked tool call \"db_drop\""));
        assert_eq!(seen["id"], "chatcmpl-1");
    }

    #[test]
    fn a_fully_blocked_stream_ends_as_a_text_answer() {
        let policy = Policy::parse(EXAMPLE).expect("example policy should parse");
        let Captured::Chat(mut completion) = capture(&drop_stream(&["production"])) else {
            panic!("expected a chat stream");
        };
        inspect_response(&mut completion, Some(&policy), "", &History::default());

        let Captured::Chat(seen) = capture(&chat_stream(&completion)) else {
            panic!("the rebuilt stream should be a chat stream");
        };
        let choice = &seen["choices"][0];
        assert!(choice["message"].get("tool_calls").is_none());
        assert_eq!(choice["finish_reason"], "stop");
    }

    #[test]
    fn a_responses_stream_is_read_from_its_final_event() {
        let response = json!({
            "id": "resp_1",
            "object": "response",
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": "call_1",
                "name": "db_drop",
                "arguments": "{\"database\":\"production\"}"
            }]
        });
        let mut stream = String::new();
        event(
            &mut stream,
            Some("response.created"),
            &json!({ "type": "response.created", "response": { "id": "resp_1" } }),
        );
        event(
            &mut stream,
            Some("response.completed"),
            &json!({ "type": "response.completed", "response": response }),
        );

        let Captured::Responses {
            event: name,
            response: mut seen,
        } = capture(&stream)
        else {
            panic!("expected a responses stream");
        };
        assert_eq!(name, "response.completed");
        assert_eq!(seen, response);

        let policy = Policy::parse(EXAMPLE).expect("example policy should parse");
        let inspection = inspect_response(&mut seen, Some(&policy), "", &History::default());
        assert_eq!(inspection.blocked, 1);

        let rebuilt = responses_stream(&name, &seen);
        assert!(!rebuilt.contains("function_call"));
        let Captured::Responses {
            response: again, ..
        } = capture(&rebuilt)
        else {
            panic!("the rebuilt stream should be a responses stream");
        };
        assert_eq!(again["output"][0]["type"], "message");
        assert!(rebuilt.starts_with("event: response.created\n"));
    }

    #[test]
    fn streams_that_cannot_be_checked_are_reported() {
        assert!(matches!(
            capture("data: {not json}\n\n"),
            Captured::Unreadable(_)
        ));
        // A Responses stream that stops before its final event.
        assert!(matches!(
            capture("data: {\"type\":\"response.created\",\"response\":{}}\n\n"),
            Captured::Unreadable(_)
        ));
    }

    /// Run a whole stream through the live gate, in pieces of `step` bytes.
    fn gate(stream: &str, step: usize) -> (String, Captured, String, Sent) {
        let mut gate = LiveGate::default();
        let mut live = Vec::new();
        for piece in stream.as_bytes().chunks(step.max(1)) {
            live.extend(gate.feed(piece));
        }
        let (captured, held, sent) = gate.finish();
        (
            String::from_utf8(live).unwrap(),
            captured,
            String::from_utf8(held).unwrap(),
            sent,
        )
    }

    fn chat_chunk(delta: Value, finish: Value) -> Value {
        json!({
            "id": "chatcmpl-1",
            "object": "chat.completion.chunk",
            "model": "gpt-test",
            "choices": [{ "index": 0, "delta": delta, "finish_reason": finish, "logprobs": null }],
        })
    }

    /// The model thinks out loud, then asks to drop two databases.
    fn talk_then_drop() -> String {
        let mut out = String::new();
        event(
            &mut out,
            None,
            &chat_chunk(json!({ "role": "assistant", "content": "" }), Value::Null),
        );
        for word in ["Dropping ", "both ", "now."] {
            event(
                &mut out,
                None,
                &chat_chunk(json!({ "content": word }), Value::Null),
            );
        }
        out.push_str(": keep-alive\n\n");
        let rest = drop_stream(&["staging", "production"]);
        // Skip the role chunk drop_stream starts with.
        let tool_part = rest.split_once("\n\n").unwrap().1;
        out.push_str(tool_part);
        out
    }

    #[test]
    fn text_goes_out_live_and_tool_calls_wait() {
        for step in [1, 7, 4096] {
            let (live, captured, held, sent) = gate(&talk_then_drop(), step);
            assert!(live.contains("Dropping "), "{live}");
            assert!(live.contains(": keep-alive"), "comments pass through");
            assert!(
                !live.contains("db_drop"),
                "a tool call went out live: {live}"
            );
            assert!(!live.contains("tool_calls"), "{live}");
            assert!(!live.contains("[DONE]"));
            assert!(held.starts_with("data: "), "{held}");
            assert!(held.contains("call_production") && held.ends_with("data: [DONE]\n\n"));
            assert_eq!(sent.content[&0], "Dropping both now.");
            assert!(sent.role.contains(&0));
            // Live and held together are exactly the original stream.
            assert_eq!(format!("{live}{held}"), talk_then_drop());
            let Captured::Chat(completion) = captured else {
                panic!("expected a chat stream");
            };
            assert_eq!(
                completion["choices"][0]["message"]["content"],
                "Dropping both now."
            );
        }
    }

    #[test]
    fn the_rebuilt_end_follows_on_from_the_live_start() {
        let policy = Policy::parse(EXAMPLE).expect("example policy should parse");
        let (live, captured, _held, sent) = gate(&talk_then_drop(), 5);
        let Captured::Chat(mut completion) = captured else {
            panic!("expected a chat stream");
        };
        let inspection = inspect_response(&mut completion, Some(&policy), "", &History::default());
        assert_eq!(inspection.blocked, 1);

        let tail = chat_tail(&completion, &sent);
        assert!(!tail.contains("call_production"));
        assert!(
            !tail.contains("\"role\""),
            "the role was already sent: {tail}"
        );
        assert!(
            !tail.contains("Dropping both"),
            "text already sent is not repeated: {tail}"
        );

        // What the agent ends up with, read the way a client reads it.
        let Captured::Chat(seen) = capture(&format!("{live}{tail}")) else {
            panic!("expected a chat stream");
        };
        let message = &seen["choices"][0]["message"];
        let content = message["content"].as_str().unwrap();
        assert!(
            content.starts_with("Dropping both now.\n\n[razorwire] Blocked tool call \"db_drop\""),
            "{content}"
        );
        let calls = message["tool_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["id"], "call_staging");
        assert_eq!(
            calls[0]["function"]["arguments"],
            "{\"database\":\"staging\"}"
        );
        assert_eq!(seen["choices"][0]["finish_reason"], "tool_calls");
    }

    #[test]
    fn anything_unknown_holds_the_rest_of_the_stream() {
        let unknown_delta = chat_chunk(
            json!({ "content": "a", "audio": { "id": "x" } }),
            Value::Null,
        );
        let unknown_choice_field =
            json!({ "choices": [{ "index": 0, "delta": { "content": "a" }, "message": {} }] });
        let finished = chat_chunk(json!({ "content": "a" }), json!("stop"));
        let not_json = json!("garbage");
        for first in [unknown_delta, unknown_choice_field, finished, not_json] {
            let mut stream = String::new();
            let payload = match &first {
                Value::String(text) => format!("data: {text}\n\n"),
                other => format!("data: {other}\n\n"),
            };
            stream.push_str(&payload);
            event(
                &mut stream,
                None,
                &chat_chunk(json!({ "content": "after" }), Value::Null),
            );
            let (live, _, held, _) = gate(&stream, 3);
            assert!(live.is_empty(), "{first}: {live}");
            assert_eq!(held, stream);
        }

        // Fields set to null carry nothing and do not stop the stream.
        let nulls = chat_chunk(
            json!({ "content": "hi", "tool_calls": null, "function_call": null }),
            Value::Null,
        );
        let mut stream = String::new();
        event(&mut stream, None, &nulls);
        let (live, _, held, _) = gate(&stream, 64);
        assert_eq!(live, stream);
        assert!(held.is_empty());
    }

    #[test]
    fn an_unfinished_last_event_is_held_and_read() {
        let stream =
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\ndata: {not json";
        let (live, captured, held, _) = gate(stream, 9);
        assert!(live.contains("\"hi\""));
        assert_eq!(held, "data: {not json");
        assert!(matches!(captured, Captured::Unreadable(_)));
    }

    #[test]
    fn a_responses_stream_sends_text_live_and_holds_the_call() {
        let message = json!({
            "type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
            "content": [{ "type": "output_text", "text": "On it.", "annotations": [] }],
        });
        let call = json!({
            "type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "db_drop",
            "arguments": "{\"database\":\"production\"}",
        });
        let response = json!({
            "id": "resp_1", "object": "response", "status": "completed", "model": "gpt-test",
            "output": [message, call],
        });
        let mut sequence = 0;
        let mut stream = String::new();
        let mut emit = |name: &str, mut data: Value| {
            data["type"] = json!(name);
            data["sequence_number"] = json!(sequence);
            sequence += 1;
            event(&mut stream, Some(name), &data);
        };
        emit(
            "response.created",
            json!({ "response": { "id": "resp_1", "status": "in_progress", "output": [] } }),
        );
        emit(
            "response.output_item.added",
            json!({ "output_index": 0, "item": { "type": "message", "id": "msg_1", "content": [] } }),
        );
        emit(
            "response.output_text.delta",
            json!({ "output_index": 0, "content_index": 0, "delta": "On it." }),
        );
        emit(
            "response.output_item.done",
            json!({ "output_index": 0, "item": message }),
        );
        emit(
            "response.output_item.added",
            json!({ "output_index": 1, "item": { "type": "function_call", "name": "db_drop", "arguments": "" } }),
        );
        emit(
            "response.function_call_arguments.delta",
            json!({ "output_index": 1, "delta": "{\"database\":\"production\"}" }),
        );
        emit(
            "response.output_item.done",
            json!({ "output_index": 1, "item": call }),
        );
        emit("response.completed", json!({ "response": response }));

        let (live, captured, held, sent) = gate(&stream, 11);
        assert!(live.contains("On it."));
        assert!(!live.contains("db_drop"), "{live}");
        assert!(held.starts_with("event: response.output_item.added\n"));
        assert!(sent.started && sent.done.contains(&0) && !sent.added.contains(&1));
        assert_eq!(sent.sequence, Some(3));

        let Captured::Responses {
            event: name,
            response: mut checked,
        } = captured
        else {
            panic!("expected a responses stream");
        };
        let policy = Policy::parse(EXAMPLE).expect("example policy should parse");
        assert_eq!(
            inspect_response(&mut checked, Some(&policy), "", &History::default()).blocked,
            1
        );
        let tail = responses_tail(&name, &checked, &sent);
        assert!(
            !tail.contains("response.created"),
            "the start was already sent"
        );
        assert!(!tail.contains("\"function_call\""));
        assert!(tail.contains("\"sequence_number\":4"), "{tail}");
        assert!(
            !tail.contains("\"output_index\":0"),
            "item 0 was already finished: {tail}"
        );

        let Captured::Responses { response: seen, .. } = capture(&format!("{live}{tail}")) else {
            panic!("expected a responses stream");
        };
        assert_eq!(seen["output"][0]["type"], "message");
        assert_eq!(seen["output"][1]["type"], "message");
        assert!(seen["output"][1]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Blocked tool call"));
    }

    #[test]
    fn stream_errors_are_raised_by_sdks() {
        let chat = stream_error(false, "response_not_inspectable", "nope");
        let payload: Value =
            serde_json::from_str(chat.strip_prefix("data: ").unwrap().trim()).unwrap();
        assert_eq!(payload["error"]["code"], "response_not_inspectable");
        let responses = stream_error(true, "response_not_inspectable", "nope");
        assert!(responses.starts_with("event: error\ndata: "));
        assert!(responses.contains("\"type\":\"error\"") && responses.contains("\"error\":{"));
    }

    #[test]
    fn streams_with_no_tool_call_shape_are_left_alone() {
        assert!(matches!(capture(""), Captured::Nothing));
        assert!(matches!(capture("data: [DONE]\n\n"), Captured::Nothing));
        // Legacy text completions cannot carry tool calls.
        assert!(matches!(
            capture("data: {\"object\":\"text_completion\",\"choices\":[{\"text\":\"hi\"}]}\n\n"),
            Captured::Nothing
        ));
    }
}
