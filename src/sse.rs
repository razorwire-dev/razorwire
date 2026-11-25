//! Streamed provider responses (server-sent events).
//!
//! A streamed reply arrives as many small events, and a tool call is spread
//! across them: the name in one, the arguments in pieces over several more.
//! `StreamCapture` reassembles the events into the same shape a non-streamed
//! reply has, so the same policy check applies.
//!
//! `LiveGate` lets the start of a reply through as it arrives, as long as it
//! is only text, and holds everything back from the first event that could
//! carry a tool call. `chat_tail` and `responses_tail` rebuild the held part
//! from the checked reply, to fit after what the agent already received.
//!
//! The agent never gets the provider's own bytes under an enforced policy.
//! Each event is read the way clients read it, checked, and written out
//! again from what was read, so no client can find in it something the
//! check did not see.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use crate::openai::array;

/// Splits bytes into lines the way the server-sent events spec does: a line
/// ends at CRLF, at LF, or at a lone CR. Clients split the same way (the
/// OpenAI SDKs do), so a lone CR cannot hide a line from the check.
#[derive(Default)]
struct Lines {
    /// Bytes after the last complete line.
    pending: Vec<u8>,
    /// The last line ended with CR, so an LF right after it belongs to it.
    after_cr: bool,
}

impl Lines {
    fn feed(&mut self, bytes: &[u8], lines: &mut Vec<Vec<u8>>) {
        let mut start = 0;
        for (index, &byte) in bytes.iter().enumerate() {
            if byte != b'\n' && byte != b'\r' {
                continue;
            }
            if byte == b'\n' && self.after_cr && index == start && self.pending.is_empty() {
                // The LF of a CRLF, perhaps in the next piece of the stream.
                self.after_cr = false;
                start = index + 1;
                continue;
            }
            self.pending.extend_from_slice(&bytes[start..index]);
            lines.push(std::mem::take(&mut self.pending));
            self.after_cr = byte == b'\r';
            start = index + 1;
        }
        if start < bytes.len() {
            self.after_cr = false;
            self.pending.extend_from_slice(&bytes[start..]);
        }
    }

    /// The last line, when the stream ends without a line break.
    fn finish(&mut self) -> Option<Vec<u8>> {
        self.after_cr = false;
        (!self.pending.is_empty()).then(|| std::mem::take(&mut self.pending))
    }
}

/// One event, as a client reads it.
#[derive(Debug, PartialEq)]
struct SseEvent {
    /// The `event:` field.
    name: Option<String>,
    /// The `data:` lines, joined with LF. `None` for an event without data,
    /// such as a comment that keeps the connection open.
    data: Option<String>,
}

/// Reads the events of a stream, following the spec's rules for lines and
/// fields, as clients do.
#[derive(Default)]
struct EventReader {
    lines: Lines,
    /// `event:` of the event being read.
    name: Option<String>,
    /// `data:` lines of the event being read.
    data: Vec<String>,
    /// A line of the event being read has arrived.
    started: bool,
}

impl EventReader {
    fn feed(&mut self, bytes: &[u8], events: &mut Vec<SseEvent>) {
        let mut lines = Vec::new();
        self.lines.feed(bytes, &mut lines);
        for line in lines {
            self.line(&line, events);
        }
    }

    fn line(&mut self, line: &[u8], events: &mut Vec<SseEvent>) {
        if line.is_empty() {
            // A blank line ends the event.
            self.dispatch(events);
            return;
        }
        self.started = true;
        if line.starts_with(b":") {
            return; // a comment
        }
        // `field: value`, or a line without a colon, which is a field with
        // an empty value.
        let (field, value) = match line.iter().position(|&byte| byte == b':') {
            Some(colon) => {
                let value = &line[colon + 1..];
                (&line[..colon], value.strip_prefix(b" ").unwrap_or(value))
            }
            None => (line, &[][..]),
        };
        match field {
            b"data" => self.data.push(String::from_utf8_lossy(value).into_owned()),
            b"event" => self.name = Some(String::from_utf8_lossy(value).into_owned()),
            // `id`, `retry` and unknown fields carry nothing used here, and
            // are never passed on.
            _ => {}
        }
    }

    fn dispatch(&mut self, events: &mut Vec<SseEvent>) {
        let name = self.name.take();
        if !std::mem::take(&mut self.started) {
            return;
        }
        let data = (!self.data.is_empty()).then(|| self.data.join("\n"));
        self.data.clear();
        events.push(SseEvent { name, data });
    }

    /// Read whatever is left when the stream ends without a final blank
    /// line. The check sees such an event, so it is read like any other.
    fn finish(&mut self, events: &mut Vec<SseEvent>) {
        if let Some(line) = self.lines.finish() {
            self.line(&line, events);
        }
        self.dispatch(events);
    }
}

/// The data of one event, read once for every check.
#[derive(Debug)]
enum Payload {
    /// `[DONE]`, the end of a Chat Completions stream.
    Done,
    /// Only whitespace.
    Blank,
    Json(Value),
    /// Not JSON. A stream with one cannot be checked.
    Invalid,
}

impl Payload {
    fn read(data: &str) -> Payload {
        let data = data.trim();
        if data.is_empty() {
            Payload::Blank
        } else if data == "[DONE]" {
            Payload::Done
        } else {
            serde_json::from_str(data).map_or(Payload::Invalid, Payload::Json)
        }
    }
}

/// Write one event for the agent, rebuilt from what was read: compact JSON
/// on a single `data:` line, so every client reads exactly what was checked.
fn render(name: Option<&str>, payload: Option<&Payload>, out: &mut Vec<u8>) {
    match payload {
        // A comment, or an event without data: it becomes a bare comment,
        // which keeps an idle connection open and carries nothing.
        None => out.extend_from_slice(b":\n\n"),
        Some(Payload::Done) => out.extend_from_slice(b"data: [DONE]\n\n"),
        Some(Payload::Json(value)) => {
            let mut text = String::new();
            event(&mut text, event_name(name, value), value);
            out.extend_from_slice(text.as_bytes());
        }
        // Nothing to send. A stream with data that is not JSON is refused.
        Some(Payload::Blank | Payload::Invalid) => {}
    }
}

/// The `event:` name sent with an event. A Responses API event is named by
/// its `type`, which is what was checked, and a Chat Completions chunk has
/// no name. Anything else keeps the provider's name. Only plain names are
/// sent, so a name can never add a line or a field.
fn event_name<'a>(name: Option<&'a str>, value: &'a Value) -> Option<&'a str> {
    let chosen = match value.get("type").and_then(Value::as_str) {
        Some(kind) if kind.starts_with("response.") => Some(kind),
        _ if value.get("choices").is_some() => None,
        _ => name,
    };
    chosen.filter(|name| {
        !name.is_empty() && name.len() <= 256 && name.bytes().all(|byte| byte.is_ascii_graphic())
    })
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
    /// A Chat Completions stream that the provider ended with an error
    /// event. The agent gets the error and none of the reply's tool calls.
    ProviderError(Value),
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
    /// The first error event of a stream that is not a Responses stream.
    error: Option<Value>,
    malformed: bool,
}

impl StreamCapture {
    pub fn feed(&mut self, bytes: &[u8]) {
        let mut events = Vec::new();
        self.reader.feed(bytes, &mut events);
        self.read(&events);
    }

    pub fn finish(mut self) -> Captured {
        let mut events = Vec::new();
        self.reader.finish(&mut events);
        self.read(&events);
        self.result()
    }

    fn read(&mut self, events: &[SseEvent]) {
        for data in events.iter().filter_map(|event| event.data.as_deref()) {
            self.payload(&Payload::read(data));
        }
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
        if let Some(error) = self.error {
            return Captured::ProviderError(error);
        }
        if self.saw_chat {
            return Captured::Chat(self.chat.into_completion());
        }
        Captured::Nothing
    }

    fn payload(&mut self, payload: &Payload) {
        let event = match payload {
            Payload::Done | Payload::Blank => return,
            Payload::Invalid => {
                self.malformed = true;
                return;
            }
            Payload::Json(event) => event,
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
            || array(event, "choices")
                .iter()
                .any(|choice| choice.get("delta").is_some())
        {
            self.saw_chat = true;
            self.chat.add(event);
        } else if event.get("error").is_some_and(|error| !error.is_null()) && self.error.is_none() {
            // How Chat Completions providers report a failure mid-stream.
            self.error = Some(event.clone());
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
    fn admit(&mut self, payload: &Payload) -> bool {
        let Payload::Json(event) = payload else {
            return false; // `[DONE]` too: it ends the stream, so it waits
        };
        match event.get("type") {
            None => self.admit_chat(event),
            Some(kind) => match kind.as_str() {
                Some(kind) if kind.starts_with("response.") => self.admit_response(kind, event),
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
/// Every event that goes out is rebuilt from what was read, never the
/// provider's own bytes.
#[derive(Default)]
pub struct LiveGate {
    reader: EventReader,
    capture: StreamCapture,
    /// Set at the first event that cannot go out live. Never unset.
    holding: bool,
    /// The held events, rebuilt. Sent only when the stream turns out to
    /// hold nothing a policy judges; otherwise the held part is rebuilt
    /// from the checked reply instead.
    held: Vec<u8>,
    sent: Sent,
}

impl LiveGate {
    /// Read bytes from the provider. Returns the bytes the agent may have now.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut events = Vec::new();
        self.reader.feed(bytes, &mut events);
        let mut out = Vec::new();
        for event in &events {
            self.event(event, &mut out);
        }
        out
    }

    /// Whether the stream is a Responses API stream, as far as it was read.
    pub fn is_responses(&self) -> bool {
        self.capture.saw_responses
    }

    fn event(&mut self, event: &SseEvent, out: &mut Vec<u8>) {
        let payload = event.data.as_deref().map(Payload::read);
        if let Some(payload) = &payload {
            self.capture.payload(payload);
            if !self.holding && !self.sent.admit(payload) {
                self.holding = true;
            }
        }
        // Events without data carry nothing and go out at once, unless the
        // stream is already being held, which keeps the order.
        let target = if self.holding { &mut self.held } else { out };
        render(event.name.as_deref(), payload.as_ref(), target);
    }

    /// The stream has ended. Returns the reassembled reply, the held events
    /// (rebuilt), and what the agent already received.
    pub fn finish(mut self) -> (Captured, Vec<u8>, Sent) {
        // An event that ends without its blank line is still read, and held.
        self.holding = true;
        let mut events = Vec::new();
        self.reader.finish(&mut events);
        let mut ignored = Vec::new();
        for event in &events {
            self.event(event, &mut ignored);
        }
        (self.capture.result(), self.held, self.sent)
    }
}

/// A provider's error event, for the agent. OpenAI SDKs raise it.
pub fn provider_error(error: &Value) -> String {
    let mut out = String::new();
    event(&mut out, None, error);
    out
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

    /// A whole Chat Completions stream for a completion: each choice as one
    /// chunk with its whole message and one with its finish reason.
    fn chat_stream(completion: &Value) -> String {
        chat_tail(completion, &Sent::default())
    }

    /// A whole Responses API stream for a response: a start event, each
    /// output item whole, then the final event.
    fn responses_stream(final_event: &str, response: &Value) -> String {
        responses_tail(final_event, response, &Sent::default())
    }

    fn read_events(pieces: &[&[u8]]) -> Vec<SseEvent> {
        let mut reader = EventReader::default();
        let mut events = Vec::new();
        for piece in pieces {
            reader.feed(piece, &mut events);
        }
        reader.finish(&mut events);
        events
    }

    fn data_event(name: Option<&str>, data: &str) -> SseEvent {
        SseEvent {
            name: name.map(str::to_string),
            data: Some(data.to_string()),
        }
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
        let stream: &[u8] =
            b"data: {\"a\":1}\r\n\r\n: comment\nevent: x\ndata: first\ndata: second\n\n\
            data: [DONE]\r\rdata\n\n";
        let whole = read_events(&[stream]);
        assert_eq!(
            whole,
            vec![
                data_event(None, "{\"a\":1}"),
                data_event(Some("x"), "first\nsecond"),
                data_event(None, "[DONE]"),
                // A line with no colon is a field with an empty value.
                data_event(None, ""),
            ]
        );

        // Feeding one byte at a time must give the same events, including a
        // CRLF split between two pieces.
        let bytes: Vec<&[u8]> = stream.chunks(1).collect();
        assert_eq!(read_events(&bytes), whole);
    }

    #[test]
    fn a_lone_cr_ends_a_line_as_it_does_for_clients() {
        // Read with LF as the only line end, this is one comment. Clients
        // (the OpenAI SDKs follow the spec) see a comment and then a data
        // line, so the check must see that data line too.
        let events = read_events(&[b": hidden\rdata: {\"b\":2}\n\n"]);
        assert_eq!(events, vec![data_event(None, "{\"b\":2}")]);

        // CR CR is a line end and a blank line: two events.
        let events = read_events(&[b"data: 1\r\rdata: 2\r\r"]);
        assert_eq!(events, vec![data_event(None, "1"), data_event(None, "2")]);
    }

    #[test]
    fn comments_and_events_without_data_are_kept_as_keep_alives() {
        let events = read_events(&[b": ping\n\nid: 7\n\n\n\n"]);
        let keep_alive = SseEvent {
            name: None,
            data: None,
        };
        // Two events: the comment and the `id`. The extra blank lines carry
        // nothing and make no event.
        assert_eq!(
            events,
            vec![
                keep_alive,
                SseEvent {
                    name: None,
                    data: None
                }
            ]
        );
    }

    #[test]
    fn an_event_without_a_final_blank_line_is_still_read() {
        let mut reader = EventReader::default();
        let mut events = Vec::new();
        reader.feed(b"data: tail", &mut events);
        assert!(events.is_empty());
        reader.finish(&mut events);
        assert_eq!(events, vec![data_event(None, "tail")]);
    }

    #[test]
    fn a_tool_call_behind_a_lone_cr_is_checked() {
        let policy = Policy::parse(EXAMPLE).expect("example policy should parse");
        let call = chat_chunk(
            json!({ "tool_calls": [{
                "index": 0, "id": "call_1", "type": "function",
                "function": { "name": "db_drop", "arguments": "{\"database\":\"production\"}" },
            }] }),
            Value::Null,
        );
        let mut stream = String::new();
        event(
            &mut stream,
            None,
            &chat_chunk(json!({ "content": "Hi." }), Value::Null),
        );
        stream.push_str(&format!(": nothing to see\rdata: {call}\n\n"));
        event(
            &mut stream,
            None,
            &chat_chunk(json!({}), json!("tool_calls")),
        );
        stream.push_str("data: [DONE]\n\n");

        for step in [1, 5, 4096] {
            let (live, captured, _held, sent) = gate(&stream, step);
            assert!(live.contains("Hi."), "{live}");
            assert!(
                !live.contains("db_drop"),
                "the call went out unchecked: {live}"
            );
            let Captured::Chat(mut completion) = captured else {
                panic!("expected a chat stream");
            };
            assert_eq!(
                completion["choices"][0]["message"]["tool_calls"][0]["function"]["name"],
                "db_drop"
            );
            let inspection =
                inspect_response(&mut completion, Some(&policy), "", &History::default());
            assert_eq!(inspection.blocked, 1);
            let tail = chat_tail(&completion, &sent);
            assert!(!tail.contains("db_drop\""), "{tail}");
        }
    }

    #[test]
    fn the_agent_gets_what_was_checked_not_the_providers_bytes() {
        // A key given twice: serde_json keeps the last one, and a client that
        // kept the first would see a tool call. The agent gets the event
        // written out again, with the one value that was checked.
        let twice = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\",\
            \"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"db_drop\"}}],\"tool_calls\":null}}]}\n\n";
        let (live, _, held, _) = gate(twice, 3);
        assert!(held.is_empty());
        assert!(!live.contains("db_drop"), "{live}");
        assert_eq!(
            only_data(&live),
            json!({ "choices": [{ "index": 0, "delta": { "content": "hi", "tool_calls": null } }] })
        );

        // Extra spaces, a CRLF and an `id` go too: one compact `data:` line.
        let loose = "id: 9\r\ndata:   {\"choices\" : [ {\"index\":0, \"delta\":{\"content\":\"x\"}} ] }\r\n\r\n";
        let (live, _, _, _) = gate(loose, 2);
        assert!(!live.contains("id:") && !live.contains('\r'), "{live}");
        assert_eq!(
            only_data(&live),
            json!({ "choices": [{ "index": 0, "delta": { "content": "x" } }] })
        );
    }

    /// The value of a stream that is exactly one compact `data:` event.
    fn only_data(stream: &str) -> Value {
        let line = stream
            .strip_prefix("data: ")
            .and_then(|rest| rest.strip_suffix("\n\n"))
            .unwrap_or_else(|| panic!("not one data event: {stream:?}"));
        assert!(!line.contains('\n'), "{stream:?}");
        assert!(
            !line.contains(": ") && !line.contains(", "),
            "not compact: {line}"
        );
        serde_json::from_str(line).unwrap()
    }

    #[test]
    fn event_names_come_from_what_was_checked() {
        // A Responses event is named by its checked `type`, whatever name
        // the provider gave it.
        let delta = "event: thread.run.created\ndata: {\"type\":\"response.output_text.delta\",\
            \"delta\":\"a\",\"output_index\":0}\n\n";
        let (live, _, _, _) = gate(delta, 4);
        assert!(
            live.starts_with("event: response.output_text.delta\ndata: "),
            "{live}"
        );

        // A name that is not plain is dropped rather than sent.
        let value = json!({ "type": "response.created\ndata: {}", "response": {} });
        let mut out = Vec::new();
        render(Some("x"), Some(&Payload::Json(value)), &mut out);
        let out = String::from_utf8(out).unwrap();
        assert!(out.starts_with("data: "), "{out}");
        assert_eq!(out.matches('\n').count(), 2, "{out}");

        // A chat chunk has no name; other events keep a plain one.
        assert_eq!(event_name(Some("x"), &json!({ "choices": [] })), None);
        assert_eq!(
            event_name(Some("error"), &json!({ "type": "error" })),
            Some("error")
        );
        assert_eq!(event_name(Some("bad name"), &json!({})), None);
    }

    #[test]
    fn a_provider_error_ends_a_chat_stream_without_its_calls() {
        let mut stream = drop_stream(&["staging"]);
        stream = stream.replace(
            "data: [DONE]\n\n",
            "data: {\"error\":{\"message\":\"overloaded\",\"type\":\"server_error\"}}\n\n",
        );
        let Captured::ProviderError(error) = capture(&stream) else {
            panic!("expected the provider's error");
        };
        assert_eq!(error["error"]["message"], "overloaded");
        let sent = provider_error(&error);
        assert!(sent.starts_with("data: {\"error\":"), "{sent}");
        assert!(!sent.contains("db_drop"));
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
            assert!(live.contains("\n\n:\n\n"), "comments pass as bare comments");
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
            // Live and held together are the original stream, rebuilt: the
            // test stream is already compact, and the comment is bare.
            assert_eq!(
                format!("{live}{held}"),
                talk_then_drop().replace(": keep-alive\n\n", ":\n\n")
            );
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
            let mut after = String::new();
            event(
                &mut after,
                None,
                &chat_chunk(json!({ "content": "after" }), Value::Null),
            );
            let payload = match &first {
                Value::String(text) => format!("data: {text}\n\n"),
                other => format!("data: {other}\n\n"),
            };
            let stream = format!("{payload}{after}");
            let (live, captured, held, _) = gate(&stream, 3);
            assert!(live.is_empty(), "{first}: {live}");
            if first.is_string() {
                // Data that is not JSON is never sent, and the stream cannot
                // be checked.
                assert_eq!(held, after);
                assert!(matches!(captured, Captured::Unreadable(_)));
            } else {
                assert_eq!(held, stream);
            }
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
        assert!(held.is_empty(), "{held}");
        assert!(matches!(captured, Captured::Unreadable(_)));

        // A complete one is read and held like any other.
        let stream = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"},\"finish_reason\":\"stop\"}]}";
        let (live, captured, held, _) = gate(stream, 9);
        assert!(live.is_empty());
        assert!(held.contains("\"stop\""), "{held}");
        assert!(matches!(captured, Captured::Chat(_)));
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
