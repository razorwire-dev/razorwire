//! Streamed provider responses (server-sent events).
//!
//! A streamed reply arrives as many small events, and a tool call is spread
//! across them: the name in one, the arguments in pieces over several more.
//! `StreamCapture` reassembles the events into the same shape a non-streamed
//! reply has, so the same policy check applies. `chat_stream` and
//! `responses_stream` turn a rewritten reply back into a stream.

use std::collections::BTreeMap;

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
        let mut delta = json!({ "role": "assistant" });
        if let Some(text) = message["content"].as_str().filter(|text| !text.is_empty()) {
            delta["content"] = json!(text);
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
        event(
            &mut out,
            None,
            &chunk(json!([{ "index": index, "delta": delta, "finish_reason": null }])),
        );

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
    let mut out = String::new();
    let mut sequence = 0u64;
    let mut emit = |out: &mut String, name: &str, mut data: Value| {
        data["type"] = json!(name);
        data["sequence_number"] = json!(sequence);
        sequence += 1;
        event(out, Some(name), &data);
    };

    let mut started = response.clone();
    started["status"] = json!("in_progress");
    started["output"] = json!([]);
    emit(&mut out, "response.created", json!({ "response": started }));

    for (index, item) in array(response, "output").iter().enumerate() {
        emit(
            &mut out,
            "response.output_item.added",
            json!({ "output_index": index, "item": item }),
        );
        emit(
            &mut out,
            "response.output_item.done",
            json!({ "output_index": index, "item": item }),
        );
    }

    emit(&mut out, final_event, json!({ "response": response }));
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
