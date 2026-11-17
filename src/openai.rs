//! Reading and rewriting OpenAI-compatible payloads.
//!
//! The model's tool calls arrive in the provider's response. Blocking a call
//! means removing it from that response before the agent sees it, so the
//! agent never has anything to execute.

use serde_json::{json, Value};

use crate::policy::{Action, Decision, Mode, Policy};

/// Result of inspecting one provider response.
pub struct Inspection {
    /// One audit event per tool call found.
    pub events: Vec<Value>,
    /// How many tool calls were removed from the response.
    pub blocked: usize,
}

/// Find every tool call in a provider response, record it, and remove the
/// ones the policy blocks. Handles the Chat Completions and Responses API
/// shapes. With no policy, calls are only recorded.
pub fn inspect_response(response: &mut Value, policy: Option<&Policy>, agent: &str) -> Inspection {
    let mut judge = Judge {
        policy,
        agent,
        model: response["model"].clone(),
        events: Vec::new(),
        blocked: 0,
    };
    inspect_chat_completion(response, &mut judge);
    inspect_responses_api(response, &mut judge);
    Inspection {
        events: judge.events,
        blocked: judge.blocked,
    }
}

struct Judge<'a> {
    policy: Option<&'a Policy>,
    agent: &'a str,
    model: Value,
    events: Vec<Value>,
    blocked: usize,
}

impl Judge<'_> {
    /// Record one tool call. Returns the note to show the agent when the call
    /// must be removed, or `None` when it may go through.
    fn judge(
        &mut self,
        api: &str,
        call_id: &Value,
        tool: Option<&str>,
        arguments: &Value,
    ) -> Option<String> {
        let mut event = json!({
            "event": "tool_call",
            "api": api,
            "model": self.model,
            "call_id": call_id,
            "tool": tool,
            "arguments": arguments,
        });
        if !self.agent.is_empty() {
            event["agent"] = json!(self.agent);
        }

        let Some(policy) = self.policy else {
            self.events.push(event);
            return None;
        };

        let decision = match tool {
            Some(name) => policy.decide(self.agent, name, arguments),
            // A call that cannot be named cannot be matched to a rule.
            None => Decision {
                action: Action::Deny,
                rule: None,
                message: "The tool call has no name, so it cannot be checked against the policy."
                    .to_string(),
                error: None,
            },
        };
        let blocked = !decision.is_allowed() && policy.mode() == Mode::Enforce;

        event["decision"] = json!(decision.action.as_str());
        event["rule"] = json!(decision.rule);
        event["blocked"] = json!(blocked);
        if !decision.is_allowed() {
            event["reason"] = json!(decision.message);
        }
        if let Some(error) = &decision.error {
            event["error"] = json!(error);
        }
        self.events.push(event);

        if !blocked {
            return None;
        }
        self.blocked += 1;
        let source = match &decision.rule {
            Some(rule) => format!("rule: {rule}"),
            None => "default policy".to_string(),
        };
        Some(format!(
            "[razorwire] Blocked tool call \"{}\": {} ({source})",
            tool.unwrap_or("unnamed"),
            decision.message
        ))
    }
}

fn inspect_chat_completion(response: &mut Value, judge: &mut Judge) {
    let Some(choices) = response.get_mut("choices").and_then(Value::as_array_mut) else {
        return;
    };

    for choice in choices {
        let mut notes = Vec::new();
        let mut calls_remain = false;

        if let Some(message) = choice.get_mut("message").and_then(Value::as_object_mut) {
            let mut tool_calls_remain = false;
            if let Some(Value::Array(calls)) = message.get_mut("tool_calls") {
                for call in std::mem::take(calls) {
                    let (tool, arguments) = chat_call_parts(&call);
                    let note =
                        judge.judge("chat.completions", &call["id"], tool.as_deref(), &arguments);
                    match note {
                        Some(note) => notes.push(note),
                        None => calls.push(call),
                    }
                }
                tool_calls_remain = !calls.is_empty();
            }

            // `function_call` is the older, single-call form of `tool_calls`.
            let legacy = message
                .get("function_call")
                .filter(|call| call.is_object())
                .map(|call| (named(&call["name"]), parse_arguments(&call["arguments"])));
            let mut function_call_remains = false;
            if let Some((tool, arguments)) = legacy {
                let note = judge.judge(
                    "chat.completions",
                    &Value::Null,
                    tool.as_deref(),
                    &arguments,
                );
                match note {
                    Some(note) => {
                        notes.push(note);
                        message.remove("function_call");
                    }
                    None => function_call_remains = true,
                }
            }

            if !notes.is_empty() {
                if !tool_calls_remain {
                    message.remove("tool_calls");
                }
                let said = message.get("content").and_then(Value::as_str).unwrap_or("");
                let content = if said.is_empty() {
                    notes.join("\n")
                } else {
                    format!("{said}\n\n{}", notes.join("\n"))
                };
                message.insert("content".to_string(), Value::String(content));
            }
            calls_remain = tool_calls_remain || function_call_remains;
        }

        // With nothing left to execute, the turn is an ordinary text answer.
        if !notes.is_empty() && !calls_remain {
            let reason = choice["finish_reason"].as_str();
            if matches!(reason, Some("tool_calls") | Some("function_call")) {
                choice["finish_reason"] = json!("stop");
            }
        }
    }
}

fn inspect_responses_api(response: &mut Value, judge: &mut Judge) {
    let Some(output) = response.get_mut("output").and_then(Value::as_array_mut) else {
        return;
    };

    for item in output.iter_mut() {
        let (tool, arguments) = match item["type"].as_str() {
            Some("function_call") => (named(&item["name"]), parse_arguments(&item["arguments"])),
            Some("custom_tool_call") => (named(&item["name"]), item["input"].clone()),
            _ => continue,
        };
        let note = judge.judge("responses", &item["call_id"], tool.as_deref(), &arguments);
        if let Some(note) = note {
            *item = json!({
                "type": "message",
                "id": format!("msg_blocked_{}", judge.blocked),
                "role": "assistant",
                "status": "completed",
                "content": [{ "type": "output_text", "text": note, "annotations": [] }],
            });
        }
    }
}

/// Name and decoded arguments of one entry in `tool_calls`.
fn chat_call_parts(call: &Value) -> (Option<String>, Value) {
    if let Some(name) = named(&call["function"]["name"]) {
        return (Some(name), parse_arguments(&call["function"]["arguments"]));
    }
    if let Some(name) = named(&call["custom"]["name"]) {
        return (Some(name), call["custom"]["input"].clone());
    }
    (None, Value::Null)
}

/// A non-empty string, or nothing.
fn named(value: &Value) -> Option<String> {
    value
        .as_str()
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

/// Tool results the agent is sending back, read from a request body.
/// Each result is paired with its call id so the caller can skip repeats.
pub fn tool_results(request: &Value) -> Vec<(Option<String>, Value)> {
    let mut events = Vec::new();

    for message in array(request, "messages") {
        if message["role"] == "tool" {
            let call_id = message["tool_call_id"].as_str().map(str::to_owned);
            events.push((
                call_id,
                json!({
                    "event": "tool_result",
                    "api": "chat.completions",
                    "call_id": message["tool_call_id"],
                    "output": message["content"],
                }),
            ));
        }
    }

    for item in array(request, "input") {
        if item["type"] == "function_call_output" {
            let call_id = item["call_id"].as_str().map(str::to_owned);
            events.push((
                call_id,
                json!({
                    "event": "tool_result",
                    "api": "responses",
                    "call_id": item["call_id"],
                    "output": item["output"],
                }),
            ));
        }
    }

    events
}

/// The array at `key`, or an empty slice if it is missing or not an array.
pub(crate) fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// Providers send tool arguments as a JSON-encoded string. Decode it so rules
/// and the log see real fields, and keep the raw value if it is not valid JSON.
fn parse_arguments(raw: &Value) -> Value {
    match raw.as_str() {
        Some(text) => serde_json::from_str(text).unwrap_or_else(|_| raw.clone()),
        None => raw.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../policy/example.policy.yaml");

    fn example_policy() -> Policy {
        Policy::parse(EXAMPLE).expect("example policy should parse")
    }

    fn shadow_policy() -> Policy {
        Policy::parse(&EXAMPLE.replace("mode: enforce", "mode: shadow"))
            .expect("shadow policy should parse")
    }

    fn drop_call(id: &str, database: &str) -> Value {
        json!({
            "id": id,
            "type": "function",
            "function": {
                "name": "db_drop",
                "arguments": json!({ "database": database }).to_string(),
            }
        })
    }

    fn chat_response(calls: Vec<Value>) -> Value {
        json!({
            "model": "gpt-test",
            "choices": [{
                "index": 0,
                "finish_reason": "tool_calls",
                "message": { "role": "assistant", "content": null, "tool_calls": calls }
            }]
        })
    }

    #[test]
    fn without_a_policy_calls_are_recorded_and_untouched() {
        let mut response = chat_response(vec![drop_call("call_1", "production")]);
        let original = response.clone();

        let inspection = inspect_response(&mut response, None, "");

        assert_eq!(response, original);
        assert_eq!(inspection.blocked, 0);
        assert_eq!(inspection.events.len(), 1);
        let event = &inspection.events[0];
        assert_eq!(event["tool"], "db_drop");
        assert_eq!(event["call_id"], "call_1");
        assert_eq!(event["arguments"]["database"], "production");
        assert!(event.get("decision").is_none());
        assert!(event.get("agent").is_none());
    }

    #[test]
    fn a_denied_call_is_removed_from_the_response() {
        let policy = example_policy();
        let mut response = chat_response(vec![drop_call("call_1", "production")]);

        let inspection = inspect_response(&mut response, Some(&policy), "ops-bot");

        assert_eq!(inspection.blocked, 1);
        let choice = &response["choices"][0];
        assert!(choice["message"].get("tool_calls").is_none());
        assert_eq!(choice["finish_reason"], "stop");
        let content = choice["message"]["content"].as_str().unwrap();
        assert!(
            content.contains("Blocked tool call \"db_drop\""),
            "{content}"
        );
        assert!(content.contains("no-production-db-drop"), "{content}");

        let event = &inspection.events[0];
        assert_eq!(event["decision"], "deny");
        assert_eq!(event["rule"], "no-production-db-drop");
        assert_eq!(event["blocked"], true);
        assert_eq!(event["agent"], "ops-bot");
    }

    #[test]
    fn allowed_calls_survive_next_to_a_denied_one() {
        let policy = example_policy();
        let mut response = chat_response(vec![
            drop_call("call_staging", "staging"),
            drop_call("call_prod", "production"),
        ]);

        let inspection = inspect_response(&mut response, Some(&policy), "");

        assert_eq!(inspection.blocked, 1);
        assert_eq!(inspection.events.len(), 2);
        let choice = &response["choices"][0];
        let calls = choice["message"]["tool_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["id"], "call_staging");
        // A call is still pending, so the agent must keep going.
        assert_eq!(choice["finish_reason"], "tool_calls");
        assert!(choice["message"]["content"]
            .as_str()
            .unwrap()
            .contains("Blocked tool call"));
    }

    #[test]
    fn an_allowed_response_is_not_modified() {
        let policy = example_policy();
        let mut response = chat_response(vec![drop_call("call_1", "staging")]);
        let original = response.clone();

        let inspection = inspect_response(&mut response, Some(&policy), "");

        assert_eq!(inspection.blocked, 0);
        assert_eq!(response, original);
        assert_eq!(inspection.events[0]["decision"], "allow");
        assert_eq!(inspection.events[0]["blocked"], false);
    }

    #[test]
    fn shadow_mode_records_the_decision_but_blocks_nothing() {
        let policy = shadow_policy();
        let mut response = chat_response(vec![drop_call("call_1", "production")]);
        let original = response.clone();

        let inspection = inspect_response(&mut response, Some(&policy), "");

        assert_eq!(response, original);
        assert_eq!(inspection.blocked, 0);
        assert_eq!(inspection.events[0]["decision"], "deny");
        assert_eq!(inspection.events[0]["blocked"], false);
    }

    #[test]
    fn text_the_model_wrote_is_kept_above_the_note() {
        let policy = example_policy();
        let mut response = chat_response(vec![drop_call("call_1", "production")]);
        response["choices"][0]["message"]["content"] = json!("Freeing up space now.");

        inspect_response(&mut response, Some(&policy), "");

        let content = response["choices"][0]["message"]["content"]
            .as_str()
            .unwrap();
        assert!(
            content.starts_with("Freeing up space now.\n\n[razorwire]"),
            "{content}"
        );
    }

    #[test]
    fn a_call_without_a_name_is_blocked_when_a_policy_is_enforced() {
        let policy = example_policy();
        let mut response = chat_response(vec![json!({ "id": "call_x", "type": "mystery" })]);

        let inspection = inspect_response(&mut response, Some(&policy), "");

        assert_eq!(inspection.blocked, 1);
        assert!(response["choices"][0]["message"]
            .get("tool_calls")
            .is_none());
        assert_eq!(inspection.events[0]["tool"], Value::Null);
        assert_eq!(inspection.events[0]["decision"], "deny");
    }

    #[test]
    fn the_legacy_function_call_form_is_checked_too() {
        let policy = example_policy();
        let mut response = json!({
            "choices": [{
                "finish_reason": "function_call",
                "message": {
                    "role": "assistant",
                    "content": null,
                    "function_call": {
                        "name": "db_drop",
                        "arguments": "{\"database\":\"production\"}"
                    }
                }
            }]
        });

        let inspection = inspect_response(&mut response, Some(&policy), "");

        assert_eq!(inspection.blocked, 1);
        let choice = &response["choices"][0];
        assert!(choice["message"].get("function_call").is_none());
        assert_eq!(choice["finish_reason"], "stop");
    }

    #[test]
    fn responses_api_calls_are_replaced_with_a_message() {
        let policy = example_policy();
        let mut response = json!({
            "object": "response",
            "model": "gpt-test",
            "output": [
                { "type": "reasoning", "summary": [] },
                {
                    "type": "function_call",
                    "call_id": "call_2",
                    "name": "stripe_refund",
                    "arguments": "{\"amount\":47000}"
                },
                {
                    "type": "function_call",
                    "call_id": "call_3",
                    "name": "stripe_refund",
                    "arguments": "{\"amount\":20}"
                }
            ]
        });

        let inspection = inspect_response(&mut response, Some(&policy), "");

        assert_eq!(inspection.blocked, 1);
        assert_eq!(inspection.events.len(), 2);
        assert_eq!(inspection.events[0]["decision"], "review");
        assert_eq!(inspection.events[0]["blocked"], true);
        assert_eq!(inspection.events[1]["decision"], "allow");

        let output = response["output"].as_array().unwrap();
        assert_eq!(output.len(), 3);
        assert_eq!(output[0]["type"], "reasoning");
        assert_eq!(output[1]["type"], "message");
        assert!(output[1]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("stripe_refund"));
        assert_eq!(output[2]["type"], "function_call");
        assert_eq!(output[2]["call_id"], "call_3");
    }

    #[test]
    fn a_plain_answer_has_no_tool_calls() {
        let policy = example_policy();
        let mut response = json!({
            "choices": [{ "finish_reason": "stop", "message": { "role": "assistant", "content": "hi" } }]
        });
        let original = response.clone();

        let inspection = inspect_response(&mut response, Some(&policy), "");

        assert!(inspection.events.is_empty());
        assert_eq!(inspection.blocked, 0);
        assert_eq!(response, original);
    }

    #[test]
    fn reads_tool_results_from_a_request() {
        let request = json!({
            "messages": [
                { "role": "user", "content": "refund order 9" },
                { "role": "tool", "tool_call_id": "call_1", "content": "refunded" }
            ]
        });

        let results = tool_results(&request);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.as_deref(), Some("call_1"));
        assert_eq!(results[0].1["output"], "refunded");
    }

    #[test]
    fn keeps_arguments_that_are_not_json() {
        let raw = json!("not json");
        assert_eq!(parse_arguments(&raw), raw);
    }
}
