//! Reading and rewriting OpenAI-compatible payloads.
//!
//! The model's tool calls arrive in the provider's response. Blocking a call
//! means removing it from that response before the agent sees it, so the
//! agent never has anything to execute.

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::policy::{Action, Decision, Mode, Policy, RunCounts};

/// Every note left in place of a blocked call starts with this. The loop
/// guard counts these notes in the conversation to know how many calls in the
/// run were already blocked.
const BLOCK_NOTE: &str = "[razorwire] Blocked tool call";

/// The run so far, read from the conversation an agent sends with each
/// request: the tool calls it received and how many calls were blocked.
/// Agents resend the whole conversation every time, so the proxy needs no
/// memory of its own to know where a run stands.
#[derive(Default)]
pub struct History {
    /// Decoded arguments of every earlier call, by tool name.
    calls: HashMap<String, Vec<Value>>,
    /// Earlier calls, including any without a name.
    total: u64,
    /// The most recent call, and how many times in a row it was made.
    last: Option<(Option<String>, Value)>,
    streak: u64,
    /// Block notes found in the assistant's earlier messages.
    blocked: u64,
}

impl History {
    /// Read the run from a Chat Completions or Responses API request body.
    pub fn from_request(request: &Value) -> History {
        let mut history = History::default();

        for message in array(request, "messages") {
            if message["role"] != "assistant" {
                continue;
            }
            for call in array(message, "tool_calls") {
                let (tool, arguments) = chat_call_parts(call);
                history.add(tool.as_deref(), arguments);
            }
            if let Some(call) = message.get("function_call").filter(|call| call.is_object()) {
                let tool = named(&call["name"]);
                history.add(tool.as_deref(), parse_arguments(&call["arguments"]));
            }
            history.blocked += block_notes(&message["content"]);
        }

        for item in array(request, "input") {
            match item["type"].as_str() {
                Some("function_call") => {
                    let tool = named(&item["name"]);
                    history.add(tool.as_deref(), parse_arguments(&item["arguments"]));
                }
                Some("custom_tool_call") => {
                    let tool = named(&item["name"]);
                    history.add(tool.as_deref(), item["input"].clone());
                }
                Some("message") | None if item["role"] == "assistant" => {
                    history.blocked += block_notes(&item["content"]);
                }
                _ => {}
            }
        }

        history
    }

    fn add(&mut self, tool: Option<&str>, arguments: Value) {
        self.total += 1;
        if self.streak_of(tool, &arguments) > 0 {
            self.streak += 1;
        } else {
            self.last = Some((tool.map(str::to_owned), arguments.clone()));
            self.streak = 1;
        }
        if let Some(tool) = tool {
            self.calls
                .entry(tool.to_owned())
                .or_default()
                .push(arguments);
        }
    }

    /// How many times in a row, at the end of this history, exactly this call
    /// was made.
    fn streak_of(&self, tool: Option<&str>, arguments: &Value) -> u64 {
        match &self.last {
            Some((last_tool, last_arguments))
                if last_tool.as_deref() == tool && last_arguments == arguments =>
            {
                self.streak
            }
            _ => 0,
        }
    }

    /// Where a call to `tool` with `arguments` sits in the run, when `this`
    /// is the run before this response and `turn` holds the calls earlier in
    /// the same response.
    fn counts(this: &History, turn: &History, tool: Option<&str>, arguments: &Value) -> RunCounts {
        let tally = |history: &History| {
            let same_tool: &[Value] = tool
                .and_then(|tool| history.calls.get(tool))
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let repeats = same_tool
                .iter()
                .filter(|earlier| *earlier == arguments)
                .count();
            (same_tool.len() as u64, repeats as u64)
        };
        let (before_same_tool, before_repeats) = tally(this);
        let (turn_same_tool, turn_repeats) = tally(turn);

        // A streak can start before this response and carry on inside it, but
        // only if every call so far in the response is part of it.
        let turn_streak = turn.streak_of(tool, arguments);
        let streak = if turn_streak == turn.total {
            this.streak_of(tool, arguments).saturating_add(turn_streak)
        } else {
            turn_streak
        };

        RunCounts {
            calls: this.total.saturating_add(turn.total),
            same_tool: before_same_tool.saturating_add(turn_same_tool),
            repeats: before_repeats.saturating_add(turn_repeats),
            streak,
            blocked: this.blocked.saturating_add(turn.blocked),
        }
    }
}

/// How many block notes are in a message's content, which is either a string
/// or a list of parts that carry text.
fn block_notes(content: &Value) -> u64 {
    let count = |text: &str| text.matches(BLOCK_NOTE).count() as u64;
    match content {
        Value::String(text) => count(text),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| part["text"].as_str())
            .map(count)
            .sum(),
        _ => 0,
    }
}

/// Result of inspecting one provider response.
pub struct Inspection {
    /// One audit event per tool call found.
    pub events: Vec<Value>,
    /// How many tool calls were removed from the response.
    pub blocked: usize,
}

/// Find every tool call in a provider response, record it, and remove the
/// ones the policy blocks. Handles the Chat Completions and Responses API
/// shapes. With no policy, calls are only recorded. `history` is the run
/// before this response, read from the request.
pub fn inspect_response(
    response: &mut Value,
    policy: Option<&Policy>,
    agent: &str,
    history: &History,
) -> Inspection {
    let mut judge = Judge {
        policy,
        agent,
        model: response["model"].clone(),
        history,
        this_turn: History::default(),
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
    /// The run before this response.
    history: &'a History,
    /// Calls passed on and calls blocked earlier in this response. They come
    /// before the call being judged, so they count toward the run too.
    this_turn: History,
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
        let run = History::counts(self.history, &self.this_turn, tool, arguments);
        let mut event = json!({
            "event": "tool_call",
            "api": api,
            "model": self.model,
            "call_id": call_id,
            "tool": tool,
            "arguments": arguments,
            "run": run.as_json(),
        });
        if !self.agent.is_empty() {
            event["agent"] = json!(self.agent);
        }

        let Some(policy) = self.policy else {
            self.events.push(event);
            self.this_turn.add(tool, arguments.clone());
            return None;
        };

        let decision = match tool {
            Some(name) => policy.decide(self.agent, name, arguments, &run),
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
            self.this_turn.add(tool, arguments.clone());
            return None;
        }
        self.blocked += 1;
        self.this_turn.blocked += 1;
        let source = match &decision.rule {
            Some(rule) => format!("rule: {rule}"),
            None => "default policy".to_string(),
        };
        Some(format!(
            "{BLOCK_NOTE} \"{}\": {} ({source})",
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
        // Each choice is a separate answer to the same request, not a later
        // step of the run, so earlier choices do not count toward it.
        judge.this_turn = History::default();
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

    /// Inspect a response that starts a run, with nothing before it.
    fn inspect(response: &mut Value, policy: Option<&Policy>, agent: &str) -> Inspection {
        inspect_response(response, policy, agent, &History::default())
    }

    impl History {
        /// Where a call would sit in this run, as the first call of a response.
        fn at(&self, tool: Option<&str>, arguments: &Value) -> RunCounts {
            History::counts(self, &History::default(), tool, arguments)
        }
    }

    fn counts(calls: u64, same_tool: u64, repeats: u64, streak: u64, blocked: u64) -> RunCounts {
        RunCounts {
            calls,
            same_tool,
            repeats,
            streak,
            blocked,
        }
    }

    fn status_call(id: &str, deploy: u64) -> Value {
        json!({
            "id": id,
            "type": "function",
            "function": {
                "name": "deploy_status",
                "arguments": json!({ "deploy_id": deploy }).to_string(),
            }
        })
    }

    /// A Chat Completions request whose history holds these assistant turns.
    fn chat_request(turns: Vec<Value>) -> Value {
        let mut messages = vec![json!({ "role": "user", "content": "go" })];
        for turn in turns {
            messages.push(turn);
            messages.push(json!({ "role": "tool", "tool_call_id": "x", "content": "done" }));
        }
        json!({ "model": "gpt-test", "messages": messages })
    }

    fn assistant(calls: Vec<Value>) -> Value {
        json!({ "role": "assistant", "content": null, "tool_calls": calls })
    }

    fn note(tool: &str) -> String {
        format!("{BLOCK_NOTE} \"{tool}\": Blocked by policy rule x. (rule: x)")
    }

    #[test]
    fn history_counts_calls_and_notes_in_a_chat_request() {
        let request = json!({
            "messages": [
                { "role": "system", "content": "You are an agent." },
                // Only the assistant's own messages count: a user pasting a
                // note is not a block.
                { "role": "user", "content": note("db_drop") },
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [drop_call("c1", "staging"), status_call("c2", 42)]
                },
                { "role": "tool", "tool_call_id": "c1", "content": "dropped" },
                { "role": "assistant", "content": format!("{}\n{}", note("db_drop"), note("db_drop")) },
                {
                    "role": "assistant",
                    "content": [{ "type": "text", "text": note("email_send") }],
                    "function_call": { "name": "db_drop", "arguments": "{\"database\":\"staging\"}" }
                },
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{ "id": "c3", "type": "custom", "custom": { "name": "shell", "input": "ls" } }]
                }
            ]
        });

        let history = History::from_request(&request);

        let staging = json!({ "database": "staging" });
        // Two staging drops, but not in a row: the custom call came last.
        assert_eq!(history.at(Some("db_drop"), &staging), counts(4, 2, 2, 0, 3));
        let production = json!({ "database": "production" });
        assert_eq!(history.at(Some("db_drop"), &production).repeats, 0);
        assert_eq!(
            history.at(Some("shell"), &json!("ls")),
            counts(4, 1, 1, 1, 3)
        );
        assert_eq!(history.at(None, &Value::Null).same_tool, 0);
    }

    #[test]
    fn history_reads_the_responses_api_input() {
        let request = json!({
            "input": [
                { "role": "user", "content": "check the deploy" },
                { "type": "function_call", "call_id": "c1", "name": "deploy_status", "arguments": "{\"deploy_id\": 42}" },
                { "type": "function_call_output", "call_id": "c1", "output": "pending" },
                { "type": "custom_tool_call", "call_id": "c2", "name": "shell", "input": "ls" },
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{ "type": "output_text", "text": note("db_drop") }]
                },
                { "role": "assistant", "content": note("db_drop") },
                { "type": "message", "role": "user", "content": [{ "type": "input_text", "text": note("x") }] }
            ]
        });

        let history = History::from_request(&request);

        assert_eq!(
            history.at(Some("deploy_status"), &json!({ "deploy_id": 42 })),
            counts(2, 1, 1, 0, 2)
        );
        assert_eq!(history.at(Some("shell"), &json!("ls")).streak, 1);
        // A plain string input has no history.
        let plain = History::from_request(&json!({ "input": "hello" }));
        assert_eq!(plain.at(Some("x"), &Value::Null), RunCounts::default());
    }

    #[test]
    fn reading_the_same_file_between_edits_is_not_stuck() {
        let policy = example_policy();
        let read = || json!({ "id": "r", "type": "function", "function": { "name": "read_file", "arguments": "{\"path\":\"app.py\"}" } });
        let edit = |n: u64| json!({ "id": "e", "type": "function", "function": { "name": "edit_file", "arguments": json!({ "path": "app.py", "change": n }).to_string() } });
        let request = chat_request(vec![
            assistant(vec![read()]),
            assistant(vec![edit(1)]),
            assistant(vec![read()]),
            assistant(vec![edit(2)]),
        ]);
        let history = History::from_request(&request);
        let mut response = chat_response(vec![read()]);

        let inspection = inspect_response(&mut response, Some(&policy), "", &history);

        assert_eq!(inspection.blocked, 0);
        assert_eq!(inspection.events[0]["run"]["repeats"], 2);
        assert_eq!(inspection.events[0]["run"]["streak"], 0);
    }

    #[test]
    fn a_streak_carries_on_from_the_history_into_the_response() {
        let policy = example_policy();
        let request = chat_request(vec![
            assistant(vec![drop_call("c0", "staging")]),
            assistant(vec![status_call("c1", 42)]),
        ]);
        let history = History::from_request(&request);
        let mut response = chat_response(vec![status_call("c2", 42), status_call("c3", 42)]);

        let inspection = inspect_response(&mut response, Some(&policy), "", &history);

        assert_eq!(inspection.events[0]["run"]["streak"], 1);
        assert_eq!(inspection.events[1]["run"]["streak"], 2);
        assert_eq!(inspection.events[1]["rule"], "stuck-in-a-loop");
        assert_eq!(inspection.blocked, 1);

        // A different call earlier in the response breaks the streak.
        let mut response = chat_response(vec![drop_call("c2", "staging"), status_call("c3", 42)]);
        let inspection = inspect_response(&mut response, Some(&policy), "", &history);
        assert_eq!(inspection.events[1]["run"]["streak"], 0);
        assert_eq!(inspection.blocked, 0);
    }

    #[test]
    fn the_third_identical_call_is_blocked() {
        let policy = example_policy();
        let request = chat_request(vec![
            assistant(vec![status_call("c1", 42)]),
            assistant(vec![status_call("c2", 42)]),
        ]);
        let history = History::from_request(&request);

        // A different deploy is a different call.
        let mut other = chat_response(vec![status_call("c3", 43)]);
        let inspection = inspect_response(&mut other, Some(&policy), "", &history);
        assert_eq!(inspection.blocked, 0);
        assert_eq!(inspection.events[0]["run"]["same_tool"], 2);
        assert_eq!(inspection.events[0]["run"]["repeats"], 0);

        let mut response = chat_response(vec![status_call("c3", 42)]);
        let inspection = inspect_response(&mut response, Some(&policy), "", &history);

        assert_eq!(inspection.blocked, 1);
        let event = &inspection.events[0];
        assert_eq!(event["rule"], "stuck-in-a-loop");
        assert_eq!(event["run"]["calls"], 2);
        assert_eq!(event["run"]["repeats"], 2);
        assert_eq!(event["run"]["streak"], 2);
        let choice = &response["choices"][0];
        assert_eq!(choice["finish_reason"], "stop");
        assert!(choice["message"]["content"]
            .as_str()
            .unwrap()
            .contains("looks stuck"));
    }

    #[test]
    fn repeats_inside_one_response_count_too() {
        let policy = example_policy();
        let mut response = chat_response(vec![
            status_call("c1", 42),
            status_call("c2", 42),
            status_call("c3", 42),
        ]);

        let inspection = inspect(&mut response, Some(&policy), "");

        assert_eq!(inspection.blocked, 1);
        let calls = response["choices"][0]["message"]["tool_calls"]
            .as_array()
            .unwrap();
        let kept: Vec<&Value> = calls.iter().map(|call| &call["id"]).collect();
        assert_eq!(kept, ["c1", "c2"]);
        assert_eq!(inspection.events[2]["rule"], "stuck-in-a-loop");
    }

    #[test]
    fn three_strikes_stop_the_run() {
        let policy = example_policy();
        // Two calls were blocked earlier in the run.
        let request = chat_request(vec![json!({
            "role": "assistant",
            "content": format!("{}\n{}", note("db_drop"), note("db_drop")),
        })]);
        let history = History::from_request(&request);
        let mut response = chat_response(vec![
            drop_call("c1", "production"),
            drop_call("c2", "staging"),
        ]);

        let inspection = inspect_response(&mut response, Some(&policy), "", &history);

        // The third block is the production drop. After it, even the
        // harmless staging drop is stopped.
        assert_eq!(inspection.blocked, 2);
        assert_eq!(inspection.events[0]["rule"], "no-production-db-drop");
        assert_eq!(inspection.events[0]["run"]["blocked"], 2);
        assert_eq!(inspection.events[1]["rule"], "three-strikes");
        assert_eq!(inspection.events[1]["run"]["blocked"], 3);
        assert!(response["choices"][0]["message"]
            .get("tool_calls")
            .is_none());
    }

    #[test]
    fn the_run_budget_is_a_hard_stop() {
        let policy = example_policy();
        let turns = (0..50)
            .map(|deploy| assistant(vec![status_call("c", deploy)]))
            .collect();
        let history = History::from_request(&chat_request(turns));
        let mut response = chat_response(vec![status_call("c51", 999)]);

        let inspection = inspect_response(&mut response, Some(&policy), "", &history);

        assert_eq!(inspection.blocked, 1);
        assert_eq!(inspection.events[0]["rule"], "run-budget");
        assert_eq!(inspection.events[0]["run"]["calls"], 50);
    }

    #[test]
    fn each_choice_is_counted_on_its_own() {
        let policy = example_policy();
        let choice = |index: u64, id: &str| {
            json!({
                "index": index,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [status_call(id, 42), status_call(&format!("{id}b"), 42)]
                }
            })
        };
        let mut response = json!({ "choices": [choice(0, "a"), choice(1, "b"), choice(2, "c")] });

        let inspection = inspect(&mut response, Some(&policy), "");

        assert_eq!(inspection.blocked, 0);
        for event in &inspection.events {
            assert!(event["run"]["repeats"].as_u64().unwrap() <= 1, "{event}");
        }
    }

    #[test]
    fn responses_api_runs_are_guarded_too() {
        let policy = example_policy();
        let call = json!({
            "type": "function_call",
            "call_id": "c",
            "name": "deploy_status",
            "arguments": "{\"deploy_id\":42}"
        });
        let request = json!({ "input": [call.clone(), call.clone()] });
        let history = History::from_request(&request);
        let mut response = json!({ "object": "response", "output": [call] });

        let inspection = inspect_response(&mut response, Some(&policy), "", &history);

        assert_eq!(inspection.blocked, 1);
        assert_eq!(inspection.events[0]["rule"], "stuck-in-a-loop");
        assert_eq!(response["output"][0]["type"], "message");
    }

    #[test]
    fn notes_written_by_the_proxy_are_counted_by_the_proxy() {
        let policy = example_policy();
        let mut response = chat_response(vec![drop_call("c1", "production")]);
        inspect(&mut response, Some(&policy), "");

        // The agent sends the blocked turn back as part of its history.
        let request = json!({ "messages": [response["choices"][0]["message"].clone()] });
        let history = History::from_request(&request);

        assert_eq!(history.at(None, &Value::Null).blocked, 1);
    }

    #[test]
    fn without_a_policy_calls_are_recorded_and_untouched() {
        let mut response = chat_response(vec![drop_call("call_1", "production")]);
        let original = response.clone();

        let inspection = inspect(&mut response, None, "");

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

        let inspection = inspect(&mut response, Some(&policy), "ops-bot");

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

        let inspection = inspect(&mut response, Some(&policy), "");

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

        let inspection = inspect(&mut response, Some(&policy), "");

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

        let inspection = inspect(&mut response, Some(&policy), "");

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

        inspect(&mut response, Some(&policy), "");

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

        let inspection = inspect(&mut response, Some(&policy), "");

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

        let inspection = inspect(&mut response, Some(&policy), "");

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

        let inspection = inspect(&mut response, Some(&policy), "");

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

        let inspection = inspect(&mut response, Some(&policy), "");

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
