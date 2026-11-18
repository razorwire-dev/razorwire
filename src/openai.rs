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
#[derive(Default, Clone)]
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
/// before this response, read from the request. A `review` decision blocks
/// at once here; holding a call for a human goes through `plan` and `apply`.
pub fn inspect_response(
    response: &mut Value,
    policy: Option<&Policy>,
    agent: &str,
    history: &History,
) -> Inspection {
    let plan = plan(response, policy, agent, history, false);
    let blocked = apply(response, &plan);
    Inspection {
        events: plan.events,
        blocked,
    }
}

/// What happens to one tool call.
enum Verdict {
    Pass,
    /// Removed, with this note left in its place.
    Block(String),
    /// Waiting for a human. The number is the index in `Plan::holds`.
    Hold(usize),
}

/// A tool call held for a human decision.
pub struct Hold {
    pub tool: String,
    pub arguments: Value,
    pub call_id: Value,
    pub rule: Option<String>,
    pub message: String,
    /// This call's entry in `Plan::events`.
    pub event: usize,
    /// Unset until decided. `Some(None)` lets the call through and
    /// `Some(Some(note))` blocks it with that note.
    outcome: Option<Option<String>>,
}

/// The policy's decisions for every tool call in one response, made before
/// anything is changed so that held calls can wait for a human.
pub struct Plan {
    /// One audit event per tool call found.
    pub events: Vec<Value>,
    pub holds: Vec<Hold>,
    verdicts: Vec<Verdict>,
}

impl Plan {
    /// A human approved this held call: it goes through unchanged.
    pub fn approve(&mut self, hold: usize) {
        if let Some(hold) = self.holds.get_mut(hold) {
            hold.outcome = Some(None);
        }
    }

    /// This held call is blocked. `why` says what happened, for example who
    /// denied it.
    pub fn refuse(&mut self, hold: usize, why: &str) {
        if let Some(hold) = self.holds.get_mut(hold) {
            let message = format!("{} {why}", hold.message);
            let note = block_note(Some(&hold.tool), &message, hold.rule.as_deref());
            hold.outcome = Some(Some(note));
        }
    }
}

/// Decide every tool call in a response without changing it. With `holds`,
/// a `review` decision under an enforced policy holds the call for a human
/// instead of blocking it; otherwise it blocks at once.
pub fn plan(
    response: &mut Value,
    policy: Option<&Policy>,
    agent: &str,
    history: &History,
    holds: bool,
) -> Plan {
    let mut planner = Planner {
        policy,
        agent,
        model: response["model"].clone(),
        history,
        this_turn: History::default(),
        holds,
        plan: Plan {
            events: Vec::new(),
            holds: Vec::new(),
            verdicts: Vec::new(),
        },
    };
    visit(response, &mut planner);
    planner.plan
}

/// Carry out a plan: remove the blocked calls, and the held calls that were
/// not approved, leaving a note for each. Returns how many were removed. A
/// held call nobody decided is blocked.
pub fn apply(response: &mut Value, plan: &Plan) -> usize {
    let mut applier = Applier {
        verdicts: plan.verdicts.iter(),
        holds: &plan.holds,
        blocked: 0,
    };
    visit(response, &mut applier);
    applier.blocked
}

/// The note left in place of a blocked call. It starts with `BLOCK_NOTE` so
/// the loop guard can count it when the agent sends it back.
fn block_note(tool: Option<&str>, message: &str, rule: Option<&str>) -> String {
    let source = match rule {
        Some(rule) => format!("rule: {rule}"),
        None => "default policy".to_string(),
    };
    format!(
        "{BLOCK_NOTE} \"{}\": {message} ({source})",
        tool.unwrap_or("unnamed")
    )
}

/// Something that looks at each tool call of a response in order.
trait Visitor {
    /// A new Chat Completions choice starts.
    fn choice(&mut self);
    /// One tool call. Returns the note to put in its place when it must be
    /// removed, or `None` to keep it.
    fn call(
        &mut self,
        api: &str,
        call_id: &Value,
        tool: Option<&str>,
        arguments: &Value,
    ) -> Option<String>;
}

struct Planner<'a> {
    policy: Option<&'a Policy>,
    agent: &'a str,
    model: Value,
    /// The run before this response.
    history: &'a History,
    /// Calls passed on, blocked and held earlier in this response. They come
    /// before the call being judged, so they count toward the run too.
    this_turn: History,
    holds: bool,
    plan: Plan,
}

impl Visitor for Planner<'_> {
    fn choice(&mut self) {
        // Each choice is a separate answer to the same request, not a later
        // step of the run, so earlier choices do not count toward it.
        self.this_turn = History::default();
    }

    fn call(
        &mut self,
        api: &str,
        call_id: &Value,
        tool: Option<&str>,
        arguments: &Value,
    ) -> Option<String> {
        let verdict = self.judge(api, call_id, tool, arguments);
        self.plan.verdicts.push(verdict);
        None
    }
}

impl Planner<'_> {
    fn judge(
        &mut self,
        api: &str,
        call_id: &Value,
        tool: Option<&str>,
        arguments: &Value,
    ) -> Verdict {
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
            self.plan.events.push(event);
            self.this_turn.add(tool, arguments.clone());
            return Verdict::Pass;
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
        let enforced = policy.mode() == Mode::Enforce;
        let held = enforced && self.holds && decision.action == Action::Review;
        let blocked = !decision.is_allowed() && enforced && !held;

        event["decision"] = json!(decision.action.as_str());
        event["rule"] = json!(decision.rule);
        if held {
            // The outcome is logged when a human decides.
            event["held"] = json!(true);
        } else {
            event["blocked"] = json!(blocked);
        }
        if !decision.is_allowed() {
            event["reason"] = json!(decision.message);
        }
        if let Some(error) = &decision.error {
            event["error"] = json!(error);
        }
        self.plan.events.push(event);

        match (tool, held, blocked) {
            (Some(tool), true, _) => {
                // A held call has not reached the agent, so later calls in
                // this response count it as blocked, as they would a denial.
                self.this_turn.blocked += 1;
                self.plan.holds.push(Hold {
                    tool: tool.to_string(),
                    arguments: arguments.clone(),
                    call_id: call_id.clone(),
                    rule: decision.rule,
                    message: decision.message,
                    event: self.plan.events.len() - 1,
                    outcome: None,
                });
                Verdict::Hold(self.plan.holds.len() - 1)
            }
            (_, false, false) => {
                self.this_turn.add(tool, arguments.clone());
                Verdict::Pass
            }
            _ => {
                self.this_turn.blocked += 1;
                Verdict::Block(block_note(
                    tool,
                    &decision.message,
                    decision.rule.as_deref(),
                ))
            }
        }
    }
}

struct Applier<'a> {
    verdicts: std::slice::Iter<'a, Verdict>,
    holds: &'a [Hold],
    blocked: usize,
}

impl Visitor for Applier<'_> {
    fn choice(&mut self) {}

    fn call(
        &mut self,
        _api: &str,
        _call_id: &Value,
        tool: Option<&str>,
        _arguments: &Value,
    ) -> Option<String> {
        let note = match self.verdicts.next() {
            Some(Verdict::Pass) => None,
            Some(Verdict::Block(note)) => Some(note.clone()),
            Some(Verdict::Hold(index)) => match self.holds.get(*index) {
                Some(Hold {
                    outcome: Some(outcome),
                    ..
                }) => outcome.clone(),
                Some(hold) => Some(block_note(
                    Some(&hold.tool),
                    &format!("{} No decision was made, so it was blocked.", hold.message),
                    hold.rule.as_deref(),
                )),
                None => Some(unmatched_note(tool)),
            },
            // The response has more calls than the plan: fail closed.
            None => Some(unmatched_note(tool)),
        };
        if note.is_some() {
            self.blocked += 1;
        }
        note
    }
}

fn unmatched_note(tool: Option<&str>) -> String {
    block_note(
        tool,
        "The call could not be matched to its policy decision, so it was blocked.",
        None,
    )
}

/// Walk every tool call in a response in a fixed order, and remove the ones
/// the visitor returns a note for. Handles the Chat Completions and
/// Responses API shapes.
fn visit(response: &mut Value, visitor: &mut dyn Visitor) {
    visit_chat_completion(response, visitor);
    visit_responses_api(response, visitor);
}

fn visit_chat_completion(response: &mut Value, visitor: &mut dyn Visitor) {
    let Some(choices) = response.get_mut("choices").and_then(Value::as_array_mut) else {
        return;
    };

    for choice in choices {
        visitor.choice();
        let mut notes = Vec::new();
        let mut calls_remain = false;

        if let Some(message) = choice.get_mut("message").and_then(Value::as_object_mut) {
            let mut tool_calls_remain = false;
            if let Some(Value::Array(calls)) = message.get_mut("tool_calls") {
                for call in std::mem::take(calls) {
                    let (tool, arguments) = chat_call_parts(&call);
                    let note =
                        visitor.call("chat.completions", &call["id"], tool.as_deref(), &arguments);
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
                let note = visitor.call(
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

fn visit_responses_api(response: &mut Value, visitor: &mut dyn Visitor) {
    let Some(output) = response.get_mut("output").and_then(Value::as_array_mut) else {
        return;
    };

    let mut removed = 0;
    for item in output.iter_mut() {
        let (tool, arguments) = match item["type"].as_str() {
            Some("function_call") => (named(&item["name"]), parse_arguments(&item["arguments"])),
            Some("custom_tool_call") => (named(&item["name"]), item["input"].clone()),
            _ => continue,
        };
        let note = visitor.call("responses", &item["call_id"], tool.as_deref(), &arguments);
        if let Some(note) = note {
            removed += 1;
            *item = json!({
                "type": "message",
                "id": format!("msg_blocked_{removed}"),
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
                    "arguments": "{\"amount\":4700}"
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

    fn refund_call(id: &str, amount: u64) -> Value {
        json!({
            "id": id,
            "type": "function",
            "function": {
                "name": "stripe_refund",
                "arguments": json!({ "amount": amount }).to_string(),
            }
        })
    }

    /// Plan a response with holds allowed, as the proxy does when an
    /// approver is set up.
    fn plan_with_holds(response: &mut Value) -> Plan {
        plan(
            response,
            Some(&example_policy()),
            "support",
            &History::default(),
            true,
        )
    }

    #[test]
    fn a_review_call_is_held_without_changing_the_response() {
        let mut response = chat_response(vec![refund_call("big", 4700), refund_call("small", 20)]);
        let original = response.clone();

        let plan = plan_with_holds(&mut response);

        assert_eq!(response, original);
        assert_eq!(plan.holds.len(), 1);
        let hold = &plan.holds[0];
        assert_eq!(hold.tool, "stripe_refund");
        assert_eq!(hold.call_id, "big");
        assert_eq!(hold.arguments["amount"], 4700);
        assert_eq!(hold.rule.as_deref(), Some("refund-cap"));
        let event = &plan.events[hold.event];
        assert_eq!(event["decision"], "review");
        assert_eq!(event["held"], true);
        assert!(event.get("blocked").is_none());
        assert_eq!(plan.events[1]["blocked"], false);
    }

    #[test]
    fn an_approved_call_goes_through() {
        let mut response = chat_response(vec![refund_call("big", 4700)]);
        let original = response.clone();
        let mut plan = plan_with_holds(&mut response);

        plan.approve(0);
        let blocked = apply(&mut response, &plan);

        assert_eq!(blocked, 0);
        assert_eq!(response, original);
    }

    #[test]
    fn a_denied_call_is_removed_with_the_reason() {
        let mut response = chat_response(vec![refund_call("big", 4700), refund_call("small", 20)]);
        let mut plan = plan_with_holds(&mut response);

        plan.refuse(0, "Denied by mann: wrong order.");
        let blocked = apply(&mut response, &plan);

        assert_eq!(blocked, 1);
        let message = &response["choices"][0]["message"];
        let calls = message["tool_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["id"], "small");
        let content = message["content"].as_str().unwrap();
        assert!(content.starts_with(BLOCK_NOTE), "{content}");
        assert!(
            content.contains("Denied by mann: wrong order."),
            "{content}"
        );
        assert!(content.contains("(rule: refund-cap)"), "{content}");
    }

    #[test]
    fn a_hold_nobody_decided_is_blocked() {
        let mut response = json!({
            "object": "response",
            "output": [{
                "type": "function_call",
                "call_id": "c1",
                "name": "stripe_refund",
                "arguments": "{\"amount\":4700}"
            }]
        });
        let plan = plan_with_holds(&mut response);

        let blocked = apply(&mut response, &plan);

        assert_eq!(blocked, 1);
        assert_eq!(response["output"][0]["type"], "message");
        assert!(response["output"][0]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("No decision was made"));
    }

    #[test]
    fn a_held_call_counts_as_blocked_for_the_calls_after_it() {
        let mut response = chat_response(vec![refund_call("big", 4700), status_call("s", 1)]);
        let plan = plan_with_holds(&mut response);
        assert_eq!(plan.events[1]["run"]["blocked"], 1);
        assert_eq!(plan.events[1]["run"]["calls"], 0);
    }

    #[test]
    fn shadow_mode_never_holds() {
        let mut response = chat_response(vec![refund_call("big", 4700)]);
        let policy = shadow_policy();
        let plan = plan(&mut response, Some(&policy), "", &History::default(), true);
        assert!(plan.holds.is_empty());
        assert_eq!(plan.events[0]["blocked"], false);
    }

    #[test]
    fn a_plan_that_does_not_fit_the_response_fails_closed() {
        let mut planned = chat_response(vec![]);
        let plan = plan_with_holds(&mut planned);
        let mut other = chat_response(vec![drop_call("c1", "staging")]);

        assert_eq!(apply(&mut other, &plan), 1);
        assert!(other["choices"][0]["message"]["content"]
            .as_str()
            .unwrap()
            .contains("could not be matched"));
    }
}
