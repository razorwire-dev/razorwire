//! Rollback: undo, newest first, what agents did.
//!
//! The plan is worked out from the audit log, so it covers every call that
//! went through, across restarts. A call counts as done when it reached the
//! agent (allowed, or held and approved) or when the executor carried out a
//! parked call. Its arguments come from the logged provider response, never
//! from what an agent sends later. Its result is what the agent reported the
//! tool returned. The policy's `undo` recipe for the tool turns these into
//! the call that reverses it, which the executor carries out.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    approvals::shown_arguments,
    auth::hex,
    policy::{Policy, UndoPlan},
};

/// Undo ids one request may name.
pub const MAX_IDS: usize = 200;

/// Which calls to roll back. At least one part must be set.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Filter {
    pub agent: Option<String>,
    pub since_ms: Option<u64>,
    pub ids: Vec<String>,
}

impl Filter {
    pub fn is_empty(&self) -> bool {
        self.agent.is_none() && self.since_ms.is_none() && self.ids.is_empty()
    }

    pub fn as_json(&self) -> Value {
        json!({ "agent": self.agent, "since_ms": self.since_ms, "ids": self.ids })
    }

    fn admits(&self, step: &Step) -> bool {
        self.agent.as_ref().is_none_or(|agent| *agent == step.agent)
            && self.since_ms.is_none_or(|since| step.ts_ms >= since)
            && (self.ids.is_empty() || self.ids.contains(&step.id))
    }
}

/// An undo id: `und_` and 24 hex characters.
pub fn is_undo_id(id: &str) -> bool {
    id.strip_prefix("und_")
        .is_some_and(|rest| rest.len() == 24 && rest.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// One call that went through, and how to undo it.
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    pub id: String,
    /// When the call was passed on, or carried out by the executor.
    pub ts_ms: u64,
    pub agent: String,
    pub tool: String,
    pub call_id: String,
    pub arguments: Value,
    /// What the tool returned, as reported. `None` if nothing was.
    pub result: Option<Value>,
    pub undo: UndoPlan,
    /// It was undone already.
    pub done: bool,
    /// Why the last attempt to undo it failed.
    pub last_error: Option<String>,
}

impl Step {
    /// What an admin is shown.
    pub fn summary(&self) -> Value {
        let (undo, cannot) = match &self.undo {
            UndoPlan::Call { tool, arguments } => (
                json!({ "tool": tool, "arguments": shown_arguments(arguments) }),
                Value::Null,
            ),
            UndoPlan::Unavailable(why) => (Value::Null, json!(why)),
        };
        json!({
            "id": self.id,
            "ts_ms": self.ts_ms,
            "agent": self.agent,
            "tool": self.tool,
            "call_id": self.call_id,
            "arguments": shown_arguments(&self.arguments),
            "result": self.result.as_ref().map(shown_arguments),
            "undo": undo,
            "cannot_undo": cannot,
            "done": self.done,
            "last_error": self.last_error,
        })
    }

    /// The request the executor gets to undo this call.
    pub fn job(&self, by: &str) -> Option<Value> {
        let UndoPlan::Call { tool, arguments } = &self.undo else {
            return None;
        };
        Some(json!({
            "kind": "undo",
            "id": self.id,
            "agent": self.agent,
            "tool": tool,
            "arguments": arguments,
            "undoes": {
                "tool": self.tool,
                "call_id": self.call_id,
                "arguments": self.arguments,
                "ts_ms": self.ts_ms,
            },
            "requested_by": by,
        }))
    }
}

/// A call found in the log, before we know whether it went through.
struct Found {
    ts_ms: u64,
    agent: String,
    tool: String,
    call_id: String,
    arguments: Value,
    ran: bool,
    result: Option<Value>,
}

/// Every call in the log that went through and that `filter` picks, newest
/// first, with how to undo it.
pub fn plan(events: &[Value], policy: Option<&Policy>, filter: &Filter) -> Vec<Step> {
    let mut found: Vec<Found> = Vec::new();
    let mut by_call: HashMap<String, Vec<usize>> = HashMap::new();
    let mut by_approval: HashMap<String, usize> = HashMap::new();
    let mut done: HashSet<String> = HashSet::new();
    let mut errors: HashMap<String, String> = HashMap::new();

    for event in events {
        match event["event"].as_str() {
            Some("tool_call") => {
                let (Some(call_id), Some(tool)) =
                    (event["call_id"].as_str(), event["tool"].as_str())
                else {
                    continue;
                };
                if event["blocked"] == true {
                    continue;
                }
                let held = event["held"] == true;
                if held {
                    match event["approval_id"].as_str() {
                        Some(approval) => {
                            by_approval.insert(approval.to_string(), found.len());
                        }
                        None => continue,
                    }
                }
                by_call
                    .entry(call_id.to_string())
                    .or_default()
                    .push(found.len());
                found.push(Found {
                    ts_ms: event["ts_ms"].as_u64().unwrap_or(0),
                    agent: event["agent"].as_str().unwrap_or("").to_string(),
                    tool: tool.to_string(),
                    call_id: call_id.to_string(),
                    arguments: event["arguments"].clone(),
                    ran: !held,
                    result: None,
                });
            }
            // An approved call reaches its waiting agent. A parked one only
            // ran once the executor says so.
            Some("approval_decided")
                if event["decision"] == "approved" && event["parked"] != true =>
            {
                if let Some(&index) = event["approval_id"]
                    .as_str()
                    .and_then(|id| by_approval.get(id))
                {
                    found[index].ran = true;
                }
            }
            Some("parked_call_ran") => {
                if let Some(&index) = event["approval_id"]
                    .as_str()
                    .and_then(|id| by_approval.get(id))
                {
                    let call = &mut found[index];
                    call.ran = true;
                    call.ts_ms = event["ts_ms"].as_u64().unwrap_or(call.ts_ms);
                    call.result = Some(event["output"].clone());
                }
            }
            Some("tool_result") => {
                let Some(list) = event["call_id"].as_str().and_then(|id| by_call.get(id)) else {
                    continue;
                };
                // Older logs have no agent on results; they match any agent.
                let agent = event["agent"].as_str();
                let latest = list.iter().rev().copied().find(|&index| {
                    let call = &found[index];
                    call.ran && call.result.is_none() && agent.is_none_or(|a| a == call.agent)
                });
                if let Some(index) = latest {
                    found[index].result = Some(decode_output(&event["output"]));
                }
            }
            Some("undo_done") => {
                if let Some(id) = event["undo_id"].as_str() {
                    done.insert(id.to_string());
                }
            }
            Some("undo_failed") => {
                if let (Some(id), Some(error)) =
                    (event["undo_id"].as_str(), event["error"].as_str())
                {
                    errors.insert(id.to_string(), error.to_string());
                }
            }
            _ => {}
        }
    }

    let mut steps: Vec<Step> = found
        .into_iter()
        .filter(|call| call.ran)
        .map(|call| {
            let id = step_id(&call.agent, &call.call_id, call.ts_ms);
            let undo = match policy {
                Some(policy) => policy.undo_for(
                    &call.agent,
                    &call.tool,
                    &call.arguments,
                    call.result.as_ref(),
                ),
                None => UndoPlan::Unavailable(
                    "no policy is loaded, so there are no undo recipes".to_string(),
                ),
            };
            Step {
                done: done.contains(&id),
                last_error: errors.get(&id).cloned(),
                id,
                ts_ms: call.ts_ms,
                agent: call.agent,
                tool: call.tool,
                call_id: call.call_id,
                arguments: call.arguments,
                result: call.result,
                undo,
            }
        })
        .filter(|step| filter.admits(step))
        .collect();
    // Newest first; the log's order breaks ties.
    steps.reverse();
    steps.sort_by_key(|step| std::cmp::Reverse(step.ts_ms));
    steps
}

/// The same call always gets the same undo id, so a step that was undone is
/// recognised the next time the plan is made.
fn step_id(agent: &str, call_id: &str, ts_ms: u64) -> String {
    let digest = Sha256::digest(format!("{agent}\n{call_id}\n{ts_ms}"));
    format!("und_{}", &hex(&digest)[..24])
}

/// A tool result as the agent sent it, decoded for an undo recipe: JSON if
/// the text is JSON, otherwise the text. Content parts are joined first.
pub fn decode_output(output: &Value) -> Value {
    let text = match output {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect::<Vec<_>>()
            .join(""),
        other => return other.clone(),
    };
    serde_json::from_str(text.trim()).unwrap_or(Value::String(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../policy/example.policy.yaml");

    fn call(ts: u64, agent: &str, id: &str, tool: &str, args: Value, extra: Value) -> Value {
        let mut event = json!({
            "event": "tool_call", "ts_ms": ts, "agent": agent, "call_id": id,
            "tool": tool, "arguments": args, "decision": "allow", "blocked": false,
        });
        for (key, value) in extra.as_object().unwrap() {
            event[key] = value.clone();
        }
        event
    }

    fn result(agent: &str, id: &str, output: Value) -> Value {
        json!({ "event": "tool_result", "agent": agent, "call_id": id, "output": output })
    }

    fn log() -> Vec<Value> {
        vec![
            call(
                100,
                "bot",
                "c1",
                "create_ticket",
                json!({ "title": "a" }),
                json!({}),
            ),
            result("bot", "c1", json!("{\"id\": 812}")),
            call(
                200,
                "bot",
                "c2",
                "db_drop",
                json!({ "database": "production" }),
                json!({ "decision": "deny", "blocked": true }),
            ),
            call(
                300,
                "bot",
                "c3",
                "grant_role",
                json!({ "user": "u1", "role": "admin" }),
                json!({ "decision": "review", "blocked": false, "held": true, "approval_id": "apr_1" }),
            ),
            json!({ "event": "approval_decided", "approval_id": "apr_1", "decision": "approved" }),
            call(
                400,
                "bot",
                "c4",
                "grant_role",
                json!({ "user": "u2", "role": "admin" }),
                json!({ "decision": "review", "blocked": false, "held": true, "approval_id": "apr_2" }),
            ),
            json!({ "event": "approval_decided", "approval_id": "apr_2", "decision": "expired" }),
            call(
                500,
                "other",
                "c1",
                "create_ticket",
                json!({ "title": "b" }),
                json!({}),
            ),
            result(
                "other",
                "c1",
                json!([{ "type": "text", "text": "{\"id\": 9}" }]),
            ),
            call(
                600,
                "bot",
                "c6",
                "db_drop",
                json!({ "database": "staging" }),
                json!({}),
            ),
        ]
    }

    fn by_agent(agent: &str) -> Filter {
        Filter {
            agent: Some(agent.into()),
            ..Filter::default()
        }
    }

    #[test]
    fn the_plan_lists_what_went_through_newest_first() {
        let policy = Policy::parse(EXAMPLE).unwrap();
        let steps = plan(&log(), Some(&policy), &by_agent("bot"));
        let tools: Vec<(&str, &str)> = steps
            .iter()
            .map(|s| (s.call_id.as_str(), s.tool.as_str()))
            .collect();
        // The blocked drop and the expired grant never ran.
        assert_eq!(
            tools,
            [
                ("c6", "db_drop"),
                ("c3", "grant_role"),
                ("c1", "create_ticket")
            ]
        );

        assert!(matches!(&steps[0].undo, UndoPlan::Unavailable(why) if why.contains("db_drop")));
        assert_eq!(
            steps[1].undo,
            UndoPlan::Call {
                tool: "revoke_role".into(),
                arguments: json!({ "user": "u1", "role": "admin" })
            }
        );
        // The ticket id comes from bot's own result, not the other agent's.
        assert_eq!(
            steps[2].undo,
            UndoPlan::Call {
                tool: "close_ticket".into(),
                arguments: json!({ "id": 812, "comment": "Closed by a Razorwire rollback." })
            }
        );
        let other = plan(&log(), Some(&policy), &by_agent("other"));
        assert!(matches!(&other[0].undo, UndoPlan::Call { arguments, .. } if arguments["id"] == 9));
    }

    #[test]
    fn steps_can_be_picked_by_time_and_id() {
        let policy = Policy::parse(EXAMPLE).unwrap();
        let all = plan(&log(), Some(&policy), &by_agent("bot"));
        let since = Filter {
            since_ms: Some(300),
            ..Filter::default()
        };
        let recent: Vec<u64> = plan(&log(), Some(&policy), &since)
            .iter()
            .map(|s| s.ts_ms)
            .collect();
        assert_eq!(recent, [600, 500, 300]);

        let one = Filter {
            ids: vec![all[1].id.clone()],
            ..Filter::default()
        };
        let picked = plan(&log(), Some(&policy), &one);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].call_id, "c3");
        assert!(is_undo_id(&picked[0].id));
        // The id is stable from one plan to the next.
        assert_eq!(plan(&log(), Some(&policy), &one)[0].id, picked[0].id);
    }

    #[test]
    fn undone_and_failed_steps_are_marked() {
        let policy = Policy::parse(EXAMPLE).unwrap();
        let first = plan(&log(), Some(&policy), &by_agent("bot"));
        let mut events = log();
        events.push(json!({ "event": "undo_done", "undo_id": first[2].id }));
        events.push(json!({ "event": "undo_failed", "undo_id": first[1].id, "error": "down" }));
        let again = plan(&events, Some(&policy), &by_agent("bot"));
        assert!(again[2].done && !again[1].done);
        assert_eq!(again[1].last_error.as_deref(), Some("down"));
        assert!(again[2].job("mann").is_some());
        assert!(again[0].job("mann").is_none());
        let job = again[1].job("mann").unwrap();
        assert_eq!(job["kind"], "undo");
        assert_eq!(job["undoes"]["tool"], "grant_role");
        assert_eq!(job["requested_by"], "mann");
    }

    #[test]
    fn a_parked_call_counts_once_the_executor_ran_it() {
        let policy = Policy::parse(EXAMPLE).unwrap();
        let mut events = vec![
            call(
                100,
                "bot",
                "c1",
                "create_ticket",
                json!({}),
                json!({ "decision": "review", "held": true, "approval_id": "apr_9" }),
            ),
            json!({ "event": "approval_decided", "approval_id": "apr_9", "decision": "parked" }),
            json!({ "event": "approval_decided", "approval_id": "apr_9", "decision": "approved", "parked": true }),
        ];
        assert!(plan(&events, Some(&policy), &by_agent("bot")).is_empty());
        events.push(json!({ "event": "parked_call_ran", "approval_id": "apr_9", "ts_ms": 900, "output": { "id": 77 } }));
        let steps = plan(&events, Some(&policy), &by_agent("bot"));
        assert_eq!(steps[0].ts_ms, 900);
        assert!(
            matches!(&steps[0].undo, UndoPlan::Call { arguments, .. } if arguments["id"] == 77)
        );
    }

    #[test]
    fn without_a_policy_nothing_can_be_undone() {
        let steps = plan(&log(), None, &by_agent("bot"));
        assert!(steps
            .iter()
            .all(|s| matches!(&s.undo, UndoPlan::Unavailable(why) if why.contains("no policy"))));
    }

    #[test]
    fn tool_output_is_decoded() {
        assert_eq!(decode_output(&json!(" {\"id\": 1} ")), json!({ "id": 1 }));
        assert_eq!(decode_output(&json!("done")), json!("done"));
        assert_eq!(
            decode_output(
                &json!([{ "type": "text", "text": "[1," }, { "type": "text", "text": "2]" }])
            ),
            json!([1, 2])
        );
        assert_eq!(decode_output(&Value::Null), Value::Null);
    }
}
