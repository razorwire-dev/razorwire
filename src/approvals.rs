//! Tool calls held for a human decision.
//!
//! When a `review` rule fires and someone can approve, the proxy holds the
//! provider's response and registers the call here. An admin approves or
//! denies it through the admin API. If nobody decides in time, or the agent
//! hangs up, the call is blocked.
//!
//! With an executor set up, such a call is parked instead of dropped: it can
//! still be approved for `PARK_FOR`, and approving it then has the executor
//! carry it out, since its agent is no longer waiting. Parked calls are
//! written to the audit log and read back from it after a restart.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use serde_json::{json, Value};
use tokio::sync::oneshot;

use crate::{
    audit::{now_ms, Audit},
    auth::hex,
};

/// Longest reason an approver can give, in characters.
pub const MAX_REASON_CHARS: usize = 500;

/// How much of a held call's arguments is shown to the approver.
const MAX_SHOWN_ARGUMENT_BYTES: usize = 16 * 1024;

/// How long a parked call can still be approved.
pub const PARK_FOR: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Parked calls kept at once. Beyond that, a call that times out is blocked.
const MAX_PARKED: usize = 1024;

/// A human's answer to one held call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub approved: bool,
    /// The admin key's name.
    pub by: String,
    pub reason: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Decided(Verdict),
    /// Nobody decided in time.
    Expired,
    /// Nobody decided in time, so the call was parked for a later decision.
    Parked,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HoldError {
    /// Too many calls are already waiting.
    Full,
    /// No id could be made, because the random number generator failed.
    NoId,
}

struct Pending {
    summary: Value,
    /// The call's arguments in full; the summary may shorten them.
    arguments: Value,
    reply: oneshot::Sender<Verdict>,
}

/// A call whose agent stopped waiting, kept for a later decision.
#[derive(Debug, Clone, PartialEq)]
pub struct Parked {
    /// What an approver is shown, with `parked_until_ms`.
    pub summary: Value,
    /// The call's arguments in full, for the executor.
    pub arguments: Value,
    pub until_ms: u64,
}

pub struct Approvals {
    pending: Mutex<HashMap<String, Pending>>,
    parked: Mutex<HashMap<String, Parked>>,
    limit: usize,
    /// Calls are parked only when an executor can carry them out later.
    parking: bool,
    audit: Arc<Audit>,
}

impl Approvals {
    pub fn new(limit: usize, audit: Arc<Audit>, parking: bool) -> Approvals {
        Approvals {
            pending: Mutex::new(HashMap::new()),
            parked: Mutex::new(HashMap::new()),
            limit,
            parking,
            audit,
        }
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn parked(&self) -> std::sync::MutexGuard<'_, HashMap<String, Parked>> {
        let mut parked = self.parked.lock().unwrap_or_else(PoisonError::into_inner);
        // Calls past their time are dropped, and the log says so.
        let now = now_ms();
        let expired: Vec<String> = parked
            .iter()
            .filter(|(_, call)| call.until_ms <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            parked.remove(&id);
            let event = json!({
                "event": "approval_decided",
                "approval_id": id,
                "decision": "expired",
                "parked": true,
                "blocked": true,
            });
            let audit = self.audit.clone();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move { audit.record(None, event).await });
            }
        }
        parked
    }

    /// Register a call that needs a decision. `summary` is what an approver
    /// is shown; its `id` field is filled in here.
    pub fn hold(&self, mut summary: Value) -> Result<Ticket<'_>, HoldError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| HoldError::NoId)?;
        let id = format!("apr_{}", hex(&bytes));
        summary["id"] = json!(id);
        let arguments = summary.get("arguments").cloned().unwrap_or(Value::Null);
        if let Some(shown) = summary.get_mut("arguments") {
            *shown = shown_arguments(shown);
        }

        let (reply, wait) = oneshot::channel();
        let mut pending = self.pending();
        if pending.len() >= self.limit {
            return Err(HoldError::Full);
        }
        pending.insert(
            id.clone(),
            Pending {
                summary,
                arguments,
                reply,
            },
        );
        Ok(Ticket {
            id,
            approvals: self,
            wait: Some(wait),
        })
    }

    /// Keep a call nobody decided in time for a later decision. Returns the
    /// event to log, or `None` if it cannot be parked.
    fn park(&self, id: &str, pending: Pending) -> Option<Value> {
        if !self.parking {
            return None;
        }
        let mut parked = self.parked();
        if parked.len() >= MAX_PARKED {
            return None;
        }
        let until_ms = now_ms().saturating_add(PARK_FOR.as_secs() * 1000);
        let mut summary = pending.summary;
        summary["parked_until_ms"] = json!(until_ms);
        let event = json!({
            "event": "approval_parked",
            "approval_id": id,
            "agent": summary["agent"],
            "tool": summary["tool"],
            "call_id": summary["call_id"],
            "rule": summary["rule"],
            "message": summary["message"],
            "arguments": pending.arguments,
            "created_ms": summary["created_ms"],
            "parked_until_ms": until_ms,
        });
        parked.insert(
            id.to_string(),
            Parked {
                summary,
                arguments: pending.arguments,
                until_ms,
            },
        );
        Some(event)
    }

    /// Every parked call, oldest first.
    pub fn list_parked(&self) -> Vec<Value> {
        let mut all: Vec<Value> = self
            .parked()
            .values()
            .map(|call| call.summary.clone())
            .collect();
        all.sort_by_key(|summary| summary["created_ms"].as_u64().unwrap_or(0));
        all
    }

    /// Take a parked call out to decide it. It is gone until `put_back`, so
    /// two admins cannot carry it out twice.
    pub fn take_parked(&self, id: &str) -> Option<Parked> {
        self.parked().remove(id)
    }

    /// Return a parked call whose run failed, so it can be tried again.
    pub fn put_back(&self, id: &str, call: Parked) {
        self.parked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id.to_string(), call);
    }

    /// Rebuild the parked calls from the audit log after a restart. Returns
    /// how many are still waiting.
    pub fn restore(&self, events: &[Value]) -> usize {
        if !self.parking {
            return 0;
        }
        let mut restored: HashMap<String, Parked> = HashMap::new();
        for event in events {
            let Some(id) = event["approval_id"].as_str() else {
                continue;
            };
            match event["event"].as_str() {
                Some("approval_parked") => {
                    let until_ms = event["parked_until_ms"].as_u64().unwrap_or(0);
                    let arguments = event["arguments"].clone();
                    let summary = json!({
                        "id": id,
                        "agent": event["agent"],
                        "tool": event["tool"],
                        "call_id": event["call_id"],
                        "rule": event["rule"],
                        "message": event["message"],
                        "arguments": shown_arguments(&arguments),
                        "created_ms": event["created_ms"],
                        "parked_until_ms": until_ms,
                    });
                    let call = Parked {
                        summary,
                        arguments,
                        until_ms,
                    };
                    restored.insert(id.to_string(), call);
                }
                Some("parked_call_ran") => {
                    restored.remove(id);
                }
                Some("approval_decided")
                    if event["parked"] == true && event["decision"] != "approved" =>
                {
                    restored.remove(id);
                }
                _ => {}
            }
        }
        let mut parked = self.parked.lock().unwrap_or_else(PoisonError::into_inner);
        parked.extend(restored);
        drop(parked);
        self.parked().len()
    }

    /// Every call waiting for a decision, oldest first.
    pub fn list(&self) -> Vec<Value> {
        let mut all: Vec<Value> = self
            .pending()
            .values()
            .map(|pending| pending.summary.clone())
            .collect();
        all.sort_by_key(|summary| summary["created_ms"].as_u64().unwrap_or(0));
        all
    }

    /// Decide a waiting call. Returns its summary, or `None` if no call is
    /// waiting under that id.
    pub fn decide(&self, id: &str, verdict: Verdict) -> Option<Value> {
        let pending = self.pending().remove(id)?;
        pending.reply.send(verdict).ok()?;
        Some(pending.summary)
    }
}

/// One held call. Dropping it before a decision arrives withdraws the call.
pub struct Ticket<'a> {
    pub id: String,
    approvals: &'a Approvals,
    wait: Option<oneshot::Receiver<Verdict>>,
}

impl Ticket<'_> {
    /// Wait for a decision, up to `timeout`.
    pub async fn wait(mut self, timeout: Duration) -> Outcome {
        // The receiver stays in the ticket while it waits, so a request that
        // is dropped mid-wait still counts as waiting and is withdrawn.
        let outcome = match self.wait.as_mut() {
            None => Outcome::Expired,
            Some(wait) => match tokio::time::timeout(timeout, &mut *wait).await {
                Ok(Ok(verdict)) => Outcome::Decided(verdict),
                Ok(Err(_)) => Outcome::Expired,
                // A decision may have come in just as time ran out.
                Err(_) => match wait.try_recv() {
                    Ok(verdict) => Outcome::Decided(verdict),
                    Err(_) => Outcome::Expired,
                },
            },
        };
        self.wait = None;
        let left = self.approvals.pending().remove(&self.id);
        match (outcome, left) {
            (Outcome::Expired, Some(pending)) => match self.approvals.park(&self.id, pending) {
                Some(event) => {
                    self.approvals.audit.record(None, event).await;
                    Outcome::Parked
                }
                None => Outcome::Expired,
            },
            (outcome, _) => outcome,
        }
    }
}

impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        // Still waiting means the request went away before a decision: the
        // agent hung up. The call never reaches it, but the log says so, and
        // with an executor it is parked for a later decision.
        if self.wait.is_none() {
            return;
        }
        let Some(pending) = self.approvals.pending().remove(&self.id) else {
            return;
        };
        let mut events = vec![json!({ "event": "approval_abandoned", "approval_id": self.id })];
        events.extend(self.approvals.park(&self.id, pending));
        let audit = self.approvals.audit.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                for event in events {
                    audit.record(None, event).await;
                }
            });
        }
    }
}

/// Arguments as an approver sees them: whole, unless they are very large.
pub(crate) fn shown_arguments(arguments: &Value) -> Value {
    let text = arguments.to_string();
    if text.len() <= MAX_SHOWN_ARGUMENT_BYTES {
        return arguments.clone();
    }
    let mut end = MAX_SHOWN_ARGUMENT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    json!({ "truncated": true, "bytes": text.len(), "start": &text[..end] })
}

/// Clean up a reason an approver typed: no control characters, and not too
/// long. It is shown to the model and written to the log.
pub fn clean_reason(reason: &str) -> Option<String> {
    let cleaned: String = reason
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_REASON_CHARS)
        .collect();
    let cleaned = cleaned.trim();
    (!cleaned.is_empty()).then(|| cleaned.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store(limit: usize) -> Approvals {
        let path =
            std::env::temp_dir().join(format!("razorwire-approvals-{}.jsonl", std::process::id()));
        let audit = Audit::open(&path.to_string_lossy(), None).await.unwrap();
        Approvals::new(limit, Arc::new(audit), false)
    }

    /// A store that parks calls, with its own log.
    async fn parking_store(name: &str) -> (Approvals, Arc<Audit>) {
        let path = std::env::temp_dir().join(format!(
            "razorwire-parking-{name}-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let audit = Arc::new(Audit::open(&path.to_string_lossy(), None).await.unwrap());
        (Approvals::new(10, audit.clone(), true), audit)
    }

    fn refund() -> Value {
        json!({ "agent": "bot", "tool": "stripe_refund", "arguments": { "amount": 4700 }, "created_ms": 1 })
    }

    #[tokio::test]
    async fn with_an_executor_a_call_nobody_decided_is_parked() {
        let (approvals, audit) = parking_store("expiry").await;
        let ticket = approvals.hold(refund()).unwrap();
        let id = ticket.id.clone();
        assert_eq!(
            ticket.wait(Duration::from_millis(20)).await,
            Outcome::Parked
        );
        assert!(approvals.list().is_empty());

        let parked = approvals.list_parked();
        assert_eq!(parked.len(), 1);
        assert_eq!(parked[0]["id"], id);
        assert!(parked[0]["parked_until_ms"].as_u64().unwrap() > now_ms());
        // A waiting-call decision does not reach it; it is taken out instead.
        assert!(approvals.decide(&id, verdict(true)).is_none());
        let call = approvals.take_parked(&id).unwrap();
        assert_eq!(call.arguments, json!({ "amount": 4700 }));
        assert!(approvals.take_parked(&id).is_none());
        approvals.put_back(&id, call);
        assert_eq!(approvals.list_parked().len(), 1);

        let events = audit.events().await.unwrap();
        assert!(events.iter().any(|e| e["event"] == "approval_parked"
            && e["approval_id"] == id
            && e["arguments"]["amount"] == 4700));
    }

    #[tokio::test]
    async fn a_call_whose_agent_hung_up_is_parked_too() {
        let (approvals, audit) = parking_store("hang-up").await;
        let ticket = approvals.hold(refund()).unwrap();
        let id = ticket.id.clone();
        let cut_short = tokio::time::timeout(
            Duration::from_millis(20),
            ticket.wait(Duration::from_secs(60)),
        )
        .await;
        assert!(cut_short.is_err());
        assert_eq!(approvals.list_parked()[0]["id"], id);
        // The log entries are written by a task of their own.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let names: Vec<String> = audit
            .events()
            .await
            .unwrap()
            .iter()
            .filter_map(|e| e["event"].as_str().map(str::to_owned))
            .collect();
        assert_eq!(names, ["approval_abandoned", "approval_parked"]);
    }

    #[tokio::test]
    async fn parked_calls_come_back_after_a_restart() {
        let (approvals, _) = parking_store("restore").await;
        let later = now_ms() + 60_000;
        let parked = |id: &str, until: u64| {
            json!({ "event": "approval_parked", "approval_id": id, "tool": "stripe_refund",
                    "arguments": { "amount": 900 }, "parked_until_ms": until })
        };
        let events = [
            parked("apr_open", later),
            parked("apr_ran", later),
            parked("apr_denied", later),
            parked("apr_old", 1),
            json!({ "event": "approval_decided", "approval_id": "apr_open", "decision": "parked" }),
            json!({ "event": "parked_call_ran", "approval_id": "apr_ran" }),
            json!({ "event": "approval_decided", "approval_id": "apr_denied", "decision": "denied", "parked": true }),
        ];
        assert_eq!(approvals.restore(&events), 1);
        let call = approvals.take_parked("apr_open").unwrap();
        assert_eq!(call.arguments["amount"], 900);
        assert_eq!(call.until_ms, later);

        // Without an executor nothing is parked or restored.
        assert_eq!(store(10).await.restore(&events), 0);
    }

    fn verdict(approved: bool) -> Verdict {
        Verdict {
            approved,
            by: "mann".into(),
            reason: None,
        }
    }

    #[tokio::test]
    async fn a_decision_reaches_the_waiting_call() {
        let approvals = store(10).await;
        let ticket = approvals
            .hold(json!({ "tool": "stripe_refund", "created_ms": 1 }))
            .unwrap();
        let id = ticket.id.clone();
        assert!(id.starts_with("apr_") && id.len() == 4 + 32);
        assert_eq!(approvals.list()[0]["id"], id);

        let summary = approvals.decide(&id, verdict(true)).unwrap();
        assert_eq!(summary["tool"], "stripe_refund");
        assert_eq!(
            ticket.wait(Duration::from_secs(5)).await,
            Outcome::Decided(verdict(true))
        );
        assert!(approvals.list().is_empty());
        // A call can only be decided once.
        assert!(approvals.decide(&id, verdict(false)).is_none());
    }

    #[tokio::test]
    async fn an_undecided_call_expires_and_is_withdrawn() {
        let approvals = store(10).await;
        let ticket = approvals.hold(json!({})).unwrap();
        let id = ticket.id.clone();

        let outcome = ticket.wait(Duration::from_millis(20)).await;

        assert_eq!(outcome, Outcome::Expired);
        assert!(approvals.list().is_empty());
        assert!(approvals.decide(&id, verdict(true)).is_none());
    }

    #[tokio::test]
    async fn a_call_whose_agent_hung_up_is_withdrawn() {
        let approvals = store(10).await;
        let ticket = approvals.hold(json!({})).unwrap();
        let id = ticket.id.clone();
        drop(ticket);
        assert!(approvals.list().is_empty());
        assert!(approvals.decide(&id, verdict(true)).is_none());
    }

    #[tokio::test]
    async fn a_call_dropped_while_it_waits_is_withdrawn() {
        let approvals = store(10).await;
        let ticket = approvals.hold(json!({})).unwrap();
        let id = ticket.id.clone();
        // The request is dropped in the middle of its wait.
        let cut_short = tokio::time::timeout(
            Duration::from_millis(20),
            ticket.wait(Duration::from_secs(60)),
        )
        .await;
        assert!(cut_short.is_err());
        assert!(approvals.list().is_empty());
        assert!(approvals.decide(&id, verdict(true)).is_none());
    }

    #[tokio::test]
    async fn the_number_of_waiting_calls_is_capped() {
        let approvals = store(2).await;
        let first = approvals.hold(json!({})).unwrap();
        let _second = approvals.hold(json!({})).unwrap();
        assert_eq!(approvals.hold(json!({})).err(), Some(HoldError::Full));
        drop(first);
        assert!(approvals.hold(json!({})).is_ok());
    }

    #[tokio::test]
    async fn huge_arguments_are_shortened_for_the_approver() {
        let approvals = store(10).await;
        let big = json!({ "body": "é".repeat(20_000) });
        let _ticket = approvals.hold(json!({ "arguments": big })).unwrap();
        let shown = &approvals.list()[0]["arguments"];
        assert_eq!(shown["truncated"], true);
        assert!(shown["start"].as_str().unwrap().len() <= MAX_SHOWN_ARGUMENT_BYTES);
    }

    #[test]
    fn reasons_are_cleaned() {
        assert_eq!(
            clean_reason("  too big\n\u{1b}[31m "),
            Some("too big  [31m".into())
        );
        assert_eq!(clean_reason(" \n "), None);
        assert_eq!(
            clean_reason(&"x".repeat(900)).unwrap().chars().count(),
            MAX_REASON_CHARS
        );
    }
}
