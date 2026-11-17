//! Tool calls held for a human decision.
//!
//! When a `review` rule fires and someone can approve, the proxy holds the
//! provider's response and registers the call here. An admin approves or
//! denies it through the admin API. If nobody decides in time, or the agent
//! hangs up, the call is blocked.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use serde_json::{json, Value};
use tokio::sync::oneshot;

use crate::{audit::Audit, auth::hex};

/// Longest reason an approver can give, in characters.
pub const MAX_REASON_CHARS: usize = 500;

/// How much of a held call's arguments is shown to the approver.
const MAX_SHOWN_ARGUMENT_BYTES: usize = 16 * 1024;

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
    reply: oneshot::Sender<Verdict>,
}

pub struct Approvals {
    pending: Mutex<HashMap<String, Pending>>,
    limit: usize,
    audit: Arc<Audit>,
}

impl Approvals {
    pub fn new(limit: usize, audit: Arc<Audit>) -> Approvals {
        Approvals {
            pending: Mutex::new(HashMap::new()),
            limit,
            audit,
        }
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Register a call that needs a decision. `summary` is what an approver
    /// is shown; its `id` field is filled in here.
    pub fn hold(&self, mut summary: Value) -> Result<Ticket<'_>, HoldError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| HoldError::NoId)?;
        let id = format!("apr_{}", hex(&bytes));
        summary["id"] = json!(id);
        if let Some(arguments) = summary.get_mut("arguments") {
            *arguments = shown_arguments(arguments);
        }

        let (reply, wait) = oneshot::channel();
        let mut pending = self.pending();
        if pending.len() >= self.limit {
            return Err(HoldError::Full);
        }
        pending.insert(id.clone(), Pending { summary, reply });
        Ok(Ticket {
            id,
            approvals: self,
            wait: Some(wait),
        })
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
        let Some(wait) = self.wait.take() else {
            return Outcome::Expired;
        };
        let outcome = match tokio::time::timeout(timeout, wait).await {
            Ok(Ok(verdict)) => Outcome::Decided(verdict),
            Ok(Err(_)) | Err(_) => Outcome::Expired,
        };
        self.approvals.pending().remove(&self.id);
        outcome
    }
}

impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        // Still waiting means the request went away before a decision: the
        // agent hung up. The call never reaches it, but the log says so.
        if self.wait.is_none() || self.approvals.pending().remove(&self.id).is_none() {
            return;
        }
        let audit = self.approvals.audit.clone();
        let event = json!({ "event": "approval_abandoned", "approval_id": self.id });
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move { audit.record(None, event).await });
        }
    }
}

/// Arguments as an approver sees them: whole, unless they are very large.
fn shown_arguments(arguments: &Value) -> Value {
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
        Approvals::new(limit, Arc::new(audit))
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
