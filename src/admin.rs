//! The admin API, under `/razorwire/`, and the commands that call it.
//!
//! Every admin request needs an admin key. Agent keys are refused, so an
//! agent cannot approve its own held calls even if it can reach the proxy.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};

use crate::{
    approvals::{clean_reason, Parked, Verdict},
    audit::{json_line, now_ms},
    auth::{self, Role},
    policy::UndoPlan,
    proxy::{is_loopback_host, json_response, refuse, refuse_unauthorized, AppState},
    rollback::{self, Filter},
};

/// Largest admin request body. A reason or a list of undo ids is all an
/// admin request carries.
const MAX_ADMIN_BODY_BYTES: usize = 16 * 1024;

const NO_EXECUTOR: &str = "No executor is set up, so Razorwire cannot carry out actions itself. \
     Run one (see examples/executor.py), set EXECUTOR_URL and EXECUTOR_KEY, and restart Razorwire.";

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/razorwire/approvals", get(list_approvals))
        .route("/razorwire/approvals/{id}/approve", post(approve))
        .route("/razorwire/approvals/{id}/deny", post(deny))
        .route("/razorwire/reload", post(reload))
        .route("/razorwire/rollback", post(rollback))
        .layer(DefaultBodyLimit::max(MAX_ADMIN_BODY_BYTES))
}

/// Check the admin key on a request and return the admin's name.
async fn admin(
    state: &AppState,
    peer: SocketAddr,
    path: &str,
    headers: &HeaderMap,
) -> Result<String, Box<Response>> {
    let config = state.config();
    if config.keys.count(Role::Admin) == 0 {
        return Err(Box::new(refuse(
            StatusCode::FORBIDDEN,
            "admin_disabled",
            "No admin keys are set up. Create one with `razorwire new-key admin <name>`, set KEYS_FILE, and restart Razorwire.",
        )));
    }
    let identity = auth::presented_key(headers).map(|key| config.keys.identify(key));
    let (reason, refusal) = match identity {
        Some(Some(identity)) if identity.role == Role::Admin => return Ok(identity.name.clone()),
        None => (
            "admin request with no key",
            refuse_unauthorized(
                "missing_key",
                "The admin API needs an admin key in `Authorization: Bearer rw_...`.",
            ),
        ),
        Some(Some(_)) => (
            "an agent key was used on the admin API",
            refuse(
                StatusCode::FORBIDDEN,
                "wrong_key_role",
                "This is an agent key. The admin API needs an admin key.",
            ),
        ),
        Some(None) => (
            "unknown admin key",
            refuse_unauthorized("invalid_key", "This Razorwire key is not valid."),
        ),
    };
    state.auth_failed(None, peer, path, reason).await;
    Err(Box::new(refusal))
}

fn reply(body: Value) -> Response {
    json_response(StatusCode::OK, &body)
}

async fn list_approvals(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Err(refusal) = admin(&state, peer, "/razorwire/approvals", &headers).await {
        return *refusal;
    }
    reply(json!({
        "now_ms": now_ms(),
        "pending": state.approvals.list(),
        "parked": state.approvals.list_parked(),
    }))
}

async fn approve(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    decide(&state, peer, &id, &headers, &body, true).await
}

async fn deny(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    decide(&state, peer, &id, &headers, &body, false).await
}

async fn decide(
    state: &AppState,
    peer: SocketAddr,
    id: &str,
    headers: &HeaderMap,
    body: &[u8],
    approved: bool,
) -> Response {
    let by = match admin(state, peer, "/razorwire/approvals", headers).await {
        Ok(name) => name,
        Err(refusal) => return *refusal,
    };
    let reason = match read_reason(body) {
        Ok(reason) => reason,
        Err(message) => return refuse(StatusCode::BAD_REQUEST, "bad_request", message),
    };
    let verdict = Verdict {
        approved,
        by: by.clone(),
        reason: reason.clone(),
    };
    if let Some(summary) = state.approvals.decide(id, verdict.clone()) {
        return reply(json!({
            "approval_id": id,
            "decision": if approved { "approved" } else { "denied" },
            "by": by,
            "reason": reason,
            "agent": summary["agent"],
            "tool": summary["tool"],
        }));
    }
    match state.approvals.take_parked(id) {
        Some(call) => decide_parked(state, id, call, verdict).await,
        None => refuse(
            StatusCode::NOT_FOUND,
            "not_pending",
            "No tool call is waiting under that id. It may have been decided already, or it timed out.",
        ),
    }
}

/// Decide a parked call. Its agent is gone, so an approved one is carried
/// out by the executor. If that fails, the call stays parked.
async fn decide_parked(state: &AppState, id: &str, call: Parked, verdict: Verdict) -> Response {
    let Verdict {
        approved,
        by,
        reason,
    } = verdict;
    let mut answer = json!({
        "approval_id": id,
        "decision": if approved { "approved" } else { "denied" },
        "by": by,
        "reason": reason,
        "agent": call.summary["agent"],
        "tool": call.summary["tool"],
        "parked": true,
    });
    let decided = json!({
        "event": "approval_decided",
        "approval_id": id,
        "decision": if approved { "approved" } else { "denied" },
        "by": by,
        "reason": reason,
        "parked": true,
        "blocked": !approved,
    });
    if !approved {
        state.record(None, decided).await;
        return reply(answer);
    }
    let Some(executor) = &state.executor else {
        state.approvals.put_back(id, call);
        return refuse(StatusCode::CONFLICT, "no_executor", NO_EXECUTOR);
    };
    state.record(None, decided).await;
    let job = json!({
        "kind": "call",
        "id": id,
        "agent": call.summary["agent"],
        "tool": call.summary["tool"],
        "call_id": call.summary["call_id"],
        "arguments": call.arguments,
        "approved_by": by,
        "reason": reason,
    });
    match executor.run(&job).await {
        Ok(output) => {
            let event = json!({
                "event": "parked_call_ran",
                "approval_id": id,
                "by": by,
                "tool": call.summary["tool"],
                "output": output,
            });
            state.record(None, event).await;
            answer["ran"] = json!(true);
            answer["output"] = output;
            reply(answer)
        }
        Err(error) => {
            state.approvals.put_back(id, call);
            let event = json!({
                "event": "parked_call_failed",
                "approval_id": id,
                "by": by,
                "error": error,
            });
            state.record(None, event).await;
            let message = format!(
                "The executor could not carry it out: {error}. The call stays parked; approve it again to retry."
            );
            refuse(StatusCode::BAD_GATEWAY, "executor_failed", &message)
        }
    }
}

/// What a rollback request asks for.
fn read_rollback(body: &[u8]) -> Result<(Filter, bool), String> {
    let usage = "The body must be JSON like {\"agent\": \"support-bot\", \"since_secs\": 3600, \"ids\": [\"und_...\"], \"run\": false}.";
    let value: Value = if body.iter().all(u8::is_ascii_whitespace) {
        json!({})
    } else {
        serde_json::from_slice(body).map_err(|_| usage.to_string())?
    };
    let Some(fields) = value.as_object() else {
        return Err(usage.into());
    };
    let mut filter = Filter::default();
    for (key, item) in fields {
        match (key.as_str(), item) {
            (_, Value::Null) => {}
            ("agent", Value::String(agent)) if !agent.is_empty() && agent.len() <= 128 => {
                filter.agent = Some(agent.clone());
            }
            ("since_ms", item) if item.is_u64() => filter.since_ms = item.as_u64(),
            ("since_secs", item) if item.is_u64() => {
                let secs = item.as_u64().unwrap_or(0);
                filter.since_ms = Some(now_ms().saturating_sub(secs.saturating_mul(1000)));
            }
            ("ids", Value::Array(ids)) if ids.len() <= rollback::MAX_IDS => {
                for id in ids {
                    match id.as_str() {
                        Some(id) if rollback::is_undo_id(id) => filter.ids.push(id.to_string()),
                        _ => {
                            return Err("Each id must look like und_ and 24 hex characters.".into())
                        }
                    }
                }
            }
            ("run", Value::Bool(_)) => {}
            _ => return Err(usage.into()),
        }
    }
    if filter.is_empty() {
        return Err(
            "Say what to roll back: an agent, a start time, or undo ids. \
                    Everything ever done cannot be rolled back in one request."
                .into(),
        );
    }
    Ok((filter, value["run"] == true))
}

/// `POST /razorwire/rollback`: show what would be undone, or with
/// `"run": true`, undo it, newest first, stopping at the first failure.
async fn rollback(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let by = match admin(&state, peer, "/razorwire/rollback", &headers).await {
        Ok(name) => name,
        Err(refusal) => return *refusal,
    };
    let (filter, run) = match read_rollback(&body) {
        Ok(request) => request,
        Err(message) => return refuse(StatusCode::BAD_REQUEST, "bad_request", &message),
    };
    if run && state.executor.is_none() {
        return refuse(StatusCode::CONFLICT, "no_executor", NO_EXECUTOR);
    }
    // A run makes its plan under the lock, so two rollbacks never undo the
    // same step.
    let _running = match run.then(|| state.rollback_lock.try_lock()) {
        Some(Err(_)) => {
            return refuse(
                StatusCode::CONFLICT,
                "rollback_running",
                "Another rollback is running. Wait for it to finish, then look again.",
            )
        }
        guard => guard,
    };
    let events = match state.audit.events().await {
        Ok(events) => events,
        Err(message) => return refuse(StatusCode::CONFLICT, "log_unreadable", &message),
    };
    let config = state.config();
    let steps = rollback::plan(&events, config.policy.as_deref(), &filter);
    let Some(executor) = state.executor.as_ref().filter(|_| run) else {
        let steps: Vec<Value> = steps.iter().map(rollback::Step::summary).collect();
        return reply(json!({ "run": false, "now_ms": now_ms(), "steps": steps }));
    };

    let started = json!({
        "event": "rollback_started",
        "by": by,
        "filter": filter.as_json(),
        "steps": steps.len(),
    });
    state.record(None, started).await;
    let (mut undone, mut failed) = (0, false);
    let mut shown = Vec::with_capacity(steps.len());
    for step in &steps {
        let mut summary = step.summary();
        let outcome = if failed {
            "not_tried"
        } else if step.done {
            "already_undone"
        } else if let (Some(job), UndoPlan::Call { tool, arguments }) = (step.job(&by), &step.undo)
        {
            let event = json!({
                "event": "undo_started",
                "undo_id": step.id,
                "by": by,
                "agent": step.agent,
                "tool": tool,
                "arguments": arguments,
                "undoes": { "tool": step.tool, "call_id": step.call_id },
            });
            state.record(None, event).await;
            match executor.run(&job).await {
                Ok(output) => {
                    let event = json!({ "event": "undo_done", "undo_id": step.id, "by": by, "output": output });
                    state.record(None, event).await;
                    summary["output"] = output;
                    undone += 1;
                    "undone"
                }
                Err(error) => {
                    let event = json!({ "event": "undo_failed", "undo_id": step.id, "by": by, "error": error });
                    state.record(None, event).await;
                    summary["error"] = json!(error);
                    failed = true;
                    "failed"
                }
            }
        } else {
            "cannot_undo"
        };
        summary["outcome"] = json!(outcome);
        shown.push(summary);
    }
    let finished = json!({
        "event": "rollback_finished",
        "by": by,
        "undone": undone,
        "failed": failed,
    });
    state.record(None, finished).await;
    reply(
        json!({ "run": true, "now_ms": now_ms(), "undone": undone, "failed": failed, "steps": shown }),
    )
}

/// The optional `{"reason": "..."}` body of an approve or deny request.
fn read_reason(body: &[u8]) -> Result<Option<String>, &'static str> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| "The body must be JSON like {\"reason\": \"...\"}.")?;
    match value.get("reason") {
        None | Some(Value::Null) if value.is_object() => Ok(None),
        Some(Value::String(reason)) => Ok(clean_reason(reason)),
        _ => Err("The body must be JSON like {\"reason\": \"...\"}."),
    }
}

async fn reload(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let by = match admin(&state, peer, "/razorwire/reload", &headers).await {
        Ok(name) => name,
        Err(refusal) => return *refusal,
    };
    match state.reload() {
        Ok(summary) => {
            let event = json!({ "event": "config_reloaded", "by": by, "config": summary });
            state.record(None, event).await;
            reply(json!({ "reloaded": true, "config": summary }))
        }
        Err(error) => {
            let event = json!({ "event": "reload_failed", "by": by, "error": error });
            state.record(None, event).await;
            let message = format!("Nothing was changed: {error}");
            refuse(StatusCode::UNPROCESSABLE_ENTITY, "reload_failed", &message)
        }
    }
}

/// Show text that came from an agent or a model safely in a terminal.
fn shown(text: &str) -> String {
    let quoted = json_line(&Value::String(text.to_string()));
    quoted[1..quoted.len() - 1].to_string()
}

fn shown_value(value: &Value) -> String {
    match value {
        Value::String(text) => shown(text),
        Value::Null => "-".to_string(),
        other => json_line(other),
    }
}

/// A client for the admin API, used by `razorwire approvals`, `approve`,
/// `deny` and `reload`.
pub struct Client {
    http: reqwest::Client,
    base: String,
    key: String,
}

impl Client {
    /// Built from `RAZORWIRE_URL` and `RAZORWIRE_ADMIN_KEY`. An admin key is
    /// only sent over plain http to this machine.
    pub fn from_env() -> Result<Client, String> {
        let base =
            std::env::var("RAZORWIRE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
        let url = reqwest::Url::parse(base.trim())
            .map_err(|_| "RAZORWIRE_URL is not a valid URL".to_string())?;
        let local = url.host_str().is_some_and(is_loopback_host);
        match url.scheme() {
            "https" => {}
            "http" if local => {}
            _ => {
                return Err(
                    "RAZORWIRE_URL must use https unless it points at this machine, \
                            or the admin key would cross the network unencrypted"
                        .into(),
                )
            }
        }
        let key = std::env::var("RAZORWIRE_ADMIN_KEY").unwrap_or_default();
        let key = key.trim().to_string();
        if !key.starts_with(auth::KEY_PREFIX) {
            return Err("Set RAZORWIRE_ADMIN_KEY to an admin key. Create one with `razorwire new-key admin <name>`".into());
        }
        let mut http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none());
        // A self-signed certificate is trusted only when named here.
        if let Some(path) = std::env::var("RAZORWIRE_CA_CERT")
            .ok()
            .filter(|path| !path.trim().is_empty())
        {
            let path = path.trim();
            let pem = std::fs::read(path)
                .map_err(|err| format!("cannot read RAZORWIRE_CA_CERT {path}: {err}"))?;
            let certificate = reqwest::Certificate::from_pem(&pem)
                .map_err(|_| format!("RAZORWIRE_CA_CERT {path} is not a PEM certificate"))?;
            http = http.add_root_certificate(certificate);
        }
        let http = http
            .build()
            .map_err(|err| format!("cannot build the HTTP client: {err}"))?;
        Ok(Client {
            http,
            base: base.trim().trim_end_matches('/').to_string(),
            key,
        })
    }

    async fn call(&self, post: bool, path: &str, body: Option<Value>) -> Result<Value, String> {
        let url = format!("{}{path}", self.base);
        let request = if post {
            self.http.post(&url)
        } else {
            self.http.get(&url)
        };
        let mut request = request.bearer_auth(&self.key);
        if let Some(body) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_string());
        }
        let response = request
            .send()
            .await
            .map_err(|err| format!("cannot reach Razorwire at {}: {err}", self.base))?;
        let status = response.status();
        let not_json = || format!("Razorwire answered {status} with something that is not JSON");
        let bytes = response.bytes().await.map_err(|_| not_json())?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| not_json())?;
        if status.is_success() {
            Ok(value)
        } else {
            let message = value["error"]["message"]
                .as_str()
                .unwrap_or("no reason given");
            Err(format!("Razorwire said no ({status}): {}", shown(message)))
        }
    }

    pub async fn approvals(&self) -> Result<(), String> {
        let answer = self.call(false, "/razorwire/approvals", None).await?;
        let now = answer["now_ms"].as_u64().unwrap_or_else(now_ms);
        let pending = answer["pending"].as_array().cloned().unwrap_or_default();
        let parked = answer["parked"].as_array().cloned().unwrap_or_default();
        if !parked.is_empty() {
            let count = parked.len();
            println!(
                "{count} parked call{}: nobody decided in time and the agent stopped waiting. \
                 Approving one has the executor carry it out now.\n",
                if count == 1 { "" } else { "s" }
            );
            for call in &parked {
                let left = call["parked_until_ms"]
                    .as_u64()
                    .unwrap_or(now)
                    .saturating_sub(now)
                    / 1000;
                println!(
                    "  {}  {}  agent: {}  rule: {}  {}d {}h left",
                    shown_value(&call["id"]),
                    shown_value(&call["tool"]),
                    shown_value(&call["agent"]),
                    shown_value(&call["rule"]),
                    left / 86_400,
                    left % 86_400 / 3600,
                );
                println!("      arguments: {}", json_line(&call["arguments"]));
                println!("      why held:  {}\n", shown_value(&call["message"]));
            }
        }
        if pending.is_empty() {
            println!("No tool calls are waiting for approval.");
            return Ok(());
        }
        let count = pending.len();
        println!(
            "{count} tool call{} waiting for approval:\n",
            if count == 1 { " is" } else { "s are" }
        );
        for call in &pending {
            let left = call["expires_ms"]
                .as_u64()
                .unwrap_or(now)
                .saturating_sub(now)
                / 1000;
            println!(
                "  {}  {}  agent: {}  rule: {}  {}m {:02}s left",
                shown_value(&call["id"]),
                shown_value(&call["tool"]),
                shown_value(&call["agent"]),
                shown_value(&call["rule"]),
                left / 60,
                left % 60,
            );
            println!("      arguments: {}", json_line(&call["arguments"]));
            println!("      why held:  {}\n", shown_value(&call["message"]));
        }
        println!(
            "Approve with `razorwire approve <id>`, or deny with `razorwire deny <id> [reason]`."
        );
        Ok(())
    }

    pub async fn decide(
        &self,
        id: &str,
        approve: bool,
        reason: Option<String>,
    ) -> Result<(), String> {
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err("That is not an approval id. Run `razorwire approvals` to see them".into());
        }
        let action = if approve { "approve" } else { "deny" };
        let body = reason.map(|reason| json!({ "reason": reason }));
        let path = format!("/razorwire/approvals/{id}/{action}");
        let answer = self.call(true, &path, body).await?;
        let verb = if approve { "Approved" } else { "Denied" };
        println!(
            "{verb} {}: {} for agent {}.",
            shown(id),
            shown_value(&answer["tool"]),
            shown_value(&answer["agent"]),
        );
        if answer["ran"] == true {
            println!(
                "It was parked, so the executor carried it out. It answered: {}",
                json_line(&answer["output"])
            );
        }
        Ok(())
    }

    /// Show what a rollback would undo, or with `run`, undo it.
    pub async fn rollback(&self, filter: Value, run: bool) -> Result<(), String> {
        let mut body = filter;
        body["run"] = json!(run);
        let answer = self.call(true, "/razorwire/rollback", Some(body)).await?;
        let now = answer["now_ms"].as_u64().unwrap_or_else(now_ms);
        let steps = answer["steps"].as_array().cloned().unwrap_or_default();
        if steps.is_empty() {
            println!("No actions that went through match, so there is nothing to roll back.");
            return Ok(());
        }
        let can = |step: &&Value| step["undo"].is_object() && step["done"] != true;
        if !run {
            let count = steps.len();
            println!(
                "{count} action{} went through, newest first:\n",
                if count == 1 { "" } else { "s" }
            );
            for step in &steps {
                print_step(step, now);
            }
            let undoable = steps.iter().filter(can).count();
            if undoable == 0 {
                println!("None of them can be undone automatically.");
            } else {
                println!(
                    "Nothing was undone yet. To undo the {undoable} that can be, newest first, run the same command with --run."
                );
            }
            return Ok(());
        }
        for step in &steps {
            let outcome = step["outcome"].as_str().unwrap_or("");
            let label = match outcome {
                "undone" => "undone      ",
                "already_undone" => "was undone  ",
                "cannot_undo" => "cannot undo ",
                "failed" => "FAILED      ",
                _ => "not tried   ",
            };
            let detail = match outcome {
                "undone" | "failed" | "already_undone" => format!(
                    "{} {}",
                    shown_value(&step["undo"]["tool"]),
                    json_line(&step["undo"]["arguments"])
                ),
                "cannot_undo" => shown_value(&step["cannot_undo"]),
                _ => String::new(),
            };
            println!(
                "  {label} {}  {}  {detail}",
                shown_value(&step["id"]),
                shown_value(&step["tool"]),
            );
            if outcome == "failed" {
                println!("               {}", shown_value(&step["error"]));
            }
        }
        let undone = answer["undone"].as_u64().unwrap_or(0);
        if answer["failed"] == true {
            return Err(format!(
                "undid {undone}, then one failed. Older actions were left as they are. \
                 Fix the problem and run it again: what was undone is skipped"
            ));
        }
        println!("\nUndid {undone}.");
        Ok(())
    }

    pub async fn reload(&self) -> Result<(), String> {
        let answer = self.call(true, "/razorwire/reload", None).await?;
        let config = &answer["config"];
        let policy = match config["policy"].as_object() {
            Some(policy) => format!(
                "{} rules, {}",
                policy.get("rules").map(shown_value).unwrap_or_default(),
                policy.get("mode").map(shown_value).unwrap_or_default()
            ),
            None => "none".to_string(),
        };
        println!(
            "Reloaded. Policy: {policy}. Keys: {} agent, {} admin.",
            shown_value(&config["agent_keys"]),
            shown_value(&config["admin_keys"]),
        );
        Ok(())
    }
}

fn print_step(step: &Value, now: u64) {
    let ago = now.saturating_sub(step["ts_ms"].as_u64().unwrap_or(now)) / 1000;
    let ago = match ago {
        0..=119 => format!("{ago}s ago"),
        120..=7199 => format!("{}m ago", ago / 60),
        7200..=172_799 => format!("{}h ago", ago / 3600),
        _ => format!("{}d ago", ago / 86_400),
    };
    println!(
        "  {}  {ago}  {}  agent: {}",
        shown_value(&step["id"]),
        shown_value(&step["tool"]),
        shown_value(&step["agent"]),
    );
    println!("      did:   {}", json_line(&step["arguments"]));
    if step["done"] == true {
        println!("      undone already");
    } else if step["undo"].is_object() {
        println!(
            "      undo:  {} {}",
            shown_value(&step["undo"]["tool"]),
            json_line(&step["undo"]["arguments"])
        );
    } else {
        println!(
            "      cannot be undone: {}",
            shown_value(&step["cannot_undo"])
        );
    }
    if let Some(error) = step["last_error"].as_str() {
        println!("      last try failed: {}", shown(error));
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reason_is_optional_and_cleaned() {
        assert_eq!(read_reason(b""), Ok(None));
        assert_eq!(read_reason(b"  \n"), Ok(None));
        assert_eq!(read_reason(b"{}"), Ok(None));
        assert_eq!(read_reason(br#"{"reason": null}"#), Ok(None));
        assert_eq!(
            read_reason(br#"{"reason": " wrong order\u001b[0m "}"#),
            Ok(Some("wrong order [0m".to_string()))
        );
        assert!(read_reason(b"not json").is_err());
        assert!(read_reason(br#"{"reason": 5}"#).is_err());
        assert!(read_reason(br#"["reason"]"#).is_err());
    }

    #[test]
    fn agent_text_cannot_drive_the_terminal() {
        let sneaky = "refund\u{1b}]0;owned\u{7}\u{9b}31m\u{202e}";
        let safe = shown(sneaky);
        assert!(safe.chars().all(|c| !c.is_control()), "{safe}");
        assert!(safe.is_ascii());
        assert!(safe.starts_with("refund"));
    }
}
