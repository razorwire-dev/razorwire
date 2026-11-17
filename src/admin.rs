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
    approvals::{clean_reason, Verdict},
    audit::{json_line, now_ms},
    auth::{self, Role},
    proxy::{is_loopback_host, json_response, refuse, refuse_unauthorized, AppState},
};

/// Largest admin request body. A reason is all an admin request carries.
const MAX_ADMIN_BODY_BYTES: usize = 16 * 1024;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/razorwire/approvals", get(list_approvals))
        .route("/razorwire/approvals/{id}/approve", post(approve))
        .route("/razorwire/approvals/{id}/deny", post(deny))
        .route("/razorwire/reload", post(reload))
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
    reply(json!({ "now_ms": now_ms(), "pending": state.approvals.list() }))
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
    match state.approvals.decide(id, verdict) {
        Some(summary) => reply(json!({
            "approval_id": id,
            "decision": if approved { "approved" } else { "denied" },
            "by": by,
            "reason": reason,
            "agent": summary["agent"],
            "tool": summary["tool"],
        })),
        None => refuse(
            StatusCode::NOT_FOUND,
            "not_pending",
            "No tool call is waiting under that id. It may have been decided already, or it timed out.",
        ),
    }
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
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
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
