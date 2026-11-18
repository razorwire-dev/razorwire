//! Forwarding agent requests to the provider, and policing what comes back.
//!
//! The agent points its SDK at this proxy instead of the provider. Requests
//! are forwarded unchanged apart from keys. In the provider's response, each
//! tool call the model asks for is checked against the policy, and a blocked
//! call is removed before the agent sees it. A call a `review` rule holds
//! waits here until a human approves or denies it.

use std::{
    collections::HashSet,
    convert::Infallible,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex as StdMutex, PoisonError, RwLock,
    },
    time::Duration,
};

use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    response::Response,
};
use futures_util::{future::join_all, stream};
use serde_json::{json, Value};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use crate::{
    approvals::{Approvals, HoldError, Outcome},
    audit::{now_ms, Audit},
    auth::{self, Keys, Role},
    executor::Executor,
    openai,
    policy::{Mode, Policy},
    sse::{self, Captured, StreamCapture},
};

/// Largest request body the proxy accepts. Chat requests can carry images.
pub const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Largest streamed response that is held back to be checked.
const MAX_STREAM_BYTES: usize = 32 * 1024 * 1024;

/// How many tool-result ids are remembered before the set is reset.
const MAX_SEEN_RESULTS: usize = 100_000;

/// Requests handled at once. More are turned away rather than queued.
const MAX_IN_FLIGHT: usize = 512;

/// Tool calls that can wait for approval at once.
pub const MAX_PENDING_APPROVALS: usize = 256;

/// Longest the provider may go quiet before the request is given up.
const UPSTREAM_READ_TIMEOUT: Duration = Duration::from_secs(600);

/// Failed key checks written to the audit log per minute. The rest are
/// counted, so a flood of bad keys cannot fill the disk.
const MAX_LOGGED_FAILURES_PER_MINUTE: u32 = 20;

/// Header an agent uses to say who it is when no agent keys are set up.
/// With agent keys, the name comes from the key and this header is ignored.
pub const AGENT_HEADER: &str = "x-agent-name";

/// Request headers that are not forwarded. `accept-encoding` is dropped so the
/// provider answers uncompressed and the response can be inspected.
const SKIP_REQUEST_HEADERS: [&str; 12] = [
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "accept-encoding",
    AGENT_HEADER,
];

/// Response headers that are not passed back. The body is re-framed here.
const SKIP_RESPONSE_HEADERS: [&str; 6] = [
    "content-length",
    "connection",
    "keep-alive",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Settings read once at startup.
pub struct Settings {
    pub upstream: String,
    /// `Authorization` value sent to the provider in place of whatever the
    /// agent sent. When set, agents never hold the provider key.
    pub upstream_key: Option<HeaderValue>,
    /// The proxy listens on this machine only.
    pub loopback: bool,
    pub policy_path: Option<String>,
    pub keys_path: Option<String>,
    pub approval_timeout: Duration,
    /// Under an enforced policy, send a streamed reply's text on as it
    /// arrives and hold back only from the first tool call. Off, the whole
    /// stream is held until it has been checked.
    pub live_streams: bool,
}

/// What `razorwire reload` can change.
pub struct Config {
    pub policy: Option<Arc<Policy>>,
    pub keys: Keys,
}

impl Config {
    pub fn summary(&self) -> Value {
        json!({
            "policy": self.policy.as_ref().map(|policy| json!({
                "rules": policy.rule_count(),
                "undo": policy.undo_count(),
                "mode": match policy.mode() { Mode::Enforce => "enforce", Mode::Shadow => "shadow" },
            })),
            "agent_keys": self.keys.count(Role::Agent),
            "admin_keys": self.keys.count(Role::Admin),
        })
    }
}

#[derive(Default)]
struct FailureWindow {
    start_ms: u64,
    logged: u32,
    suppressed: u64,
}

pub struct AppState {
    client: reqwest::Client,
    pub settings: Settings,
    config: RwLock<Arc<Config>>,
    pub audit: Arc<Audit>,
    pub approvals: Approvals,
    /// Carries out undos and parked calls. `None` if none is set up.
    pub executor: Option<Executor>,
    /// One rollback runs at a time.
    pub rollback_lock: Mutex<()>,
    /// Tool results already recorded. Agents resend the whole conversation on
    /// every request, so without this each result would be logged many times.
    seen_results: Mutex<HashSet<String>>,
    next_request_id: AtomicU64,
    in_flight: Arc<Semaphore>,
    failures: StdMutex<FailureWindow>,
}

impl AppState {
    pub fn new(
        settings: Settings,
        config: Config,
        audit: Arc<Audit>,
        executor: Option<Executor>,
    ) -> Result<AppState, String> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(UPSTREAM_READ_TIMEOUT)
            // A redirect is passed back to the agent, never followed with the
            // provider key attached.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| format!("cannot build the HTTP client: {err}"))?;
        Ok(AppState {
            client,
            settings,
            config: RwLock::new(Arc::new(config)),
            approvals: Approvals::new(MAX_PENDING_APPROVALS, audit.clone(), executor.is_some()),
            audit,
            executor,
            rollback_lock: Mutex::new(()),
            seen_results: Mutex::new(HashSet::new()),
            next_request_id: AtomicU64::new(1),
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            failures: StdMutex::new(FailureWindow::default()),
        })
    }

    /// The configuration as it is now. A request keeps the one it started
    /// with, even if a reload happens meanwhile.
    pub fn config(&self) -> Arc<Config> {
        self.config
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Read the policy and keys files again. If either is invalid, nothing
    /// changes.
    pub fn reload(&self) -> Result<Value, String> {
        let policy = match &self.settings.policy_path {
            Some(path) => Some(Arc::new(Policy::load(path).map_err(|err| err.to_string())?)),
            None => None,
        };
        let keys = match &self.settings.keys_path {
            Some(path) => Keys::load(path).map_err(|err| err.to_string())?,
            None => Keys::default(),
        };
        check_exposure(self.settings.loopback, &keys)?;
        let config = Config { policy, keys };
        let summary = config.summary();
        *self.config.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(config);
        Ok(summary)
    }

    pub async fn record(&self, request_id: Option<u64>, event: Value) {
        self.audit.record(request_id, event).await;
    }

    /// Log a request that was turned away for its key. Never logs the key.
    pub async fn auth_failed(
        &self,
        request_id: Option<u64>,
        peer: SocketAddr,
        path: &str,
        reason: &str,
    ) {
        let now = now_ms();
        let (log, suppressed) = {
            let mut window = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
            let mut suppressed = 0;
            if now.saturating_sub(window.start_ms) >= 60_000 {
                suppressed = window.suppressed;
                *window = FailureWindow {
                    start_ms: now,
                    ..FailureWindow::default()
                };
            }
            let log = window.logged < MAX_LOGGED_FAILURES_PER_MINUTE;
            if log {
                window.logged += 1;
            } else {
                window.suppressed += 1;
            }
            (log, suppressed)
        };
        if suppressed > 0 {
            let event = json!({ "event": "auth_failures_suppressed", "count": suppressed });
            self.record(None, event).await;
        }
        if log {
            let path: String = path.chars().take(200).collect();
            let event = json!({
                "event": "auth_failed",
                "peer": peer.ip().to_string(),
                "path": path,
                "reason": reason,
            });
            self.record(request_id, event).await;
        }
    }
}

/// Refuse a configuration that would let anyone on the network use the
/// proxy without a key.
pub fn check_exposure(loopback: bool, keys: &Keys) -> Result<(), String> {
    if loopback || keys.count(Role::Agent) > 0 {
        return Ok(());
    }
    Err("Razorwire listens on an address other machines can reach, so every agent needs a key. \
         Create one with `razorwire new-key agent <name>` and set KEYS_FILE, or listen on 127.0.0.1."
        .to_string())
}

/// Check `UPSTREAM_URL` and return it without a trailing slash. The URL is
/// not echoed in errors, in case it holds a secret.
pub fn check_upstream(raw: &str) -> Result<String, String> {
    let url = reqwest::Url::parse(raw.trim())
        .map_err(|_| "UPSTREAM_URL is not a valid URL".to_string())?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(
            "UPSTREAM_URL must not hold credentials. Put the provider key in UPSTREAM_API_KEY"
                .into(),
        );
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("UPSTREAM_URL must not have a query string or a fragment".into());
    }
    match url.scheme() {
        "https" => {}
        "http" if url.host_str().is_some_and(is_loopback_host) => {}
        "http" => {
            return Err(
                "UPSTREAM_URL uses plain http to another machine, so prompts, replies and keys \
                        would cross the network unencrypted. Use https"
                    .into(),
            )
        }
        _ => return Err("UPSTREAM_URL must start with https://".into()),
    }
    Ok(raw.trim().trim_end_matches('/').to_string())
}

pub fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The `Authorization` value for `UPSTREAM_API_KEY`, marked sensitive so it
/// is never printed. The key is not echoed in errors.
pub fn upstream_authorization(key: &str) -> Result<HeaderValue, String> {
    let mut value = HeaderValue::from_str(&format!("Bearer {}", key.trim()))
        .map_err(|_| "UPSTREAM_API_KEY holds characters that cannot go in a header".to_string())?;
    value.set_sensitive(true);
    Ok(value)
}

/// Paths under `/razorwire` belong to the proxy and are never forwarded.
fn is_own_path(path: &str) -> bool {
    let path = path.trim_start_matches('/').to_ascii_lowercase();
    path == "razorwire" || path.starts_with("razorwire/")
}

/// Forward one request to the provider, then record and police the response.
pub async fn forward(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request_id = state.next_request_id.fetch_add(1, Ordering::Relaxed);
    if is_own_path(uri.path()) {
        return refuse(
            StatusCode::NOT_FOUND,
            "not_found",
            "There is no such Razorwire endpoint.",
        );
    }

    let config = state.config();
    let agent = match identify_agent(&state, &config, &headers, peer, uri.path(), request_id).await
    {
        Ok(agent) => agent,
        Err(refusal) => return *refusal,
    };
    let Ok(permit) = state.in_flight.clone().try_acquire_owned() else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "busy",
            "Razorwire is handling too many requests at once. Try again shortly.",
        );
    };

    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let url = format!("{}{}", state.settings.upstream, path);

    // The conversation the agent sent tells us where its run stands. Read it
    // here so the parsed request is not held while the provider answers.
    let history = match serde_json::from_slice::<Value>(&body) {
        Ok(request) => {
            for (call_id, mut event) in openai::tool_results(&request) {
                // Call ids are only unique per agent, so results are told
                // apart by both. Rollback pairs a result with its call.
                if !agent.is_empty() {
                    event["agent"] = json!(agent);
                }
                let is_new = match call_id {
                    Some(id) => {
                        let mut seen = state.seen_results.lock().await;
                        if seen.len() >= MAX_SEEN_RESULTS {
                            seen.clear();
                        }
                        seen.insert(format!("{agent}\n{id}"))
                    }
                    None => true,
                };
                if is_new {
                    state.record(Some(request_id), event).await;
                }
            }
            openai::History::from_request(&request)
        }
        Err(_) => openai::History::default(),
    };

    let upstream = match state
        .client
        .request(method, &url)
        .headers(forward_headers(
            &headers,
            state.settings.upstream_key.as_ref(),
        ))
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            let message = format!("could not reach upstream: {err}");
            eprintln!("razorwire: {message}");
            return refuse(StatusCode::BAD_GATEWAY, "upstream_unreachable", &message);
        }
    };

    let status = upstream.status();
    let mut response_headers = HeaderMap::new();
    for (name, value) in upstream.headers() {
        let name_text = name.as_str();
        // The provider cannot speak for Razorwire.
        if !SKIP_RESPONSE_HEADERS.contains(&name_text) && !name_text.starts_with("x-razorwire-") {
            response_headers.append(name.clone(), value.clone());
        }
    }

    let policy = config.policy.clone();
    let enforced_policy = policy
        .clone()
        .filter(|policy| policy.mode() == Mode::Enforce);
    let enforced = enforced_policy.as_deref();
    // Calls can only be held when someone is able to approve them.
    let holds = config.keys.count(Role::Admin) > 0;
    let job = Job {
        state: &state,
        request_id,
        agent: &agent,
        history: &history,
        holds,
    };

    let response_body = if content_type(&response_headers).contains("event-stream") {
        match enforced_policy {
            Some(policy) if state.settings.live_streams => police_live(Live {
                state: state.clone(),
                request_id,
                agent: agent.clone(),
                history: history.clone(),
                policy,
                holds,
                path: uri.path().to_string(),
                upstream,
                gate: sse::LiveGate::default(),
                read: 0,
                _permit: permit,
            }),
            Some(policy) => {
                match police_stream(&job, &policy, uri.path(), upstream, &mut response_headers)
                    .await
                {
                    Ok(body) => body,
                    Err(refusal) => return *refusal,
                }
            }
            None => watch_stream(
                state.clone(),
                request_id,
                agent.clone(),
                history.clone(),
                policy,
                upstream,
                permit,
            ),
        }
    } else {
        let bytes = match upstream.bytes().await {
            Ok(bytes) => bytes,
            Err(err) => {
                let message = format!("upstream response was cut short: {err}");
                eprintln!("razorwire: {message}");
                return refuse(StatusCode::BAD_GATEWAY, "upstream_incomplete", &message);
            }
        };

        match serde_json::from_slice::<Value>(&bytes) {
            Ok(mut response) => {
                let blocked = match enforced {
                    Some(policy) => police(&job, policy, &mut response).await,
                    None => {
                        let inspection = openai::inspect_response(
                            &mut response,
                            policy.as_deref(),
                            &agent,
                            &history,
                        );
                        for event in inspection.events {
                            state.record(Some(request_id), event).await;
                        }
                        inspection.blocked
                    }
                };
                if blocked == 0 {
                    Body::from(bytes)
                } else {
                    response_headers.insert(
                        HeaderName::from_static("x-razorwire-blocked"),
                        HeaderValue::from(blocked),
                    );
                    Body::from(response.to_string())
                }
            }
            Err(_) => {
                // Under an enforced policy, a response that might carry tool
                // calls but cannot be read is not passed on.
                if enforced.is_some()
                    && !bytes.is_empty()
                    && may_carry_tool_calls(&response_headers)
                {
                    return refuse_response(
                        &state,
                        request_id,
                        uri.path(),
                        "the response is not readable JSON",
                    )
                    .await;
                }
                Body::from(bytes)
            }
        }
    };

    let mut response = Response::new(response_body);
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;
    response
}

/// Work out which agent sent a request. With agent keys set up, the key
/// decides and a request without a valid one is refused. Without them, the
/// agent's own `x-agent-name` header is taken at its word.
async fn identify_agent(
    state: &AppState,
    config: &Config,
    headers: &HeaderMap,
    peer: SocketAddr,
    path: &str,
    request_id: u64,
) -> Result<String, Box<Response>> {
    if config.keys.count(Role::Agent) == 0 {
        let claimed = headers
            .get(AGENT_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        return Ok(claimed.chars().take(128).collect());
    }
    let identity = auth::presented_key(headers).map(|key| config.keys.identify(key));
    let (reason, refusal) = match identity {
        Some(Some(identity)) if identity.role == Role::Agent => return Ok(identity.name.clone()),
        None => (
            "no Razorwire key",
            refuse_unauthorized(
                "missing_key",
                "This Razorwire needs an agent key. Pass it as the API key, which sends \
                 `Authorization: Bearer rw_...`, or in the x-razorwire-key header.",
            ),
        ),
        Some(Some(_)) => (
            "an admin key was used by an agent",
            refuse(
                StatusCode::FORBIDDEN,
                "wrong_key_role",
                "This is an admin key. Agents need an agent key, so that no agent can approve its own calls.",
            ),
        ),
        Some(None) => (
            "unknown key",
            refuse_unauthorized("invalid_key", "This Razorwire key is not valid."),
        ),
    };
    state
        .auth_failed(Some(request_id), peer, path, reason)
        .await;
    Err(Box::new(refusal))
}

/// The headers sent to the provider. Hop-by-hop headers, Razorwire's own
/// headers and any Razorwire key are removed. With `upstream_key`, the
/// agent's `Authorization` is replaced by the provider key.
pub(crate) fn forward_headers(
    headers: &HeaderMap,
    upstream_key: Option<&HeaderValue>,
) -> HeaderMap {
    // Headers named in `Connection` are hop-by-hop too.
    let listed: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect();

    let mut forwarded = HeaderMap::new();
    for (name, value) in headers {
        let text = name.as_str();
        if SKIP_REQUEST_HEADERS.contains(&text)
            || text.starts_with("x-razorwire-")
            || listed.iter().any(|listed| listed == text)
        {
            continue;
        }
        if name == header::AUTHORIZATION {
            let ours = value
                .to_str()
                .ok()
                .and_then(auth::bearer_token)
                .is_some_and(|token| token.starts_with(auth::KEY_PREFIX));
            if ours || upstream_key.is_some() {
                continue;
            }
        }
        forwarded.append(name.clone(), value.clone());
    }
    if let Some(key) = upstream_key {
        forwarded.insert(header::AUTHORIZATION, key.clone());
    }
    forwarded
}

/// One request being policed.
struct Job<'a> {
    state: &'a AppState,
    request_id: u64,
    agent: &'a str,
    history: &'a openai::History,
    holds: bool,
}

/// Decide every tool call in a response under an enforced policy, wait for a
/// human on the held ones, and remove what is blocked. Returns how many calls
/// were removed.
async fn police(job: &Job<'_>, policy: &Policy, response: &mut Value) -> usize {
    let state = job.state;
    let mut plan = openai::plan(response, Some(policy), job.agent, job.history, job.holds);
    let timeout = state.settings.approval_timeout;
    let created = now_ms();
    let expires = created.saturating_add(u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX));

    let mut tickets = Vec::new();
    let mut unheld = Vec::new();
    for (index, hold) in plan.holds.iter().enumerate() {
        let summary = json!({
            "agent": job.agent,
            "tool": hold.tool,
            "arguments": hold.arguments,
            "call_id": hold.call_id,
            "rule": hold.rule,
            "message": hold.message,
            "request_id": job.request_id,
            "created_ms": created,
            "expires_ms": expires,
        });
        match state.approvals.hold(summary) {
            Ok(ticket) => tickets.push((index, ticket)),
            Err(err) => unheld.push((index, err)),
        }
    }
    for (index, ticket) in &tickets {
        let event = plan.holds[*index].event;
        plan.events[event]["approval_id"] = json!(ticket.id);
    }
    for (index, err) in unheld {
        let why = match err {
            HoldError::Full => {
                "Too many tool calls are already waiting for approval, so it was blocked."
            }
            HoldError::NoId => "It could not be registered for approval, so it was blocked.",
        };
        let event = &mut plan.events[plan.holds[index].event];
        if let Some(fields) = event.as_object_mut() {
            fields.remove("held");
        }
        event["blocked"] = json!(true);
        event["approval_error"] = json!(why);
        plan.refuse(index, why);
    }

    for event in std::mem::take(&mut plan.events) {
        state.record(Some(job.request_id), event).await;
    }
    for (index, ticket) in &tickets {
        let hold = &plan.holds[*index];
        let id = &ticket.id;
        let event = json!({
            "event": "approval_requested",
            "approval_id": id,
            "agent": job.agent,
            "tool": hold.tool,
            "rule": hold.rule,
            "expires_ms": expires,
            "hint": format!("razorwire approve {id}   or   razorwire deny {id} [reason]"),
        });
        state.record(Some(job.request_id), event).await;
    }

    let waits = tickets.into_iter().map(|(index, ticket)| async move {
        let id = ticket.id.clone();
        (index, id, ticket.wait(timeout).await)
    });
    for (index, id, outcome) in join_all(waits).await {
        let (decision, by, reason) = match outcome {
            Outcome::Decided(verdict) if verdict.approved => {
                plan.approve(index);
                ("approved", Some(verdict.by), verdict.reason)
            }
            Outcome::Decided(verdict) => {
                let why = match &verdict.reason {
                    Some(reason) => sentence(&format!("Denied by {}: {reason}", verdict.by)),
                    None => format!("Denied by {}.", verdict.by),
                };
                plan.refuse(index, &why);
                ("denied", Some(verdict.by), verdict.reason)
            }
            Outcome::Expired => {
                let why = format!("No one approved it within {} seconds.", timeout.as_secs());
                plan.refuse(index, &why);
                ("expired", None, None)
            }
            Outcome::Parked => {
                let why = format!(
                    "No one approved it within {} seconds, so it is parked. If a person approves it \
                     later, Razorwire carries it out itself, so do not try it again.",
                    timeout.as_secs()
                );
                plan.refuse(index, &why);
                ("parked", None, None)
            }
        };
        let event = json!({
            "event": "approval_decided",
            "approval_id": id,
            "decision": decision,
            "by": by,
            "reason": reason,
            "blocked": decision != "approved",
        });
        state.record(Some(job.request_id), event).await;
    }

    openai::apply(response, &plan)
}

fn sentence(text: &str) -> String {
    if text.ends_with(['.', '!', '?']) {
        text.to_string()
    } else {
        format!("{text}.")
    }
}

/// Under an enforced policy: hold the whole stream back, check it, then send
/// either the original bytes or a rebuilt stream with the blocked calls
/// removed. Nothing reaches the agent until the check is done.
async fn police_stream(
    job: &Job<'_>,
    policy: &Policy,
    path: &str,
    mut upstream: reqwest::Response,
    headers: &mut HeaderMap,
) -> Result<Body, Box<Response>> {
    let mut capture = StreamCapture::default();
    let mut original: Vec<u8> = Vec::new();
    loop {
        match upstream.chunk().await {
            Ok(Some(chunk)) => {
                if original.len() + chunk.len() > MAX_STREAM_BYTES {
                    let reason = "the streamed response is too large to check";
                    return Err(Box::new(
                        refuse_response(job.state, job.request_id, path, reason).await,
                    ));
                }
                capture.feed(&chunk);
                original.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(err) => {
                let message = format!("upstream response was cut short: {err}");
                eprintln!("razorwire: {message}");
                return Err(Box::new(refuse(
                    StatusCode::BAD_GATEWAY,
                    "upstream_incomplete",
                    &message,
                )));
            }
        }
    }

    let rebuilt = match capture.finish() {
        Captured::Nothing => None,
        Captured::Unreadable(reason) => {
            return Err(Box::new(
                refuse_response(job.state, job.request_id, path, reason).await,
            ));
        }
        Captured::Chat(mut completion) => {
            let blocked = police(job, policy, &mut completion).await;
            (blocked > 0).then(|| (blocked, sse::chat_stream(&completion)))
        }
        Captured::Responses {
            event,
            mut response,
        } => {
            let blocked = police(job, policy, &mut response).await;
            (blocked > 0).then(|| (blocked, sse::responses_stream(&event, &response)))
        }
    };

    match rebuilt {
        None => Ok(Body::from(original)),
        Some((blocked, stream)) => {
            headers.insert(
                HeaderName::from_static("x-razorwire-blocked"),
                HeaderValue::from(blocked),
            );
            Ok(Body::from(stream))
        }
    }
}

/// A streamed reply being policed live.
struct Live {
    state: Arc<AppState>,
    request_id: u64,
    agent: String,
    history: openai::History,
    policy: Arc<Policy>,
    holds: bool,
    path: String,
    upstream: reqwest::Response,
    gate: sse::LiveGate,
    /// Bytes read from the provider so far.
    read: usize,
    /// The request's slot, held until the stream ends.
    _permit: OwnedSemaphorePermit,
}

/// While a streamed reply waits for a human, this comment is sent every
/// `HEARTBEAT`. Clients skip comments. It keeps idle connections open, and
/// writing to an agent that hung up fails, which withdraws its held calls.
const HEARTBEAT: Duration = Duration::from_secs(5);
const HEARTBEAT_LINE: &[u8] = b": razorwire is waiting for a decision\n\n";

/// The check of a finished stream, which may wait for a human.
type Checking = Pin<Box<dyn Future<Output = Vec<u8>> + Send>>;

enum Phase {
    Reading(Box<Live>),
    Checking(Checking),
}

impl Live {
    /// The stream is complete: check it, wait for a human on held calls,
    /// and return what is left to send. The request's slot goes with it.
    async fn finish(mut self) -> Vec<u8> {
        let responses = self.gate.is_responses();
        let (captured, held, sent) = std::mem::take(&mut self.gate).finish();
        let job = Job {
            state: &self.state,
            request_id: self.request_id,
            agent: &self.agent,
            history: &self.history,
            holds: self.holds,
        };
        match captured {
            Captured::Nothing => held,
            Captured::Unreadable(reason) => self.refuse(reason, responses).await,
            Captured::Chat(mut completion) => {
                if police(&job, &self.policy, &mut completion).await == 0 {
                    held
                } else {
                    sse::chat_tail(&completion, &sent).into_bytes()
                }
            }
            Captured::Responses {
                event,
                mut response,
            } => {
                if police(&job, &self.policy, &mut response).await == 0 {
                    held
                } else {
                    sse::responses_tail(&event, &response, &sent).into_bytes()
                }
            }
        }
    }

    /// End the stream with an error instead of the rest of the reply. What
    /// was already sent was only text, so no tool call got through.
    async fn refuse(&self, reason: &str, responses: bool) -> Vec<u8> {
        let message = format!(
            "razorwire could not check the provider's response, so the rest of it was not passed on: {reason}."
        );
        let event = json!({ "event": "response_refused", "path": self.path, "reason": message });
        self.state.record(Some(self.request_id), event).await;
        sse::stream_error(responses, "response_not_inspectable", &message).into_bytes()
    }
}

/// Under an enforced policy, with live streaming: pass the reply on as it
/// arrives while it is only text, and hold everything from the first event
/// that could carry a tool call until the whole reply is checked. Then send
/// the held part unchanged, or rebuilt without the blocked calls. A tool
/// call never reaches the agent before its decision. If the agent hangs up,
/// the stream is dropped, and with it any held approval.
fn police_live(live: Live) -> Body {
    let start = Some(Phase::Reading(Box::new(live)));
    let stream = stream::unfold(start, |phase| async move {
        let mut live = match phase? {
            Phase::Reading(live) => live,
            Phase::Checking(checking) => return check_step(checking).await,
        };
        loop {
            let responses = live.gate.is_responses();
            match live.upstream.chunk().await {
                Ok(Some(chunk)) => {
                    live.read = live.read.saturating_add(chunk.len());
                    if live.read > MAX_STREAM_BYTES {
                        let end = live
                            .refuse("the streamed response is too large to check", responses)
                            .await;
                        return Some((Ok(Bytes::from(end)), None));
                    }
                    let ready = live.gate.feed(&chunk);
                    if !ready.is_empty() {
                        return Some((Ok(Bytes::from(ready)), Some(Phase::Reading(live))));
                    }
                }
                Ok(None) => return check_step(Box::pin(live.finish())).await,
                Err(err) => {
                    eprintln!("razorwire: upstream response was cut short: {err}");
                    let reason = format!("the provider's stream was cut short: {err}");
                    let end = live.refuse(&reason, responses).await;
                    return Some((Ok(Bytes::from(end)), None));
                }
            }
        }
    });
    Body::from_stream(stream)
}

/// Wait for the check to end, sending a heartbeat comment meanwhile.
async fn check_step(mut checking: Checking) -> Option<(Result<Bytes, Infallible>, Option<Phase>)> {
    tokio::select! {
        end = &mut checking => Some((Ok(Bytes::from(end)), None)),
        () = tokio::time::sleep(HEARTBEAT) => Some((
            Ok(Bytes::from_static(HEARTBEAT_LINE)),
            Some(Phase::Checking(checking)),
        )),
    }
}

/// With no policy enforced: pass the stream on as it arrives, and read it on
/// the side so its tool calls still reach the audit log. The request's slot
/// is held until the stream ends.
fn watch_stream(
    state: Arc<AppState>,
    request_id: u64,
    agent: String,
    history: openai::History,
    policy: Option<Arc<Policy>>,
    upstream: reqwest::Response,
    permit: OwnedSemaphorePermit,
) -> Body {
    let stream = stream::unfold(
        Some((upstream, StreamCapture::default(), history, permit)),
        move |progress| {
            let state = state.clone();
            let agent = agent.clone();
            let policy = policy.clone();
            async move {
                let (mut upstream, mut capture, history, permit) = progress?;
                match upstream.chunk().await {
                    Ok(Some(chunk)) => {
                        capture.feed(&chunk);
                        Some((Ok(chunk), Some((upstream, capture, history, permit))))
                    }
                    Ok(None) => {
                        let mut reply = match capture.finish() {
                            Captured::Chat(completion) => completion,
                            Captured::Responses { response, .. } => response,
                            Captured::Unreadable(_) | Captured::Nothing => return None,
                        };
                        let inspection = openai::inspect_response(
                            &mut reply,
                            policy.as_deref(),
                            &agent,
                            &history,
                        );
                        for event in inspection.events {
                            state.record(Some(request_id), event).await;
                        }
                        None
                    }
                    Err(err) => Some((Err(err), None)),
                }
            }
        },
    );
    Body::from_stream(stream)
}

/// Record that a response was withheld and build the error the agent gets.
async fn refuse_response(state: &AppState, request_id: u64, path: &str, reason: &str) -> Response {
    let message = format!(
        "razorwire could not check the provider's response, so it was not passed on: {reason}."
    );
    state
        .record(
            Some(request_id),
            json!({ "event": "response_refused", "path": path, "reason": message }),
        )
        .await;
    refuse(
        StatusCode::BAD_GATEWAY,
        "response_not_inspectable",
        &message,
    )
}

fn content_type(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Whether an unreadable response could still be hiding tool calls: it claims
/// to be JSON, or it is compressed.
fn may_carry_tool_calls(headers: &HeaderMap) -> bool {
    content_type(headers).contains("json") || headers.contains_key(header::CONTENT_ENCODING)
}

/// An error produced by the proxy itself, in the shape OpenAI SDKs expect.
pub fn refuse(status: StatusCode, code: &str, message: &str) -> Response {
    let body = json!({
        "error": { "message": message, "type": "razorwire_error", "code": code }
    });
    json_response(status, &body)
}

/// A JSON answer from the proxy itself. It is never cached and never
/// sniffed as another content type.
pub fn json_response(status: StatusCode, body: &Value) -> Response {
    let mut response = Response::new(Body::from(body.to_string()));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

pub fn refuse_unauthorized(code: &str, message: &str) -> Response {
    let mut response = refuse(StatusCode::UNAUTHORIZED, code, message);
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"razorwire\""),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn razorwire_keys_never_reach_the_provider() {
        let sent = headers(&[
            ("authorization", "Bearer rw_agentkey"),
            ("x-razorwire-key", "rw_other"),
            ("x-razorwire-anything", "x"),
            ("x-agent-name", "liar"),
            ("content-type", "application/json"),
        ]);
        let forwarded = forward_headers(&sent, None);
        assert!(forwarded.get("authorization").is_none());
        assert!(forwarded
            .keys()
            .all(|name| !name.as_str().starts_with("x-razorwire")));
        assert!(forwarded.get("x-agent-name").is_none());
        assert_eq!(forwarded["content-type"], "application/json");
    }

    #[test]
    fn the_agents_provider_key_passes_unless_the_proxy_holds_one() {
        let sent = headers(&[("authorization", "Bearer sk-agents-own")]);
        assert_eq!(
            forward_headers(&sent, None)["authorization"],
            "Bearer sk-agents-own"
        );

        let ours = upstream_authorization(" gsk-held-by-proxy \n").unwrap();
        let forwarded = forward_headers(&sent, Some(&ours));
        let values: Vec<_> = forwarded.get_all("authorization").iter().collect();
        assert_eq!(
            values,
            [&HeaderValue::from_static("Bearer gsk-held-by-proxy")]
        );
        assert!(values[0].is_sensitive());

        // With no Authorization at all, the proxy's key is still sent.
        let forwarded = forward_headers(&HeaderMap::new(), Some(&ours));
        assert_eq!(forwarded["authorization"], "Bearer gsk-held-by-proxy");
    }

    #[test]
    fn headers_named_in_connection_are_dropped() {
        let sent = headers(&[
            ("connection", "keep-alive, X-Secret-Hop"),
            ("x-secret-hop", "1"),
            ("x-kept", "1"),
        ]);
        let forwarded = forward_headers(&sent, None);
        assert!(forwarded.get("x-secret-hop").is_none());
        assert!(forwarded.get("x-kept").is_some());
    }

    #[test]
    fn the_upstream_must_be_encrypted_unless_it_is_local() {
        assert_eq!(
            check_upstream("https://api.groq.com/openai/").unwrap(),
            "https://api.groq.com/openai"
        );
        assert!(check_upstream("http://127.0.0.1:9911").is_ok());
        assert!(check_upstream("http://localhost:9911").is_ok());
        assert!(check_upstream("http://[::1]:9911").is_ok());
        for bad in [
            "http://api.openai.com",
            "http://10.0.0.5:8000",
            "ftp://api.openai.com",
            "https://user:secret@api.openai.com",
            "https://api.openai.com/?key=secret",
            "not a url",
        ] {
            let err = check_upstream(bad).expect_err(bad);
            assert!(!err.contains("secret"), "{err}");
        }
    }

    #[test]
    fn only_local_listeners_may_go_without_agent_keys() {
        let none = Keys::default();
        assert!(check_exposure(true, &none).is_ok());
        assert!(check_exposure(false, &none).is_err());
        let key = auth::generate().unwrap();
        let admin_only = Keys::parse(&auth::key_line(Role::Admin, "mann", &key)).unwrap();
        assert!(check_exposure(false, &admin_only).is_err());
        let agent = Keys::parse(&auth::key_line(Role::Agent, "bot", &key)).unwrap();
        assert!(check_exposure(false, &agent).is_ok());
    }

    #[test]
    fn the_proxys_own_paths_are_recognised() {
        for path in ["/razorwire", "/razorwire/approvals", "//RAZORWIRE/reload"] {
            assert!(is_own_path(path), "{path}");
        }
        for path in ["/v1/chat/completions", "/razorwirex", "/v1/razorwire"] {
            assert!(!is_own_path(path), "{path}");
        }
    }

    #[test]
    fn loopback_hosts() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("127.0.0.2"));
        assert!(is_loopback_host("[::1]"));
        assert!(!is_loopback_host("localhost.evil.test"));
        assert!(!is_loopback_host("192.168.1.2"));
    }
}
