//! A proxy for OpenAI-compatible APIs that records every tool call and blocks
//! the ones a policy forbids.
//!
//! The agent points its SDK at this proxy instead of the provider. Requests
//! are forwarded unchanged. In the provider's response, each tool call the
//! model asks for is checked against the policy, and a blocked call is removed
//! before the agent sees it.

mod openai;
mod policy;
mod sse;

use std::{
    collections::HashSet,
    env,
    net::SocketAddr,
    process,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    response::Response,
    routing::get,
    Router,
};
use serde_json::{json, Value};
use tokio::{fs::OpenOptions, io::AsyncWriteExt, sync::Mutex};

use futures_util::stream;
use policy::{Mode, Policy};
use sse::{Captured, StreamCapture};

/// Largest request body the proxy accepts. Chat requests can carry images.
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Largest streamed response that is held back to be checked.
const MAX_STREAM_BYTES: usize = 32 * 1024 * 1024;

/// How many tool-result ids are remembered before the set is reset.
const MAX_SEEN_RESULTS: usize = 100_000;

/// Header an agent uses to say who it is. Rules can match on it.
const AGENT_HEADER: &str = "x-agent-name";

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

struct AppState {
    client: reqwest::Client,
    upstream: String,
    policy: Option<Policy>,
    audit: Mutex<tokio::fs::File>,
    /// Tool results already recorded. Agents resend the whole conversation on
    /// every request, so without this each result would be logged many times.
    seen_results: Mutex<HashSet<String>>,
    next_request_id: AtomicU64,
}

impl AppState {
    /// True when a policy is loaded and its decisions are applied.
    fn enforcing(&self) -> bool {
        self.policy
            .as_ref()
            .is_some_and(|policy| policy.mode() == Mode::Enforce)
    }

    /// Stamp an event and append it to the audit log and stdout.
    async fn record(&self, request_id: u64, mut event: Value) {
        if let Some(fields) = event.as_object_mut() {
            fields.insert("ts_ms".into(), json!(now_ms()));
            fields.insert("request_id".into(), json!(request_id));
        }
        let line = format!("{event}\n");
        print!("{line}");

        let mut file = self.audit.lock().await;
        let written = file.write_all(line.as_bytes()).await;
        let flushed = file.flush().await;
        if let Err(err) = written.and(flushed) {
            eprintln!("audit log write failed: {err}");
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let upstream = env::var("UPSTREAM_URL").unwrap_or_else(|_| "https://api.openai.com".into());
    let upstream = upstream.trim_end_matches('/').to_string();
    let listen: SocketAddr = env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()?;
    let audit_path = env::var("AUDIT_LOG").unwrap_or_else(|_| "audit.jsonl".into());

    // A policy that was asked for but cannot be loaded stops the proxy.
    // Starting without it would silently allow everything.
    let policy_path = env::var("POLICY_FILE")
        .ok()
        .filter(|path| !path.trim().is_empty());
    let policy = match &policy_path {
        None => None,
        Some(path) => match Policy::load(path) {
            Ok(policy) => Some(policy),
            Err(err) => {
                eprintln!("razorwire: {err}");
                process::exit(2);
            }
        },
    };

    let audit = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&audit_path)
        .await?;

    println!("razorwire listening on http://{listen}");
    println!("forwarding to {upstream}");
    println!("audit log: {audit_path}");
    match (&policy_path, &policy) {
        (Some(path), Some(policy)) => {
            let mode = match policy.mode() {
                Mode::Enforce => "enforce: blocked calls never reach the agent",
                Mode::Shadow => "shadow: decisions are logged, nothing is blocked",
            };
            println!("policy: {path} ({} rules, {mode})", policy.rule_count());
        }
        _ => println!("policy: none (tool calls are logged, nothing is blocked)"),
    }

    let state = Arc::new(AppState {
        client: reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .build()?,
        upstream,
        policy,
        audit: Mutex::new(audit),
        seen_results: Mutex::new(HashSet::new()),
        next_request_id: AtomicU64::new(1),
    });

    let app = Router::new()
        .route("/healthz", get(healthz))
        .fallback(proxy)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}

/// Forward one request to the provider, then record and police the response.
async fn proxy(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request_id = state.next_request_id.fetch_add(1, Ordering::Relaxed);
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let url = format!("{}{}", state.upstream, path);
    let agent = headers
        .get(AGENT_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();

    // The conversation the agent sent tells us where its run stands. Read it
    // here so the parsed request is not held while the provider answers.
    let history = match serde_json::from_slice::<Value>(&body) {
        Ok(request) => {
            for (call_id, event) in openai::tool_results(&request) {
                let is_new = match call_id {
                    Some(id) => {
                        let mut seen = state.seen_results.lock().await;
                        if seen.len() >= MAX_SEEN_RESULTS {
                            seen.clear();
                        }
                        seen.insert(id)
                    }
                    None => true,
                };
                if is_new {
                    state.record(request_id, event).await;
                }
            }
            openai::History::from_request(&request)
        }
        Err(_) => openai::History::default(),
    };

    let mut forward_headers = HeaderMap::new();
    for (name, value) in &headers {
        if !SKIP_REQUEST_HEADERS.contains(&name.as_str()) {
            forward_headers.append(name.clone(), value.clone());
        }
    }

    let upstream = match state
        .client
        .request(method, &url)
        .headers(forward_headers)
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            let message = format!("could not reach upstream: {err}");
            eprintln!("{message}");
            return refuse(StatusCode::BAD_GATEWAY, "upstream_unreachable", &message);
        }
    };

    let status = upstream.status();
    let mut response_headers = HeaderMap::new();
    for (name, value) in upstream.headers() {
        if !SKIP_RESPONSE_HEADERS.contains(&name.as_str()) {
            response_headers.append(name.clone(), value.clone());
        }
    }

    let response_body = if content_type(&response_headers).contains("event-stream") {
        if state.enforcing() {
            let policed = police_stream(
                &state,
                request_id,
                &agent,
                &history,
                uri.path(),
                upstream,
                &mut response_headers,
            )
            .await;
            match policed {
                Ok(body) => body,
                Err(refusal) => return *refusal,
            }
        } else {
            watch_stream(state.clone(), request_id, agent, history, upstream)
        }
    } else {
        let bytes = match upstream.bytes().await {
            Ok(bytes) => bytes,
            Err(err) => {
                let message = format!("upstream response was cut short: {err}");
                eprintln!("{message}");
                return refuse(StatusCode::BAD_GATEWAY, "upstream_incomplete", &message);
            }
        };

        match serde_json::from_slice::<Value>(&bytes) {
            Ok(mut response) => {
                let inspection = openai::inspect_response(
                    &mut response,
                    state.policy.as_ref(),
                    &agent,
                    &history,
                );
                for event in inspection.events {
                    state.record(request_id, event).await;
                }
                if inspection.blocked == 0 {
                    Body::from(bytes)
                } else {
                    response_headers.insert(
                        HeaderName::from_static("x-razorwire-blocked"),
                        HeaderValue::from(inspection.blocked),
                    );
                    Body::from(response.to_string())
                }
            }
            Err(_) => {
                // Under an enforced policy, a response that might carry tool
                // calls but cannot be read is not passed on.
                if state.enforcing() && !bytes.is_empty() && may_carry_tool_calls(&response_headers)
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

/// Under an enforced policy: hold the whole stream back, check it, then send
/// either the original bytes or a rebuilt stream with the blocked calls
/// removed. Nothing reaches the agent until the check is done.
async fn police_stream(
    state: &AppState,
    request_id: u64,
    agent: &str,
    history: &openai::History,
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
                        refuse_response(state, request_id, path, reason).await,
                    ));
                }
                capture.feed(&chunk);
                original.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(err) => {
                let message = format!("upstream response was cut short: {err}");
                eprintln!("{message}");
                return Err(Box::new(refuse(
                    StatusCode::BAD_GATEWAY,
                    "upstream_incomplete",
                    &message,
                )));
            }
        }
    }

    let (inspection, rebuilt) = match capture.finish() {
        Captured::Nothing => return Ok(Body::from(original)),
        Captured::Unreadable(reason) => {
            return Err(Box::new(
                refuse_response(state, request_id, path, reason).await,
            ));
        }
        Captured::Chat(mut completion) => {
            let inspection =
                openai::inspect_response(&mut completion, state.policy.as_ref(), agent, history);
            let rebuilt = (inspection.blocked > 0).then(|| sse::chat_stream(&completion));
            (inspection, rebuilt)
        }
        Captured::Responses {
            event,
            mut response,
        } => {
            let inspection =
                openai::inspect_response(&mut response, state.policy.as_ref(), agent, history);
            let rebuilt =
                (inspection.blocked > 0).then(|| sse::responses_stream(&event, &response));
            (inspection, rebuilt)
        }
    };

    let blocked = inspection.blocked;
    for event in inspection.events {
        state.record(request_id, event).await;
    }
    match rebuilt {
        None => Ok(Body::from(original)),
        Some(stream) => {
            headers.insert(
                HeaderName::from_static("x-razorwire-blocked"),
                HeaderValue::from(blocked),
            );
            Ok(Body::from(stream))
        }
    }
}

/// With no policy enforced: pass the stream on as it arrives, and read it on
/// the side so its tool calls still reach the audit log.
fn watch_stream(
    state: Arc<AppState>,
    request_id: u64,
    agent: String,
    history: openai::History,
    upstream: reqwest::Response,
) -> Body {
    let stream = stream::unfold(
        Some((upstream, StreamCapture::default(), history)),
        move |progress| {
            let state = state.clone();
            let agent = agent.clone();
            async move {
                let (mut upstream, mut capture, history) = progress?;
                match upstream.chunk().await {
                    Ok(Some(chunk)) => {
                        capture.feed(&chunk);
                        Some((Ok(chunk), Some((upstream, capture, history))))
                    }
                    Ok(None) => {
                        let mut reply = match capture.finish() {
                            Captured::Chat(completion) => completion,
                            Captured::Responses { response, .. } => response,
                            Captured::Unreadable(_) | Captured::Nothing => return None,
                        };
                        let inspection = openai::inspect_response(
                            &mut reply,
                            state.policy.as_ref(),
                            &agent,
                            &history,
                        );
                        for event in inspection.events {
                            state.record(request_id, event).await;
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
            request_id,
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
fn refuse(status: StatusCode, code: &str, message: &str) -> Response {
    let body = json!({
        "error": { "message": message, "type": "razorwire_error", "code": code }
    });
    let mut response = Response::new(Body::from(body.to_string()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}
