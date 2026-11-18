//! Alerts: tell a person the moment a tool call is waiting for them.
//!
//! With `ALERT_URL` set, Razorwire posts a short message when a call is held
//! for approval, when one is parked for a later decision, and when a held
//! call ends without a decision. Blocked calls can be added with
//! `ALERT_EVENTS`. Slack and Discord webhooks and ntfy topics get a message
//! written for them. Any other address gets JSON, signed with `ALERT_KEY`
//! when one is set, the same way as requests to the executor.
//!
//! Alerts never slow the proxy down or change a decision: they go into a
//! bounded queue that one task empties. When the queue is full, or more than
//! `MAX_PER_MINUTE` would go out in a minute, the rest are counted, logged as
//! `alerts_dropped`, and summed up in one message. An alert only informs:
//! approving a call still takes an admin key.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::{
    audit::{json_line, now_ms, Audit},
    auth::{hex, unhex},
    executor::{signature, SIGNATURE_HEADER, TIMESTAMP_HEADER},
    proxy::is_loopback_host,
};

/// Alerts waiting to go out. Beyond that, new ones are counted and dropped.
const QUEUE: usize = 256;

/// Most alerts sent in one minute. The rest are summed up in one message
/// when the minute is over.
const MAX_PER_MINUTE: u32 = 20;

const WINDOW_MS: u64 = 60_000;

/// Tries per alert when the receiver is down or busy.
const ATTEMPTS: u32 = 3;

/// Longest wait before a retry, even if the receiver asks for more.
const MAX_RETRY_WAIT: Duration = Duration::from_secs(30);

/// How long one try may take.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Shortest `ALERT_KEY` accepted, in bytes.
const MIN_KEY_BYTES: usize = 32;

/// How much of a call's arguments goes into a chat message, in bytes.
/// Discord refuses messages over 2000 characters.
const DISCORD_ARGUMENT_BYTES: usize = 1000;
const CHAT_ARGUMENT_BYTES: usize = 2500;
const DISCORD_MAX_CHARS: usize = 2000;

/// Longest agent, tool or rule name shown, in characters.
const MAX_NAME_CHARS: usize = 100;

/// Longest rule message shown, in characters.
const MAX_MESSAGE_CHARS: usize = 300;

/// How much of a receiver's error answer is read.
const MAX_ANSWER_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A call is waiting for a person.
    Held,
    /// Nobody decided in time, so the call was parked for a later decision.
    Parked,
    /// A held or parked call ended without a decision, so it was blocked.
    Expired,
    /// A rule blocked a call.
    Blocked,
    /// Some alerts were not sent.
    Dropped,
    /// `razorwire test-alert`.
    Test,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Held => "held",
            Kind::Parked => "parked",
            Kind::Expired => "expired",
            Kind::Blocked => "blocked",
            Kind::Dropped => "dropped",
            Kind::Test => "test",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Kind::Held => "Tool call waiting for approval",
            Kind::Parked => "Tool call parked for a later decision",
            Kind::Expired => "Held tool call blocked without a decision",
            Kind::Blocked => "Tool call blocked",
            Kind::Dropped => "Some alerts were not sent",
            Kind::Test => "Razorwire test alert",
        }
    }
}

/// Which kinds of alert go out. `Dropped` and `Test` always do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Events {
    held: bool,
    parked: bool,
    expired: bool,
    blocked: bool,
}

impl Events {
    const DEFAULT: Events = Events {
        held: true,
        parked: true,
        expired: true,
        blocked: false,
    };

    fn parse(text: &str) -> Result<Events, String> {
        let mut events = Events::default();
        for word in text
            .split(',')
            .map(str::trim)
            .filter(|word| !word.is_empty())
        {
            match word.to_ascii_lowercase().as_str() {
                "held" => events.held = true,
                "parked" => events.parked = true,
                "expired" => events.expired = true,
                "blocked" => events.blocked = true,
                "all" => {
                    events = Events {
                        held: true,
                        parked: true,
                        expired: true,
                        blocked: true,
                    }
                }
                _ => {
                    return Err(format!(
                        "ALERT_EVENTS lists {:?}. Use a comma-separated list of held, parked, \
                         expired and blocked, or all",
                        word.chars().take(20).collect::<String>()
                    ))
                }
            }
        }
        if events == Events::default() {
            return Err("ALERT_EVENTS lists no events".into());
        }
        Ok(events)
    }

    fn wants(self, kind: Kind) -> bool {
        match kind {
            Kind::Held => self.held,
            Kind::Parked => self.parked,
            Kind::Expired => self.expired,
            Kind::Blocked => self.blocked,
            Kind::Dropped | Kind::Test => true,
        }
    }

    fn names(self) -> String {
        [
            (self.held, "held"),
            (self.parked, "parked"),
            (self.expired, "expired"),
            (self.blocked, "blocked"),
        ]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(", ")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Slack,
    Discord,
    Ntfy,
}

impl Format {
    fn parse(text: &str) -> Result<Format, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Format::Json),
            "slack" => Ok(Format::Slack),
            "discord" => Ok(Format::Discord),
            "ntfy" => Ok(Format::Ntfy),
            _ => Err("ALERT_FORMAT must be json, slack, discord or ntfy".into()),
        }
    }

    /// The format a well-known address takes. Anything else gets json.
    fn guess(url: &reqwest::Url) -> Format {
        let host = url.host_str().unwrap_or("").to_ascii_lowercase();
        let discord = [
            "discord.com",
            "discordapp.com",
            "ptb.discord.com",
            "canary.discord.com",
        ];
        if host == "hooks.slack.com" {
            Format::Slack
        } else if discord.contains(&host.as_str()) && url.path().starts_with("/api/webhooks/") {
            Format::Discord
        } else if host == "ntfy.sh" {
            Format::Ntfy
        } else {
            Format::Json
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Format::Json => "json",
            Format::Slack => "slack",
            Format::Discord => "discord",
            Format::Ntfy => "ntfy",
        }
    }
}

/// Where alerts go and how they are written. The address is never echoed,
/// in errors or anywhere else: a webhook URL is a secret.
pub struct Target {
    http: reqwest::Client,
    url: reqwest::Url,
    format: Format,
    key: Option<Vec<u8>>,
    /// Tool call arguments go into alerts.
    arguments: bool,
    events: Events,
    /// Where alerts go, without the path, for the startup banner.
    shown: String,
}

impl Target {
    /// Read the `ALERT_*` settings. `None` if `ALERT_URL` is not set.
    pub fn from_settings(
        setting: impl Fn(&str) -> Option<String>,
    ) -> Result<Option<Target>, String> {
        let Some(raw) = setting("ALERT_URL") else {
            for name in [
                "ALERT_FORMAT",
                "ALERT_KEY",
                "ALERT_EVENTS",
                "ALERT_ARGUMENTS",
            ] {
                if setting(name).is_some() {
                    return Err(format!(
                        "{name} is set but ALERT_URL is not, so no alert would go out"
                    ));
                }
            }
            return Ok(None);
        };
        let url = reqwest::Url::parse(raw.trim())
            .map_err(|_| "ALERT_URL is not a valid URL".to_string())?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err("ALERT_URL must not hold a user name or password".into());
        }
        let host = url.host_str().unwrap_or("").to_string();
        match url.scheme() {
            "https" => {}
            "http" if is_loopback_host(&host) => {}
            "http" => {
                return Err(
                    "ALERT_URL uses plain http to another machine, so alerts, and the address \
                     itself, would cross the network unencrypted. Use https"
                        .into(),
                )
            }
            _ => return Err("ALERT_URL must start with https://".into()),
        }
        let format = match setting("ALERT_FORMAT") {
            Some(text) => Format::parse(&text)?,
            None => Format::guess(&url),
        };
        let key = match setting("ALERT_KEY") {
            None => None,
            Some(_) if format != Format::Json => {
                return Err(format!(
                    "ALERT_KEY signs json alerts, and a {} receiver cannot check it. \
                     Unset ALERT_KEY, or set ALERT_FORMAT=json",
                    format.as_str()
                ))
            }
            Some(text) => {
                let key = unhex(text.trim()).ok_or_else(|| {
                    "ALERT_KEY must be hex. Create one with `razorwire new-alert-key`".to_string()
                })?;
                if key.len() < MIN_KEY_BYTES {
                    return Err(format!(
                        "ALERT_KEY is too short: it needs at least {MIN_KEY_BYTES} bytes ({} hex characters)",
                        MIN_KEY_BYTES * 2
                    ));
                }
                Some(key)
            }
        };
        let events = match setting("ALERT_EVENTS") {
            Some(text) => Events::parse(&text)?,
            None => Events::DEFAULT,
        };
        let arguments = match setting("ALERT_ARGUMENTS").as_deref().map(str::trim) {
            None | Some("show") => true,
            Some("hide") => false,
            Some(_) => return Err("ALERT_ARGUMENTS must be `show` or `hide`".into()),
        };
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(TIMEOUT)
            // An alert is never sent anywhere but the configured address.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| format!("cannot build the HTTP client: {err}"))?;
        let shown = match url.port() {
            Some(port) => format!("{}://{host}:{port}", url.scheme()),
            None => format!("{}://{host}", url.scheme()),
        };
        Ok(Some(Target {
            http,
            url,
            format,
            key,
            arguments,
            events,
            shown,
        }))
    }

    /// Where alerts go and which ones, for the startup banner. Never the
    /// whole address.
    pub fn describe(&self) -> String {
        let mut text = format!(
            "{} ({}): {}",
            self.shown,
            self.format.as_str(),
            self.events.names()
        );
        if !self.arguments {
            text.push_str("; arguments left out");
        }
        text
    }

    /// Send one test alert now, for `razorwire test-alert`.
    pub async fn send_test(&self) -> Result<(), String> {
        self.deliver(&Alert::new(Kind::Test, json!({}))).await
    }

    /// Send an alert, logging `alert_failed` if it cannot be delivered.
    async fn send_logged(&self, alert: &Alert, audit: &Audit) {
        if let Err(reason) = self.deliver(alert).await {
            let event = json!({
                "event": "alert_failed",
                "alert_id": alert.id,
                "kind": alert.kind.as_str(),
                "approval_id": alert.details["approval_id"],
                "reason": reason,
            });
            audit.record(None, event).await;
        }
    }

    /// Send an alert, trying again while the receiver is down or busy.
    async fn deliver(&self, alert: &Alert) -> Result<(), String> {
        let mut attempt = 1;
        loop {
            match self.post(alert).await {
                Ok(()) => return Ok(()),
                Err(failure) if failure.retry && attempt < ATTEMPTS => {
                    let wait = failure.wait.unwrap_or(match attempt {
                        1 => Duration::from_secs(2),
                        _ => Duration::from_secs(5),
                    });
                    tokio::time::sleep(wait).await;
                    attempt += 1;
                }
                Err(failure) => {
                    return Err(match attempt {
                        1 => failure.reason,
                        _ => format!("{} (after {attempt} tries)", failure.reason),
                    })
                }
            }
        }
    }

    /// One try.
    async fn post(&self, alert: &Alert) -> Result<(), Failure> {
        let (content_type, body, headers) = self.render(alert);
        let mut request = self
            .http
            .post(self.url.clone())
            .header(reqwest::header::CONTENT_TYPE, content_type);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if let Some(key) = &self.key {
            let timestamp = now_ms().to_string();
            let signature = signature(key, &timestamp, &body);
            request = request
                .header(TIMESTAMP_HEADER, &timestamp)
                .header(SIGNATURE_HEADER, format!("v1={signature}"));
        }
        let mut response = request.body(body).send().await.map_err(|err| Failure {
            reason: self.scrub(&describe_error(err)),
            retry: true,
            wait: None,
        })?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let wait = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|text| text.trim().parse::<u64>().ok())
            .map(|secs| Duration::from_secs(secs).min(MAX_RETRY_WAIT));
        let answer = self.scrub(&read_answer(&mut response).await);
        let reason = if answer.is_empty() {
            format!("the receiver answered {status}")
        } else {
            format!("the receiver answered {status}: {answer}")
        };
        Err(Failure {
            reason,
            retry: status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error(),
            wait,
        })
    }

    /// Take the address out of a message, in case a library or a receiver
    /// put it in.
    fn scrub(&self, text: &str) -> String {
        let mut text = text.replace(self.url.as_str(), &self.shown);
        let path = self.url.path();
        if path.len() > 1 {
            text = text.replace(path, "/…");
        }
        if let Some(query) = self.url.query().filter(|query| !query.is_empty()) {
            text = text.replace(query, "…");
        }
        text
    }

    fn limit(&self, bytes: usize) -> Option<usize> {
        self.arguments.then_some(bytes)
    }

    /// The content type, body and extra headers of one alert.
    fn render(&self, alert: &Alert) -> (&'static str, String, Vec<(&'static str, &'static str)>) {
        let title = alert.kind.title();
        match self.format {
            Format::Slack => {
                let text = format!(
                    "*{title}*\n{}",
                    slack(&alert.parts(self.limit(CHAT_ARGUMENT_BYTES)))
                );
                let body = json!({ "text": text, "unfurl_links": false, "unfurl_media": false });
                ("application/json", body.to_string(), Vec::new())
            }
            Format::Discord => {
                let mut content = format!(
                    "**{title}**\n{}",
                    discord(&alert.parts(self.limit(DISCORD_ARGUMENT_BYTES)))
                );
                if content.chars().count() > DISCORD_MAX_CHARS {
                    content = content.chars().take(DISCORD_MAX_CHARS - 1).collect();
                    content.push('…');
                }
                let body = json!({
                    "content": content,
                    "username": "Razorwire",
                    // Nobody is pinged, whatever the text says.
                    "allowed_mentions": { "parse": [] },
                    // No link previews.
                    "flags": 4,
                });
                ("application/json", body.to_string(), Vec::new())
            }
            Format::Ntfy => {
                let body = plain(&alert.parts(self.limit(CHAT_ARGUMENT_BYTES)));
                let priority = if alert.kind == Kind::Held {
                    "high"
                } else {
                    "default"
                };
                let mut headers = vec![("title", title), ("priority", priority)];
                if alert.kind == Kind::Held {
                    headers.push(("tags", "warning"));
                }
                ("text/plain; charset=utf-8", body, headers)
            }
            Format::Json => {
                let mut body = json!({
                    "id": alert.id,
                    "kind": alert.kind.as_str(),
                    "title": title,
                    "text": plain(&alert.parts(None)),
                    "created_ms": alert.created_ms,
                });
                if let (Some(fields), Some(details)) =
                    (body.as_object_mut(), alert.details.as_object())
                {
                    for (name, value) in details {
                        if name == "arguments" && !self.arguments {
                            continue;
                        }
                        fields.insert(name.clone(), value.clone());
                    }
                }
                ("application/json", json_line(&body), Vec::new())
            }
        }
    }
}

struct Failure {
    reason: String,
    /// Worth another try.
    retry: bool,
    /// How long the receiver asked us to wait.
    wait: Option<Duration>,
}

/// Why a request failed, without the address.
fn describe_error(err: reqwest::Error) -> String {
    let what = if err.is_timeout() {
        "it timed out"
    } else if err.is_connect() {
        "could not connect"
    } else {
        "the request failed"
    };
    let err = err.without_url();
    let mut cause = None;
    let mut source = std::error::Error::source(&err);
    while let Some(inner) = source {
        cause = Some(inner.to_string());
        source = std::error::Error::source(inner);
    }
    match cause {
        Some(cause) => format!("{what}: {}", clean_line(&cause, 200)),
        None => what.to_string(),
    }
}

async fn read_answer(response: &mut reqwest::Response) -> String {
    let mut bytes = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        bytes.extend_from_slice(&chunk);
        if bytes.len() >= MAX_ANSWER_BYTES {
            break;
        }
    }
    clean_line(&String::from_utf8_lossy(&bytes), 200)
}

/// One alert. `details` holds what is known about the call: `approval_id`,
/// `agent`, `tool`, `rule`, `message`, `arguments`, `until_ms`, and `why`
/// for an expired call or `count` for dropped alerts.
struct Alert {
    id: String,
    kind: Kind,
    details: Value,
    created_ms: u64,
}

impl Alert {
    fn new(kind: Kind, details: Value) -> Alert {
        let created_ms = now_ms();
        let mut bytes = [0u8; 12];
        let id = match getrandom::fill(&mut bytes) {
            Ok(()) => format!("alr_{}", hex(&bytes)),
            Err(_) => format!("alr_t{created_ms}"),
        };
        Alert {
            id,
            kind,
            details,
            created_ms,
        }
    }

    /// A name from the details, cleaned up to show on one line.
    fn name(&self, field: &str) -> Option<String> {
        self.details[field]
            .as_str()
            .map(|text| clean_line(text, MAX_NAME_CHARS))
            .filter(|text| !text.is_empty())
    }

    /// What the alert says, apart from its title. With `argument_bytes`,
    /// the call's arguments are shown, cut to that size.
    fn parts(&self, argument_bytes: Option<usize>) -> Vec<Part> {
        use Part::{Break, Code, Fixed};
        let mut parts = Vec::new();
        let agent = self.name("agent");
        let tool = self.name("tool");
        let rule = self.name("rule");
        let id = self.name("approval_id");
        let until = self.details["until_ms"]
            .as_u64()
            .map(|until| span(until.saturating_sub(self.created_ms).saturating_add(500) / 1000));
        match self.kind {
            Kind::Held => {
                push_agent(&mut parts, agent, true);
                parts.push(Fixed(" wants to run ".into()));
                push_tool(&mut parts, tool);
                parts.push(Fixed(". ".into()));
                match rule {
                    Some(rule) => {
                        parts.push(Fixed("Rule ".into()));
                        parts.push(Code(rule));
                    }
                    None => parts.push(Fixed("A rule".into())),
                }
                parts.push(Fixed(" holds it for a person".into()));
                self.push_reason(&mut parts);
                parts.push(Break);
                parts.push(Fixed(match until {
                    Some(left) => format!("Decide within {left}:"),
                    None => "Decide:".into(),
                }));
                push_commands(&mut parts, id);
                self.push_arguments(&mut parts, argument_bytes);
            }
            Kind::Parked => {
                parts.push(Fixed("Nobody decided on ".into()));
                push_tool(&mut parts, tool);
                parts.push(Fixed(" from ".into()));
                push_agent(&mut parts, agent, false);
                parts.push(Fixed(format!(
                    " in time, so it is parked{}. If you approve it, the executor carries it out:",
                    until.map(|left| format!(" for {left}")).unwrap_or_default()
                )));
                push_commands(&mut parts, id);
                self.push_arguments(&mut parts, argument_bytes);
            }
            Kind::Expired => {
                match self.details["why"].as_str() {
                    Some("withdrawn") => {
                        push_agent(&mut parts, agent, true);
                        parts.push(Fixed(" stopped waiting, so ".into()));
                        push_tool(&mut parts, tool);
                        parts.push(Fixed(
                            " was withdrawn without a decision. It did not run.".into(),
                        ));
                    }
                    Some("parked") => {
                        parts.push(Fixed("Nobody decided on the parked call ".into()));
                        push_tool(&mut parts, tool);
                        parts.push(Fixed(" from ".into()));
                        push_agent(&mut parts, agent, false);
                        parts.push(Fixed(" in time, so it was dropped. It did not run.".into()));
                    }
                    _ => {
                        parts.push(Fixed("Nobody decided on ".into()));
                        push_tool(&mut parts, tool);
                        parts.push(Fixed(" from ".into()));
                        push_agent(&mut parts, agent, false);
                        parts.push(Fixed(" in time, so it was blocked. It did not run.".into()));
                    }
                }
                if let Some(id) = id {
                    parts.push(Break);
                    parts.push(Fixed("Approval id: ".into()));
                    parts.push(Code(id));
                }
            }
            Kind::Blocked => {
                match rule {
                    Some(rule) => {
                        parts.push(Fixed("Rule ".into()));
                        parts.push(Code(rule));
                    }
                    None => parts.push(Fixed("Razorwire".into())),
                }
                parts.push(Fixed(" blocked ".into()));
                push_tool(&mut parts, tool);
                parts.push(Fixed(" from ".into()));
                push_agent(&mut parts, agent, false);
                self.push_reason(&mut parts);
                self.push_arguments(&mut parts, argument_bytes);
            }
            Kind::Dropped => {
                let count = self.details["count"].as_u64().unwrap_or(0);
                let (alerts, were) = if count == 1 {
                    ("alert", "was")
                } else {
                    ("alerts", "were")
                };
                parts.push(Fixed(format!(
                    "{count} more {alerts} in the last minute {were} not sent, to keep this \
                     channel readable. Run "
                )));
                parts.push(Code("razorwire approvals".into()));
                parts.push(Fixed(" to see what is waiting.".into()));
            }
            Kind::Test => parts.push(Fixed(
                "This is a test from Razorwire. Tool calls held for approval will show up here."
                    .into(),
            )),
        }
        parts
    }

    /// `: <the rule's message>.`, or just `.` without one.
    fn push_reason(&self, parts: &mut Vec<Part>) {
        let message = self.details["message"]
            .as_str()
            .map(|text| clean_line(text, MAX_MESSAGE_CHARS))
            .filter(|text| !text.is_empty());
        match message {
            Some(message) => {
                let end = if message.ends_with(['.', '!', '?']) {
                    ""
                } else {
                    "."
                };
                parts.push(Part::Fixed(": ".into()));
                parts.push(Part::Text(message));
                parts.push(Part::Fixed(end.into()));
            }
            None => parts.push(Part::Fixed(".".into())),
        }
    }

    fn push_arguments(&self, parts: &mut Vec<Part>, argument_bytes: Option<usize>) {
        let Some(limit) = argument_bytes else {
            return;
        };
        let arguments = &self.details["arguments"];
        if arguments.is_null() {
            return;
        }
        let text = serde_json::to_string_pretty(arguments).unwrap_or_default();
        parts.push(Part::Break);
        parts.push(Part::Fixed("Arguments, as the model wrote them:".into()));
        parts.push(Part::Block(clean_block(&text, limit)));
    }
}

fn push_agent(parts: &mut Vec<Part>, agent: Option<String>, first: bool) {
    match (agent, first) {
        (Some(agent), first) => {
            parts.push(Part::Fixed(if first { "Agent " } else { "agent " }.into()));
            parts.push(Part::Code(agent));
        }
        (None, true) => parts.push(Part::Fixed("An agent".into())),
        (None, false) => parts.push(Part::Fixed("an agent".into())),
    }
}

fn push_tool(parts: &mut Vec<Part>, tool: Option<String>) {
    match tool {
        Some(tool) => parts.push(Part::Code(tool)),
        None => parts.push(Part::Fixed("a tool call with no name".into())),
    }
}

fn push_commands(parts: &mut Vec<Part>, id: Option<String>) {
    if let Some(id) = id {
        parts.push(Part::Break);
        parts.push(Part::Code(format!("razorwire approve {id}")));
        parts.push(Part::Break);
        parts.push(Part::Code(format!("razorwire deny {id} [reason]")));
    }
}

/// A length of time in words: `45 seconds`, `5 minutes`, `7 days`.
fn span(secs: u64) -> String {
    match secs {
        0..=1 => "a second".into(),
        2..=119 => format!("{secs} seconds"),
        120..=7199 => format!("{} minutes", (secs + 30) / 60),
        7200..=172_799 => format!("{} hours", (secs + 1800) / 3600),
        _ => format!("{} days", (secs + 43_200) / 86_400),
    }
}

/// A piece of a message. Names and arguments come from the model, so each
/// format escapes them in its own way.
enum Part {
    /// Razorwire's own words.
    Fixed(String),
    /// Prose from the policy.
    Text(String),
    /// A name or a command, as code on one line.
    Code(String),
    /// Arguments, as a block of code.
    Block(String),
    Break,
}

/// Plain text, for ntfy and the `text` field of json alerts.
fn plain(parts: &[Part]) -> String {
    let mut out = String::new();
    for part in parts {
        match part {
            Part::Fixed(text) | Part::Text(text) | Part::Code(text) => out.push_str(text),
            Part::Block(text) => {
                out.push('\n');
                out.push_str(text);
            }
            Part::Break => out.push('\n'),
        }
    }
    out
}

/// Slack's mrkdwn. `&`, `<` and `>` are escaped everywhere, so nothing can
/// make a link or mention anyone, and code cannot close its backticks.
fn slack(parts: &[Part]) -> String {
    let escape = |text: &str| {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let mut out = String::new();
    for part in parts {
        match part {
            Part::Fixed(text) => out.push_str(text),
            Part::Text(text) => out.push_str(&escape(text)),
            Part::Code(text) => {
                out.push('`');
                out.push_str(&escape(&no_backticks(text)));
                out.push('`');
            }
            Part::Block(text) => {
                out.push_str("\n```\n");
                out.push_str(&escape(&no_backticks(text)));
                out.push_str("\n```");
            }
            Part::Break => out.push('\n'),
        }
    }
    out
}

/// Discord's markdown. Prose has its markup characters escaped, and code
/// cannot close its backticks. Mentions are turned off in the request too.
fn discord(parts: &[Part]) -> String {
    let mut out = String::new();
    for part in parts {
        match part {
            Part::Fixed(text) => out.push_str(text),
            Part::Text(text) => {
                for c in text.chars() {
                    if "\\*_~`|<>[]()#-@".contains(c) {
                        out.push('\\');
                    }
                    out.push(c);
                }
            }
            Part::Code(text) => {
                out.push('`');
                out.push_str(&no_backticks(text));
                out.push('`');
            }
            Part::Block(text) => {
                out.push_str("\n```\n");
                out.push_str(&no_backticks(text));
                out.push_str("\n```");
            }
            Part::Break => out.push('\n'),
        }
    }
    out
}

/// A backtick would end the code early, so it is swapped for a look-alike.
fn no_backticks(text: &str) -> String {
    text.replace('`', "\u{02cb}")
}

/// Characters that do not show but can change how text reads: direction
/// marks and overrides, zero-width characters.
fn invisible(c: char) -> bool {
    matches!(
        c,
        '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}'
    )
}

/// One line of text: control and invisible characters become spaces, and
/// it is cut to `max_chars`.
fn clean_line(text: &str, max_chars: usize) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| {
            if c.is_control() || invisible(c) {
                ' '
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.chars().count() <= max_chars {
        return cleaned.to_string();
    }
    let mut cut: String = cleaned.chars().take(max_chars.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

/// A block of text that keeps its line breaks, cut to `max_bytes`.
fn clean_block(text: &str, max_bytes: usize) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| {
            if (c.is_control() && c != '\n') || invisible(c) {
                ' '
            } else {
                c
            }
        })
        .collect();
    if cleaned.len() <= max_bytes {
        return cleaned;
    }
    let mut end = max_bytes;
    while !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n… cut short", &cleaned[..end])
}

/// The proxy's side of alerts: queue one and move on.
pub struct Alerts {
    queue: mpsc::Sender<Alert>,
    events: Events,
    /// Alerts that did not fit in the queue and are not logged yet.
    dropped: Arc<AtomicU64>,
    described: String,
}

impl Alerts {
    /// Start the task that sends alerts. Must be called inside the runtime.
    pub fn start(target: Target, audit: Arc<Audit>) -> Alerts {
        Alerts::start_with(target, audit, WINDOW_MS)
    }

    fn start_with(target: Target, audit: Arc<Audit>, window_ms: u64) -> Alerts {
        let (queue, inbox) = mpsc::channel(QUEUE);
        let dropped = Arc::new(AtomicU64::new(0));
        let alerts = Alerts {
            queue,
            events: target.events,
            dropped: dropped.clone(),
            described: target.describe(),
        };
        tokio::spawn(send_all(target, inbox, dropped, audit, window_ms));
        alerts
    }

    pub fn describe(&self) -> &str {
        &self.described
    }

    /// Whether alerts of this kind go out, so a caller can skip building one.
    pub fn wants(&self, kind: Kind) -> bool {
        self.events.wants(kind)
    }

    /// Queue an alert. Never waits: when the queue is full, the alert is
    /// dropped and counted.
    pub fn notify(&self, kind: Kind, details: Value) {
        if !self.events.wants(kind) {
            return;
        }
        if self.queue.try_send(Alert::new(kind, details)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Send queued alerts one at a time, at most `MAX_PER_MINUTE` per window.
/// When a window ends with alerts held back, say how many in one message.
async fn send_all(
    target: Target,
    mut inbox: mpsc::Receiver<Alert>,
    dropped: Arc<AtomicU64>,
    audit: Arc<Audit>,
    window_ms: u64,
) {
    let mut window_start = now_ms();
    let mut sent = 0u32;
    let mut held_back = 0u64;
    loop {
        let waiting = held_back > 0 || dropped.load(Ordering::Relaxed) > 0;
        let next = if waiting {
            // Wake up when the window is over, to say what was not sent.
            let left = window_start
                .saturating_add(window_ms)
                .saturating_sub(now_ms());
            match tokio::time::timeout(Duration::from_millis(left), inbox.recv()).await {
                Ok(Some(alert)) => Some(alert),
                Ok(None) => break,
                Err(_) => None,
            }
        } else {
            match inbox.recv().await {
                Some(alert) => Some(alert),
                None => break,
            }
        };
        let now = now_ms();
        if now.saturating_sub(window_start) >= window_ms {
            let count = held_back.saturating_add(dropped.swap(0, Ordering::Relaxed));
            if count > 0 {
                let event = json!({ "event": "alerts_dropped", "count": count });
                audit.record(None, event).await;
                let summary = Alert::new(Kind::Dropped, json!({ "count": count }));
                target.send_logged(&summary, &audit).await;
            }
            window_start = now;
            sent = 0;
            held_back = 0;
        }
        let Some(alert) = next else {
            continue;
        };
        if sent >= MAX_PER_MINUTE {
            held_back += 1;
            continue;
        }
        sent += 1;
        target.send_logged(&alert, &audit).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use axum::{extract::State, http::HeaderMap, routing::post, Router};

    use super::*;

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn settings<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        }
    }

    fn target(pairs: &[(&str, &str)]) -> Target {
        Target::from_settings(settings(pairs)).unwrap().unwrap()
    }

    /// A held call whose model tried to smuggle markup into the message.
    fn sneaky() -> Value {
        json!({
            "approval_id": "apr_0123",
            "agent": "support-bot",
            "tool": "refund`<!channel>`",
            "rule": "big-refunds",
            "message": "Refunds over $500 need a person",
            "arguments": { "amount": 750, "note": "<https://evil.example|Approve here> @everyone ```" },
            "until_ms": now_ms() + 300_000,
        })
    }

    #[test]
    fn alert_settings_are_checked() {
        let slack = "https://hooks.slack.com/services/T000/B000/s3cret";
        assert_eq!(target(&[("ALERT_URL", slack)]).format, Format::Slack);
        let discord = "https://discord.com/api/webhooks/1/s3cret";
        assert_eq!(target(&[("ALERT_URL", discord)]).format, Format::Discord);
        assert_eq!(
            target(&[("ALERT_URL", "https://ntfy.sh/razorwire-s3cret")]).format,
            Format::Ntfy
        );
        assert_eq!(
            target(&[("ALERT_URL", "https://alerts.example.com/hook")]).format,
            Format::Json
        );
        let own_ntfy = target(&[
            ("ALERT_URL", "https://push.example.com/topic"),
            ("ALERT_FORMAT", "ntfy"),
        ]);
        assert_eq!(own_ntfy.format, Format::Ntfy);
        assert!(Target::from_settings(settings(&[])).unwrap().is_none());

        // The banner never shows the secret part of the address.
        let shown = target(&[("ALERT_URL", slack)]).describe();
        assert_eq!(
            shown,
            "https://hooks.slack.com (slack): held, parked, expired"
        );
        assert!(!shown.contains("s3cret"));

        let refused = [
            (
                vec![("ALERT_URL", "http://alerts.example.com/")],
                "plain http",
            ),
            (vec![("ALERT_URL", "ftp://127.0.0.1/")], "https://"),
            (
                vec![("ALERT_URL", "https://u:p@alerts.example.com/")],
                "user name",
            ),
            (vec![("ALERT_URL", "not a url")], "not a valid URL"),
            (vec![("ALERT_FORMAT", "slack")], "ALERT_URL is not"),
            (
                vec![("ALERT_URL", slack), ("ALERT_FORMAT", "email")],
                "json, slack",
            ),
            (
                vec![("ALERT_URL", slack), ("ALERT_KEY", KEY)],
                "cannot check it",
            ),
            (
                vec![("ALERT_URL", "https://a.example.com/"), ("ALERT_KEY", "zz")],
                "hex",
            ),
            (
                vec![
                    ("ALERT_URL", "https://a.example.com/"),
                    ("ALERT_KEY", "abcd"),
                ],
                "too short",
            ),
            (
                vec![("ALERT_URL", slack), ("ALERT_EVENTS", "held,typo")],
                "\"typo\"",
            ),
            (
                vec![("ALERT_URL", slack), ("ALERT_EVENTS", " , ")],
                "no events",
            ),
            (
                vec![("ALERT_URL", slack), ("ALERT_ARGUMENTS", "maybe")],
                "show",
            ),
        ];
        for (pairs, expected) in refused {
            match Target::from_settings(settings(&pairs)) {
                Ok(_) => panic!("{pairs:?} should be refused"),
                Err(err) => {
                    assert!(err.contains(expected), "{err}");
                    assert!(!err.contains("s3cret"), "{err}");
                }
            }
        }
        assert!(Target::from_settings(settings(&[("ALERT_URL", "http://127.0.0.1:9/x")])).is_ok());
    }

    #[test]
    fn events_can_be_chosen() {
        let events = Events::parse("held, blocked").unwrap();
        assert!(events.wants(Kind::Held) && events.wants(Kind::Blocked));
        assert!(!events.wants(Kind::Parked) && !events.wants(Kind::Expired));
        assert!(events.wants(Kind::Dropped) && events.wants(Kind::Test));
        assert_eq!(
            Events::parse("ALL").unwrap().names(),
            "held, parked, expired, blocked"
        );
        assert!(!Events::DEFAULT.wants(Kind::Blocked));
    }

    #[test]
    fn slack_alerts_cannot_link_or_mention() {
        let slack = target(&[("ALERT_URL", "https://hooks.slack.com/services/T/B/s3cret")]);
        let (_, body, _) = slack.render(&Alert::new(Kind::Held, sneaky()));
        let body: Value = serde_json::from_str(&body).unwrap();
        let text = body["text"].as_str().unwrap();
        assert!(
            text.starts_with("*Tool call waiting for approval*\n"),
            "{text}"
        );
        assert!(
            text.contains("Agent `support-bot` wants to run `refundˋ&lt;!channel&gt;ˋ`"),
            "{text}"
        );
        assert!(
            text.contains(
                "Rule `big-refunds` holds it for a person: Refunds over $500 need a person."
            ),
            "{text}"
        );
        assert!(text.contains("Decide within 5 minutes:"), "{text}");
        assert!(text.contains("`razorwire approve apr_0123`"), "{text}");
        assert!(
            text.contains("&lt;https://evil.example|Approve here&gt;"),
            "{text}"
        );
        assert!(!text.contains('<') && !text.contains('>'), "{text}");
        // The only code fences are the two around the arguments.
        assert_eq!(text.matches("```").count(), 2, "{text}");
        assert_eq!(body["unfurl_links"], false);
    }

    #[test]
    fn discord_alerts_ping_nobody_and_fit() {
        let discord = target(&[("ALERT_URL", "https://discord.com/api/webhooks/1/s3cret")]);
        let mut details = sneaky();
        details["message"] = json!("Ask @everyone in [the channel](https://evil.example)");
        details["arguments"] = json!({ "blob": "x".repeat(50_000) });
        let (_, body, _) = discord.render(&Alert::new(Kind::Held, details));
        let body: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["allowed_mentions"], json!({ "parse": [] }));
        assert_eq!(body["flags"], 4);
        let content = body["content"].as_str().unwrap();
        assert!(content.chars().count() <= DISCORD_MAX_CHARS);
        assert!(
            content.contains("Ask \\@everyone in \\[the channel\\]\\(https://evil.example\\)"),
            "{content}"
        );
        assert!(content.contains("… cut short"), "{content}");
        assert_eq!(content.matches("```").count(), 2, "{content}");
    }

    #[test]
    fn ntfy_alerts_are_plain_text() {
        let ntfy = target(&[("ALERT_URL", "https://ntfy.sh/razorwire-s3cret")]);
        let (content_type, body, headers) = ntfy.render(&Alert::new(Kind::Held, sneaky()));
        assert!(content_type.starts_with("text/plain"));
        assert!(headers.contains(&("title", "Tool call waiting for approval")));
        assert!(headers.contains(&("priority", "high")));
        assert!(
            body.contains("razorwire approve apr_0123\nrazorwire deny apr_0123 [reason]"),
            "{body}"
        );
        assert!(body.contains("\"amount\": 750"), "{body}");

        let (_, body, headers) = ntfy.render(&Alert::new(
            Kind::Expired,
            json!({ "approval_id": "apr_9", "agent": "bot", "tool": "drop", "why": "withdrawn" }),
        ));
        assert!(headers.contains(&("priority", "default")));
        assert_eq!(
            body,
            "Agent bot stopped waiting, so drop was withdrawn without a decision. It did not run.\nApproval id: apr_9"
        );
    }

    #[test]
    fn json_alerts_carry_the_details() {
        let hook = target(&[("ALERT_URL", "https://alerts.example.com/hook")]);
        let alert = Alert::new(Kind::Parked, sneaky());
        let (content_type, body, _) = hook.render(&alert);
        assert_eq!(content_type, "application/json");
        let body: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["id"], json!(alert.id));
        assert_eq!(body["kind"], "parked");
        assert_eq!(body["approval_id"], "apr_0123");
        assert_eq!(body["arguments"]["amount"], 750);
        assert!(body["text"]
            .as_str()
            .unwrap()
            .contains("razorwire approve apr_0123"));

        let hidden = target(&[
            ("ALERT_URL", "https://alerts.example.com/hook"),
            ("ALERT_ARGUMENTS", "hide"),
        ]);
        let (_, body, _) = hidden.render(&alert);
        assert!(!body.contains("amount"), "{body}");
        let slack = target(&[
            ("ALERT_URL", "https://hooks.slack.com/services/T/B/s3cret"),
            ("ALERT_ARGUMENTS", "hide"),
        ]);
        let (_, body, _) = slack.render(&alert);
        assert!(!body.contains("amount") && !body.contains("```"), "{body}");
    }

    #[test]
    fn hidden_characters_are_taken_out() {
        assert_eq!(
            clean_line("drop\u{202e}esab\n_atad", 100),
            "drop esab _atad"
        );
        assert_eq!(clean_line(&"x".repeat(150), 100).chars().count(), 100);
        assert_eq!(clean_block("a\nb\u{200b}c\u{7}", 100), "a\nb c ");
        assert_eq!(span(300), "5 minutes");
        assert_eq!(span(45), "45 seconds");
        assert_eq!(span(7 * 86_400), "7 days");
    }

    /// A webhook receiver on this machine that records what it is sent and
    /// answers with the statuses it is given, last first.
    #[derive(Clone, Default)]
    struct Receiver {
        got: Arc<Mutex<Vec<(HeaderMap, String)>>>,
        answers: Arc<Mutex<Vec<u16>>>,
    }

    impl Receiver {
        async fn start(answers: Vec<u16>) -> (Receiver, String) {
            async fn take(
                State(receiver): State<Receiver>,
                headers: HeaderMap,
                body: String,
            ) -> (
                axum::http::StatusCode,
                [(&'static str, &'static str); 1],
                &'static str,
            ) {
                receiver.got.lock().unwrap().push((headers, body));
                let status = receiver.answers.lock().unwrap().pop().unwrap_or(200);
                (
                    axum::http::StatusCode::from_u16(status).unwrap(),
                    [("retry-after", "0")],
                    "nope",
                )
            }
            let receiver = Receiver {
                answers: Arc::new(Mutex::new(answers)),
                ..Receiver::default()
            };
            let app = Router::new()
                .route("/hook/s3cret", post(take))
                .with_state(receiver.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            (receiver, format!("http://{address}/hook/s3cret"))
        }

        fn bodies(&self) -> Vec<String> {
            self.got
                .lock()
                .unwrap()
                .iter()
                .map(|(_, body)| body.clone())
                .collect()
        }
    }

    async fn log(name: &str) -> Arc<Audit> {
        let path = std::env::temp_dir().join(format!(
            "razorwire-alerts-{name}-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        Arc::new(Audit::open(&path.to_string_lossy(), None).await.unwrap())
    }

    #[tokio::test]
    async fn json_alerts_are_signed() {
        let (receiver, url) = Receiver::start(Vec::new()).await;
        let hook = target(&[("ALERT_URL", url.as_str()), ("ALERT_KEY", KEY)]);
        hook.send_test().await.unwrap();
        let got = receiver.got.lock().unwrap();
        let (headers, body) = &got[0];
        let timestamp = headers[TIMESTAMP_HEADER].to_str().unwrap();
        let expected = format!("v1={}", signature(&unhex(KEY).unwrap(), timestamp, body));
        assert_eq!(headers[SIGNATURE_HEADER], expected.as_str());
        assert!(body.contains("\"kind\":\"test\""), "{body}");
    }

    #[tokio::test]
    async fn a_busy_receiver_is_tried_again() {
        let (receiver, url) = Receiver::start(vec![200, 503, 429]).await;
        let hook = target(&[("ALERT_URL", url.as_str())]);
        hook.send_test().await.unwrap();
        let bodies = receiver.bodies();
        assert_eq!(bodies.len(), 3);
        // Every try carries the same id, so a receiver can drop repeats.
        assert!(bodies.iter().all(|body| body == &bodies[0]));
    }

    #[tokio::test]
    async fn a_refused_alert_is_logged_without_the_address() {
        let (receiver, url) = Receiver::start(vec![404]).await;
        let audit = log("refused").await;
        let alerts = Alerts::start(target(&[("ALERT_URL", url.as_str())]), audit.clone());
        alerts.notify(Kind::Held, sneaky());
        let mut failed = None;
        for _ in 0..100 {
            let events = audit.events().await.unwrap();
            failed = events
                .into_iter()
                .find(|event| event["event"] == "alert_failed");
            if failed.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let failed = failed.expect("alert_failed is logged");
        assert_eq!(receiver.bodies().len(), 1, "a 404 is not tried again");
        assert_eq!(failed["approval_id"], "apr_0123");
        assert_eq!(failed["kind"], "held");
        let reason = failed["reason"].as_str().unwrap();
        assert!(
            reason.contains("404") && reason.contains("nope"),
            "{reason}"
        );
        assert!(!failed.to_string().contains("s3cret"), "{failed}");
    }

    #[tokio::test]
    async fn an_unreachable_receiver_is_logged_without_the_address() {
        // Nothing listens on port 9 on this machine.
        let hook = target(&[("ALERT_URL", "http://127.0.0.1:9/hook/s3cret?auth=t0ken")]);
        let err = hook
            .post(&Alert::new(Kind::Test, json!({})))
            .await
            .err()
            .unwrap();
        assert!(err.retry);
        assert!(
            err.reason.starts_with("could not connect"),
            "{}",
            err.reason
        );
        assert!(
            !err.reason.contains("s3cret") && !err.reason.contains("t0ken"),
            "{}",
            err.reason
        );
    }

    #[tokio::test]
    async fn a_flood_of_alerts_is_summed_up() {
        let (receiver, url) = Receiver::start(Vec::new()).await;
        let audit = log("flood").await;
        let alerts =
            Alerts::start_with(target(&[("ALERT_URL", url.as_str())]), audit.clone(), 2000);
        for _ in 0..25 {
            alerts.notify(Kind::Held, sneaky());
        }
        // Blocked alerts are off by default, so this one is not even queued.
        alerts.notify(Kind::Blocked, sneaky());
        for _ in 0..200 {
            if receiver.bodies().len() > MAX_PER_MINUTE as usize {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let bodies = receiver.bodies();
        assert_eq!(bodies.len(), MAX_PER_MINUTE as usize + 1);
        let summary: Value = serde_json::from_str(&bodies[MAX_PER_MINUTE as usize]).unwrap();
        assert_eq!(summary["kind"], "dropped");
        assert_eq!(summary["count"], 5);
        assert!(summary["text"]
            .as_str()
            .unwrap()
            .starts_with("5 more alerts"));
        let events = audit.events().await.unwrap();
        let dropped: Vec<_> = events
            .iter()
            .filter(|event| event["event"] == "alerts_dropped")
            .collect();
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0]["count"], 5);
    }
}
