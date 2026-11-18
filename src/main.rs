//! Razorwire: a proxy between an AI agent and its model provider that checks
//! every tool call against a policy before the agent can run it.
//!
//! `razorwire` with no command starts the proxy. The other commands create
//! keys, check files, and drive the admin API.

mod admin;
mod alerts;
mod approvals;
mod audit;
mod auth;
mod executor;
mod openai;
mod policy;
mod proxy;
mod rollback;
mod sse;
mod tls;

use std::{env, io::Write, net::SocketAddr, process, sync::Arc, time::Duration};

use axum::{extract::DefaultBodyLimit, routing::get, serve::ListenerExt, Router};
use serde_json::json;

use audit::Audit;
use auth::{Keys, Role};
use policy::{Mode, Policy};
use proxy::{AppState, Config, Settings};

/// Default and longest time a held call waits for a human, in seconds.
const DEFAULT_APPROVAL_TIMEOUT_SECS: u64 = 300;
const MAX_APPROVAL_TIMEOUT_SECS: u64 = 3600;

const DEFAULT_KEYS_FILE: &str = "razorwire.keys";

const HELP: &str = "\
Razorwire checks every tool call an AI agent makes before the agent can run it.

Usage:
  razorwire                        start the proxy (same as `razorwire serve`)
  razorwire new-key <agent|admin> <name>
                                   create a key and add its hash to the keys file
  razorwire keys                   list the keys in the keys file
  razorwire revoke-key <name> [fingerprint]
                                   remove a key from the keys file
  razorwire new-audit-key          create a key for signing the audit log
  razorwire check-policy <file>    check a policy file and exit
  razorwire verify-log [file]      check that the audit log was not tampered with
  razorwire approvals              list tool calls waiting for approval, and parked ones
  razorwire approve <id> [reason]  let a held tool call through, or run a parked one
  razorwire deny <id> [reason]     block a held or parked tool call
  razorwire reload                 re-read the policy and keys files
  razorwire rollback [--agent <name>] [--since <30m|2h|1d>] [<undo id>...] [--run]
                                   show what agents did and how it would be undone;
                                   with --run, undo it, newest first
  razorwire new-executor-key       create a key for signing requests to the executor
  razorwire test-alert             send a test alert to ALERT_URL
  razorwire new-alert-key          create a key for signing json alerts

The proxy is configured with environment variables:
  UPSTREAM_URL            provider to forward to (default https://api.openai.com)
  UPSTREAM_API_KEY        provider key the proxy sends, so agents never hold it
  LISTEN_ADDR             where to listen (default 127.0.0.1:8080)
  POLICY_FILE             policy to enforce (unset: log only, block nothing)
  KEYS_FILE               agent and admin keys (default for new-key: razorwire.keys)
  AUDIT_LOG               audit log file (default audit.jsonl)
  AUDIT_KEY               signs the audit log so tampering shows
  APPROVAL_TIMEOUT_SECS   how long a held call waits for a human (default 300)
  TLS_CERT, TLS_KEY       PEM certificate chain and PKCS#8 key: serve https
  STREAM_MODE             live (default): streamed text goes out as it arrives;
                          hold: the whole stream waits until it is checked
  EXECUTOR_URL, EXECUTOR_KEY
                          a service that carries out undos and parked calls;
                          turns on rollback and approve-later
  ALERT_URL               where to send an alert when a call is held: a Slack or
                          Discord webhook, an ntfy topic, or any https address
  ALERT_FORMAT            json, slack, discord or ntfy (default: from the address)
  ALERT_EVENTS            held,parked,expired (default); add blocked, or say all
  ALERT_ARGUMENTS         show (default) or hide the call's arguments in alerts
  ALERT_KEY               signs json alerts, like requests to the executor

The admin commands use RAZORWIRE_URL (default http://127.0.0.1:8080),
RAZORWIRE_ADMIN_KEY, and RAZORWIRE_CA_CERT to trust a self-signed certificate.
";

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or(&[]);
    let result = match args.first().map(String::as_str) {
        None | Some("serve") => serve().await,
        Some("new-key") => new_key(rest).await,
        Some("keys") => list_keys(rest),
        Some("revoke-key") => revoke_key(rest).await,
        Some("new-audit-key") => new_audit_key(),
        Some("check-policy") => check_policy(rest),
        Some("verify-log") => verify_log(rest),
        Some("approvals") => match admin::Client::from_env() {
            Ok(client) => client.approvals().await,
            Err(err) => Err(err),
        },
        Some(command @ ("approve" | "deny")) => decide(command == "approve", rest).await,
        Some("reload") => match admin::Client::from_env() {
            Ok(client) => client.reload().await,
            Err(err) => Err(err),
        },
        Some("rollback") => rollback(rest).await,
        Some("new-executor-key") => new_executor_key(),
        Some("test-alert") => test_alert().await,
        Some("new-alert-key") => new_alert_key(),
        Some("help" | "--help" | "-h") => {
            print!("{HELP}");
            Ok(())
        }
        Some("version" | "--version" | "-V") => {
            println!("razorwire {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(other) => Err(format!(
            "unknown command {:?}. Run `razorwire help`",
            other.chars().take(40).collect::<String>()
        )),
    };
    if let Err(err) = result {
        eprintln!("razorwire: {err}");
        process::exit(2);
    }
}

/// An environment variable that is set and not blank.
fn setting(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

async fn serve() -> Result<(), String> {
    let upstream = proxy::check_upstream(
        &setting("UPSTREAM_URL").unwrap_or_else(|| "https://api.openai.com".into()),
    )?;
    let listen_text = setting("LISTEN_ADDR").unwrap_or_else(|| "127.0.0.1:8080".into());
    let listen: SocketAddr = listen_text.trim().parse().map_err(|_| {
        format!("LISTEN_ADDR {listen_text:?} is not an address like 127.0.0.1:8080")
    })?;
    let audit_path = setting("AUDIT_LOG").unwrap_or_else(|| "audit.jsonl".into());
    let audit_key = setting("AUDIT_KEY")
        .map(|text| audit::parse_key(&text))
        .transpose()?;
    let upstream_key = setting("UPSTREAM_API_KEY")
        .map(|key| proxy::upstream_authorization(&key))
        .transpose()?;
    let approval_timeout = match setting("APPROVAL_TIMEOUT_SECS") {
        None => DEFAULT_APPROVAL_TIMEOUT_SECS,
        Some(text) => text
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|secs| (1..=MAX_APPROVAL_TIMEOUT_SECS).contains(secs))
            .ok_or_else(|| {
                format!("APPROVAL_TIMEOUT_SECS must be a whole number of seconds from 1 to {MAX_APPROVAL_TIMEOUT_SECS}")
            })?,
    };

    // A policy or keys file that was asked for but cannot be loaded stops the
    // proxy. Starting without it would silently allow everything.
    let policy_path = setting("POLICY_FILE");
    let policy = match &policy_path {
        Some(path) => Some(Arc::new(Policy::load(path).map_err(|err| err.to_string())?)),
        None => None,
    };
    let keys_path = setting("KEYS_FILE");
    let keys = match &keys_path {
        Some(path) => Keys::load(path).map_err(|err| err.to_string())?,
        None => Keys::default(),
    };
    let loopback = listen.ip().is_loopback();
    proxy::check_exposure(loopback, &keys)?;

    let live_streams = match setting("STREAM_MODE").as_deref().map(str::trim) {
        None | Some("live") => true,
        Some("hold") => false,
        Some(_) => return Err("STREAM_MODE must be `live` or `hold`".into()),
    };
    let tls = match (setting("TLS_CERT"), setting("TLS_KEY")) {
        (Some(cert), Some(key)) => Some(tls::acceptor(cert.trim(), key.trim())?),
        (None, None) => None,
        _ => return Err("set both TLS_CERT and TLS_KEY to serve https, or neither".into()),
    };
    let executor = match (setting("EXECUTOR_URL"), setting("EXECUTOR_KEY")) {
        (Some(url), Some(key)) => Some(executor::Executor::new(&url, &key)?),
        (None, None) => None,
        _ => return Err("set both EXECUTOR_URL and EXECUTOR_KEY, or neither".into()),
    };
    let alert_target = alerts::Target::from_settings(setting)?;

    let audit = Arc::new(Audit::open(&audit_path, audit_key).await?);
    let alerts = alert_target.map(|target| Arc::new(alerts::Alerts::start(target, audit.clone())));
    let signed = audit.signed().await;
    let agent_keys = keys.count(Role::Agent);
    let admin_keys = keys.count(Role::Admin);

    println!(
        "razorwire {} listening on {}://{listen}",
        env!("CARGO_PKG_VERSION"),
        if tls.is_some() { "https" } else { "http" }
    );
    if !loopback && tls.is_none() {
        println!("  warning: this address is reachable from other machines over plain http.");
        println!("           Set TLS_CERT and TLS_KEY, or put a TLS proxy in front, or keys and prompts travel unencrypted.");
    }
    println!(
        "forwarding to {upstream} ({})",
        if upstream_key.is_some() {
            "provider key held by razorwire; agents never see it"
        } else {
            "each agent sends its own provider key"
        }
    );
    match &policy {
        Some(policy) => {
            let mode = match policy.mode() {
                Mode::Enforce => "enforce: blocked calls never reach the agent",
                Mode::Shadow => "shadow: decisions are logged, nothing is blocked",
            };
            let path = policy_path.as_deref().unwrap_or("");
            println!(
                "policy: {path} ({} rules, {} undo recipes, {mode})",
                policy.rule_count(),
                policy.undo_count()
            );
            if policy.mode() == Mode::Enforce {
                println!(
                    "  streamed replies: {}",
                    if live_streams {
                        "live. Text goes out as it arrives; tool calls wait for their check"
                    } else {
                        "held until the whole reply is checked (STREAM_MODE=hold)"
                    }
                );
            }
        }
        None => println!("policy: none (tool calls are logged, nothing is blocked)"),
    }
    match &keys_path {
        Some(path) => println!("keys: {path} ({agent_keys} agent, {admin_keys} admin)"),
        None => println!("keys: none"),
    }
    if agent_keys == 0 {
        println!("  agents: no key needed. Any program on this machine can use the proxy, and x-agent-name is trusted.");
    } else {
        println!("  agents: a valid agent key is required; the agent's name comes from its key.");
    }
    if admin_keys == 0 {
        println!("  approvals: off. No admin key, so `review` rules block at once.");
    } else {
        println!("  approvals: on. Held calls wait up to {approval_timeout} seconds for `razorwire approve`.");
    }
    match &executor {
        Some(executor) => println!(
            "executor: {} (rollback can undo; a held call nobody decides in time is parked for {} days)",
            executor.shown(),
            approvals::PARK_FOR.as_secs() / 86_400
        ),
        None => println!("executor: none (rollback only shows its plan; held calls that time out are blocked)"),
    }
    match &alerts {
        Some(alerts) => {
            println!("alerts: {}", alerts.describe());
            if admin_keys == 0 {
                println!(
                    "  no admin key, so no call is ever held: only `blocked` alerts can go out."
                );
            }
        }
        None => println!("alerts: none (set ALERT_URL to be told when a call is held)"),
    }
    println!(
        "audit log: {audit_path} ({})",
        if signed {
            "signed: tampering shows in `razorwire verify-log`"
        } else {
            "not signed: set AUDIT_KEY to make tampering show"
        }
    );

    let settings = Settings {
        upstream: upstream.clone(),
        upstream_key,
        loopback,
        policy_path,
        keys_path,
        approval_timeout: Duration::from_secs(approval_timeout),
        live_streams,
    };
    let config = Config { policy, keys };
    let summary = config.summary();
    let has_executor = executor.is_some();
    let has_alerts = alerts.is_some();
    let state = Arc::new(AppState::new(settings, config, audit, executor, alerts)?);
    if has_executor {
        // Calls parked before a restart can still be decided.
        match state.audit.events().await {
            Ok(events) => {
                let parked = state.approvals.restore(&events);
                if parked > 0 {
                    println!("  parked calls: {parked} still waiting. See `razorwire approvals`.");
                }
            }
            Err(err) => println!("  parked calls were not restored: {err}"),
        }
    }
    let started = json!({
        "event": "proxy_started",
        "version": env!("CARGO_PKG_VERSION"),
        "listen": listen.to_string(),
        "upstream": upstream,
        "config": summary,
        "signed": signed,
        "tls": tls.is_some(),
        "executor": has_executor,
        "alerts": has_alerts,
    });
    state.record(None, started).await;

    let app = Router::new()
        .route("/healthz", get(healthz))
        .merge(admin::routes())
        .fallback(proxy::forward)
        .layer(DefaultBodyLimit::max(proxy::MAX_BODY_BYTES))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|err| format!("cannot listen on {listen}: {err}"))?;
    let served = match tls {
        None => {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        }
        Some(acceptor) => {
            let listener = tls::TlsListener::new(listener, acceptor)
                .map_err(|err| format!("cannot listen on {listen}: {err}"))?
                // Gives the handlers the client's address, as plain TCP does.
                .tap_io(|_| {});
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        }
    };
    served.map_err(|err| format!("the server stopped: {err}"))
}

async fn healthz() -> &'static str {
    "ok"
}

fn keys_path() -> String {
    setting("KEYS_FILE").unwrap_or_else(|| DEFAULT_KEYS_FILE.into())
}

/// The keys file's text, or nothing if it does not exist yet.
fn read_keys_file(path: &str) -> Result<String, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(err) => Err(format!(
            "cannot read keys file {path}: {err} (it must be UTF-8 text)"
        )),
    }
}

/// Replace a file in one step, so a crash never leaves it half written. The
/// new file keeps the old one's permissions.
fn replace_file(path: &str, text: &str) -> Result<(), String> {
    let temporary = format!("{path}.tmp-{}", process::id());
    let write = || -> std::io::Result<()> {
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        if let Ok(metadata) = std::fs::metadata(path) {
            std::fs::set_permissions(&temporary, metadata.permissions())?;
        }
        std::fs::rename(&temporary, path)
    };
    write().map_err(|err| {
        let _ = std::fs::remove_file(&temporary);
        format!("cannot write keys file {path}: {err}")
    })
}

/// Ask the running proxy to re-read its files, when an admin key is at hand.
/// `None` means no reload was tried.
async fn reload_if_possible() -> Option<Result<(), String>> {
    setting("RAZORWIRE_ADMIN_KEY")?;
    Some(match admin::Client::from_env() {
        Ok(client) => client.reload().await,
        Err(err) => Err(err),
    })
}

fn list_keys(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("usage: razorwire keys".into());
    }
    let path = keys_path();
    let keys = Keys::parse(&read_keys_file(&path)?).map_err(|err| format!("{path}: {err}"))?;
    let listed = keys.listed();
    if listed.is_empty() {
        println!("{path} has no keys. Create one with `razorwire new-key <agent|admin> <name>`.");
        return Ok(());
    }
    let width = listed.iter().map(|key| key.name.len()).max().unwrap_or(0);
    println!("Keys in {path}:\n");
    for key in &listed {
        println!(
            "  {:<5}  {:<width$}  {}",
            key.role.as_str(),
            key.name,
            key.fingerprint
        );
    }
    println!("\nThe last column is the start of the key's hash. Remove a key with `razorwire revoke-key <name>`.");
    Ok(())
}

async fn revoke_key(args: &[String]) -> Result<(), String> {
    let (name, fingerprint) = match args {
        [name] => (name, None),
        [name, fingerprint] => (name, Some(fingerprint.as_str())),
        _ => return Err("usage: razorwire revoke-key <name> [fingerprint]".into()),
    };
    let path = keys_path();
    let text = read_keys_file(&path)?;
    let (kept, removed) =
        auth::without_key(&text, name, fingerprint).map_err(|err| format!("{path}: {err}"))?;
    replace_file(&path, &kept)?;
    println!(
        "Removed the {} key {} ({}) from {path}.",
        removed.role.as_str(),
        removed.name,
        removed.fingerprint
    );

    let left = Keys::parse(&kept).map_err(|err| format!("{path}: {err}"))?;
    if removed.role == Role::Admin && left.count(Role::Admin) == 0 {
        println!("No admin keys are left, so after a reload `review` rules block at once.");
    }
    match reload_if_possible().await {
        Some(Ok(())) => Ok(()),
        Some(Err(err)) => Err(format!(
            "the running Razorwire was not reloaded, so it still accepts that key: {err}"
        )),
        None => {
            println!("The running Razorwire still accepts it until you run `razorwire reload` or restart it.");
            Ok(())
        }
    }
}

async fn new_key(args: &[String]) -> Result<(), String> {
    let usage = "usage: razorwire new-key <agent|admin> <name>";
    let [role, name] = args else {
        return Err(usage.into());
    };
    let role = Role::parse(role).ok_or(usage)?;
    if !auth::valid_name(name) {
        return Err("the name must be 1 to 64 letters, digits, dots, dashes or underscores".into());
    }
    let path = keys_path();

    // Never add to a file that is already broken.
    let existing = read_keys_file(&path)?;
    Keys::parse(&existing).map_err(|err| format!("{path}: {err}"))?;

    let key = auth::generate()?;
    let mut addition = String::new();
    if existing.trim().is_empty() {
        addition.push_str(auth::KEYS_FILE_HEADER);
    } else if !existing.ends_with('\n') {
        addition.push('\n');
    }
    addition.push_str(&auth::key_line(role, name, &key));
    addition.push('\n');
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| file.write_all(addition.as_bytes()))
        .map_err(|err| format!("cannot write keys file {path}: {err}"))?;

    let what = match role {
        Role::Agent => "Give it to the agent as its API key, or send it in the x-razorwire-key header.",
        Role::Admin => "Whoever holds it can approve and deny held calls, so hand it over privately and never \
                        give it to an agent. They set it as RAZORWIRE_ADMIN_KEY where they run `razorwire approve`.",
    };
    println!("New {} key for {name}:\n", role.as_str());
    println!("    {key}\n");
    println!("It is shown only this once. {path} keeps only its hash.");
    println!("{what}");
    println!("Remove it later with `razorwire revoke-key {name}`.");
    match reload_if_possible().await {
        Some(Ok(())) => {}
        Some(Err(err)) => println!(
            "The running Razorwire was not reloaded ({err}). Run `razorwire reload` once it is up."
        ),
        None => println!(
            "Start Razorwire with KEYS_FILE={path}, or run `razorwire reload` if it is running."
        ),
    }
    Ok(())
}

fn new_audit_key() -> Result<(), String> {
    let key = audit::generate_key()?;
    println!("{key}\n");
    println!("Set AUDIT_KEY to this value when you start Razorwire, and when you run `razorwire verify-log`.");
    println!("Keep it secret: anyone who has it can rewrite the log without it showing.");
    println!("Use a new log file when you change the key.");
    Ok(())
}

fn check_policy(args: &[String]) -> Result<(), String> {
    let [path] = args else {
        return Err("usage: razorwire check-policy <file>".into());
    };
    let policy = Policy::load(path).map_err(|err| err.to_string())?;
    let mode = match policy.mode() {
        Mode::Enforce => "enforce",
        Mode::Shadow => "shadow",
    };
    println!(
        "{path}: ok, {} rules, {} undo recipes, mode {mode}",
        policy.rule_count(),
        policy.undo_count()
    );
    Ok(())
}

fn new_executor_key() -> Result<(), String> {
    let key = audit::generate_key()?;
    println!("{key}\n");
    println!(
        "Set EXECUTOR_KEY to this value for Razorwire, and give the same value to your executor,"
    );
    println!("which uses it to check that a request really came from Razorwire.");
    println!("Keep it secret: anyone who has it can ask the executor to act.");
    Ok(())
}

async fn test_alert() -> Result<(), String> {
    let target = alerts::Target::from_settings(setting)?
        .ok_or("set ALERT_URL to the address alerts go to: a Slack or Discord webhook, an ntfy topic, or your own https endpoint")?;
    let shown = target.describe();
    target
        .send_test()
        .await
        .map_err(|err| format!("the test alert to {shown} failed: {err}"))?;
    println!("Sent a test alert to {shown}.");
    println!("If it did not arrive, check ALERT_URL, and ALERT_FORMAT if the address is your own.");
    Ok(())
}

fn new_alert_key() -> Result<(), String> {
    let key = audit::generate_key()?;
    println!("{key}\n");
    println!("Set ALERT_KEY to this value for Razorwire, and give the same value to whatever");
    println!("receives the json alerts, so it can check that an alert really came from Razorwire.");
    println!("Slack, Discord and ntfy cannot check it; it is for json alerts only.");
    Ok(())
}

/// A span like `30m`, `2h`, `1d` or `90s`, in seconds.
fn parse_span(text: &str) -> Option<u64> {
    let text = text.trim();
    let split = text.find(|c: char| !c.is_ascii_digit())?;
    let (number, unit) = text.split_at(split);
    let number: u64 = number.parse().ok()?;
    let unit = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    number.checked_mul(unit)
}

async fn rollback(args: &[String]) -> Result<(), String> {
    let usage =
        "usage: razorwire rollback [--agent <name>] [--since <30m|2h|1d>] [<undo id>...] [--run]";
    let mut filter = json!({});
    let mut ids = Vec::new();
    let mut run = false;
    let mut words = args.iter();
    while let Some(word) = words.next() {
        match word.as_str() {
            "--run" => run = true,
            "--agent" => filter["agent"] = json!(words.next().ok_or(usage)?),
            "--since" => {
                let span = words.next().ok_or(usage)?;
                let secs = parse_span(span).ok_or("--since takes a span like 30m, 2h or 1d")?;
                filter["since_secs"] = json!(secs);
            }
            id if rollback::is_undo_id(id) => ids.push(id.to_string()),
            _ => return Err(usage.into()),
        }
    }
    if !ids.is_empty() {
        filter["ids"] = json!(ids);
    }
    if filter.as_object().is_some_and(serde_json::Map::is_empty) {
        return Err(format!(
            "say what to roll back: --agent, --since, or undo ids\n{usage}"
        ));
    }
    admin::Client::from_env()?.rollback(filter, run).await
}

fn verify_log(args: &[String]) -> Result<(), String> {
    let path = match args {
        [] => setting("AUDIT_LOG").unwrap_or_else(|| "audit.jsonl".into()),
        [path] => path.clone(),
        _ => return Err("usage: razorwire verify-log [file]".into()),
    };
    let key = setting("AUDIT_KEY").ok_or("set AUDIT_KEY to the key the log was signed with")?;
    let key = audit::parse_key(&key)?;
    let log = std::fs::read(&path).map_err(|err| format!("cannot read {path}: {err}"))?;
    let report = audit::verify(&log, &key);

    if report.unsigned_prefix > 0 {
        println!(
            "{} line{} at the start {} written before signing was turned on, and cannot be checked.",
            report.unsigned_prefix,
            if report.unsigned_prefix == 1 { "" } else { "s" },
            if report.unsigned_prefix == 1 { "was" } else { "were" },
        );
    }
    if let Some((line, reason)) = report.broken {
        return Err(format!(
            "{path} FAILED at line {line}: {reason}. The {} signed lines before it are intact.",
            report.signed
        ));
    }
    match report.last_seq {
        Some(seq) => println!(
            "{path}: intact. {} signed lines, the last is seq {seq}.\n\
             Lines cut off the end of a log cannot be detected: compare the last seq with a copy kept elsewhere.",
            report.signed
        ),
        None => return Err(format!("{path} has no signed lines. Start Razorwire with AUDIT_KEY set to sign it")),
    }
    Ok(())
}

async fn decide(approve: bool, args: &[String]) -> Result<(), String> {
    let action = if approve { "approve" } else { "deny" };
    let Some((id, words)) = args.split_first() else {
        return Err(format!("usage: razorwire {action} <id> [reason]"));
    };
    let reason = (!words.is_empty()).then(|| words.join(" "));
    admin::Client::from_env()?.decide(id, approve, reason).await
}
