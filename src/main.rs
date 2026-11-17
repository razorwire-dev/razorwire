//! Razorwire: a proxy between an AI agent and its model provider that checks
//! every tool call against a policy before the agent can run it.
//!
//! `razorwire` with no command starts the proxy. The other commands create
//! keys, check files, and drive the admin API.

mod admin;
mod approvals;
mod audit;
mod auth;
mod openai;
mod policy;
mod proxy;
mod sse;

use std::{env, io::Write, net::SocketAddr, process, sync::Arc, time::Duration};

use axum::{extract::DefaultBodyLimit, routing::get, Router};
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
  razorwire new-audit-key          create a key for signing the audit log
  razorwire check-policy <file>    check a policy file and exit
  razorwire verify-log [file]      check that the audit log was not tampered with
  razorwire approvals              list tool calls waiting for approval
  razorwire approve <id> [reason]  let a held tool call through
  razorwire deny <id> [reason]     block a held tool call
  razorwire reload                 re-read the policy and keys files

The proxy is configured with environment variables:
  UPSTREAM_URL            provider to forward to (default https://api.openai.com)
  UPSTREAM_API_KEY        provider key the proxy sends, so agents never hold it
  LISTEN_ADDR             where to listen (default 127.0.0.1:8080)
  POLICY_FILE             policy to enforce (unset: log only, block nothing)
  KEYS_FILE               agent and admin keys (default for new-key: razorwire.keys)
  AUDIT_LOG               audit log file (default audit.jsonl)
  AUDIT_KEY               signs the audit log so tampering shows
  APPROVAL_TIMEOUT_SECS   how long a held call waits for a human (default 300)

The admin commands use RAZORWIRE_URL (default http://127.0.0.1:8080) and
RAZORWIRE_ADMIN_KEY.
";

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or(&[]);
    let result = match args.first().map(String::as_str) {
        None | Some("serve") => serve().await,
        Some("new-key") => new_key(rest),
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

    let audit = Arc::new(Audit::open(&audit_path, audit_key).await?);
    let signed = audit.signed().await;
    let agent_keys = keys.count(Role::Agent);
    let admin_keys = keys.count(Role::Admin);

    println!(
        "razorwire {} listening on http://{listen}",
        env!("CARGO_PKG_VERSION")
    );
    if !loopback {
        println!("  warning: this address is reachable from other machines over plain http.");
        println!("           Put a TLS proxy (Caddy, nginx) in front, or keys and prompts travel unencrypted.");
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
            println!("policy: {path} ({} rules, {mode})", policy.rule_count());
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
    };
    let config = Config { policy, keys };
    let summary = config.summary();
    let state = Arc::new(AppState::new(settings, config, audit)?);
    let started = json!({
        "event": "proxy_started",
        "version": env!("CARGO_PKG_VERSION"),
        "listen": listen.to_string(),
        "upstream": upstream,
        "config": summary,
        "signed": signed,
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
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|err| format!("the server stopped: {err}"))
}

async fn healthz() -> &'static str {
    "ok"
}

fn new_key(args: &[String]) -> Result<(), String> {
    let usage = "usage: razorwire new-key <agent|admin> <name>";
    let [role, name] = args else {
        return Err(usage.into());
    };
    let role = Role::parse(role).ok_or(usage)?;
    if !auth::valid_name(name) {
        return Err("the name must be 1 to 64 letters, digits, dots, dashes or underscores".into());
    }
    let path = setting("KEYS_FILE").unwrap_or_else(|| DEFAULT_KEYS_FILE.into());

    // Never add to a file that is already broken.
    let existing = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            return Err(format!(
                "cannot read keys file {path}: {err} (it must be UTF-8 text)"
            ))
        }
    };
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
        Role::Admin => "Set it as RAZORWIRE_ADMIN_KEY where you run `razorwire approve`. Never give it to an agent.",
    };
    println!("New {} key for {name}:\n", role.as_str());
    println!("    {key}\n");
    println!("It is shown only this once. {path} keeps only its hash.");
    println!("{what}");
    println!("Start Razorwire with KEYS_FILE={path}, or run `razorwire reload` if it is running.");
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
    println!("{path}: ok, {} rules, mode {mode}", policy.rule_count());
    Ok(())
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
