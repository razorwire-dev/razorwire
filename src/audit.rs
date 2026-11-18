//! The audit log: one JSON object per line, optionally chained with an HMAC
//! so that editing, inserting, reordering or deleting a line is detected.
//!
//! A signed line ends with `,"seq":<n>,"mac":"<hex>"}`. The MAC covers the
//! previous line's MAC, the sequence number and the rest of the line, so each
//! line vouches for the one before it. `razorwire verify-log` walks the chain.
//!
//! What it cannot catch: lines cut off the end of the file, and anything done
//! by someone who holds the key. Ship the log to another machine if those
//! matter.

use std::{
    fmt::Write as _,
    io::{Read, Seek, SeekFrom},
    time::{SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use tokio::{fs::OpenOptions, io::AsyncWriteExt, sync::Mutex};

use crate::auth::{hex, unhex};

type HmacSha256 = Hmac<Sha256>;

/// Shortest audit key accepted, in bytes.
const MIN_KEY_BYTES: usize = 32;

/// How much of the end of an existing log is read to continue its chain.
/// The chain fields sit at the very end of the last line.
const TAIL_BYTES: u64 = 4096;

/// Largest log that is read back into memory, for rollback and for parked
/// calls.
const MAX_READ_BYTES: u64 = 1024 * 1024 * 1024;

pub struct Audit {
    writer: Mutex<Writer>,
    path: String,
    /// Kept to check the chain when the log is read back.
    key: Option<Vec<u8>>,
}

struct Writer {
    file: tokio::fs::File,
    chain: Option<Chain>,
    /// The file does not end with a newline, so the last line was cut short.
    /// The next line starts on a fresh line.
    needs_newline: bool,
}

struct Chain {
    key: Vec<u8>,
    prev: String,
    next_seq: u64,
}

/// Decode an `AUDIT_KEY` value. The key itself is never printed.
pub fn parse_key(text: &str) -> Result<Vec<u8>, String> {
    let key = unhex(text.trim()).ok_or_else(|| {
        "AUDIT_KEY must be hex. Create one with `razorwire new-audit-key`".to_string()
    })?;
    if key.len() < MIN_KEY_BYTES {
        return Err(format!(
            "AUDIT_KEY is too short: it needs at least {MIN_KEY_BYTES} bytes ({} hex characters)",
            MIN_KEY_BYTES * 2
        ));
    }
    Ok(key)
}

/// A new audit key: 32 random bytes in hex.
pub fn generate_key() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|err| format!("the system random number generator failed: {err}"))?;
    Ok(hex(&bytes))
}

impl Audit {
    /// Open the log for appending. With a key, lines are signed, and an
    /// existing signed log is continued where it stopped.
    pub async fn open(path: &str, key: Option<Vec<u8>>) -> Result<Audit, String> {
        let (needs_newline, last) =
            read_tail(path).map_err(|err| format!("cannot read the audit log {path}: {err}"))?;
        let check_key = key.clone();
        let chain = key.map(|key| match last {
            Some((seq, mac)) => Chain {
                key,
                prev: mac,
                next_seq: seq.saturating_add(1),
            },
            None => Chain {
                key,
                prev: String::new(),
                next_seq: 0,
            },
        });
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .map_err(|err| format!("cannot open the audit log {path}: {err}"))?;
        Ok(Audit {
            writer: Mutex::new(Writer {
                file,
                chain,
                needs_newline,
            }),
            path: path.to_string(),
            key: check_key,
        })
    }

    pub async fn signed(&self) -> bool {
        self.writer.lock().await.chain.is_some()
    }

    /// Every event in the log, oldest first. A signed log is checked first,
    /// and one that fails the check is refused, so nothing is acted on from
    /// lines that may have been changed.
    pub async fn events(&self) -> Result<Vec<Value>, String> {
        let path = &self.path;
        let bytes = {
            // No line is half written while the file is read.
            let _writer = self.writer.lock().await;
            match tokio::fs::metadata(path).await {
                Ok(metadata) if metadata.len() > MAX_READ_BYTES => {
                    return Err(format!(
                        "the audit log {path} is over {} MB, too large to read back. Start a new log file",
                        MAX_READ_BYTES / (1024 * 1024)
                    ));
                }
                _ => {}
            }
            match tokio::fs::read(path).await {
                Ok(bytes) => bytes,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(err) => return Err(format!("cannot read the audit log {path}: {err}")),
            }
        };
        if let Some(key) = &self.key {
            if let Some((line, reason)) = verify(&bytes, key).broken {
                return Err(format!(
                    "the audit log {path} fails its check at line {line}: {reason}. \
                     Nothing is read from a log that may have been changed; `razorwire verify-log` shows the same"
                ));
            }
        }
        Ok(bytes
            .split(|&b| b == b'\n')
            .filter_map(|line| {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                serde_json::from_slice::<Value>(line).ok()
            })
            .filter(Value::is_object)
            .collect())
    }

    /// Stamp an event, sign it if there is a key, and append it to the log
    /// and to stdout.
    pub async fn record(&self, request_id: Option<u64>, mut event: Value) {
        if let Some(fields) = event.as_object_mut() {
            fields.insert("ts_ms".into(), json!(now_ms()));
            if let Some(id) = request_id {
                fields.insert("request_id".into(), json!(id));
            }
        }
        let body = json_line(&event);

        let mut writer = self.writer.lock().await;
        let (mut line, mac) = match &writer.chain {
            Some(chain) => {
                let mac = hex(&line_mac(&chain.key, &chain.prev, chain.next_seq, &body));
                (sign(&body, chain.next_seq, &mac), Some(mac))
            }
            None => (body, None),
        };
        line.push('\n');
        if writer.needs_newline {
            line.insert(0, '\n');
        }
        print!("{}", line.trim_start_matches('\n'));

        let written = writer.file.write_all(line.as_bytes()).await;
        let flushed = writer.file.flush().await;
        match written.and(flushed) {
            Ok(()) => {
                writer.needs_newline = false;
                if let (Some(chain), Some(mac)) = (writer.chain.as_mut(), mac) {
                    chain.prev = mac;
                    chain.next_seq = chain.next_seq.saturating_add(1);
                }
            }
            Err(err) => {
                // Part of the line may have been written.
                writer.needs_newline = true;
                eprintln!("razorwire: audit log write failed: {err}");
            }
        }
    }
}

/// Whether the file ends without a newline, and the chain position of its
/// last complete line if that line is signed.
fn read_tail(path: &str) -> std::io::Result<(bool, Option<(u64, String)>)> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok((false, None)),
        Err(err) => return Err(err),
    };
    let length = file.metadata()?.len();
    if length == 0 {
        return Ok((false, None));
    }
    let start = length.saturating_sub(TAIL_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail)?;

    let needs_newline = tail.last() != Some(&b'\n');
    let last = tail
        .iter()
        .rposition(|&b| b == b'\n')
        .and_then(|end| chain_fields(&tail[..end]))
        .map(|(seq, mac, _)| (seq, mac));
    Ok((needs_newline, last))
}

/// The MAC of one line: it covers the previous MAC, the sequence number and
/// the line without its chain fields.
fn line_mac(key: &[u8], prev: &str, seq: u64, body: &str) -> Vec<u8> {
    // HMAC takes a key of any length, so this cannot fail.
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
    mac.update(prev.as_bytes());
    mac.update(b"\n");
    mac.update(seq.to_string().as_bytes());
    mac.update(b"\n");
    mac.update(body.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Add the chain fields to a serialized JSON object.
fn sign(body: &str, seq: u64, mac: &str) -> String {
    let open = body.strip_suffix('}').unwrap_or(body);
    let comma = if open.ends_with('{') { "" } else { "," };
    format!("{open}{comma}\"seq\":{seq},\"mac\":\"{mac}\"}}")
}

/// Read the chain fields from the end of a line: the sequence number, the
/// MAC, and the line as it was before they were added.
fn chain_fields(line: &[u8]) -> Option<(u64, String, String)> {
    let line = std::str::from_utf8(line).ok()?;
    let rest = line.strip_suffix("\"}")?;
    let mac_start = rest.len().checked_sub(64)?;
    let mac = rest.get(mac_start..)?;
    if !mac.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let rest = rest[..mac_start].strip_suffix(",\"mac\":\"")?;
    let digits = rest.len() - rest.bytes().rev().take_while(u8::is_ascii_digit).count();
    let seq: u64 = rest[digits..].parse().ok()?;
    let rest = &rest[..digits];
    let open = rest
        .strip_suffix(",\"seq\":")
        .or_else(|| rest.strip_suffix("\"seq\":"))?;
    Some((seq, mac.to_string(), format!("{open}}}")))
}

/// What `verify` found.
#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    /// Lines at the start of the file, written before signing was turned on.
    pub unsigned_prefix: usize,
    /// Signed lines whose MAC checked out.
    pub signed: usize,
    pub last_seq: Option<u64>,
    /// The first line that does not check out, with the reason.
    pub broken: Option<(usize, String)>,
}

/// Walk the chain of a log file and report the first line that is wrong.
pub fn verify(log: &[u8], key: &[u8]) -> Report {
    let mut report = Report {
        unsigned_prefix: 0,
        signed: 0,
        last_seq: None,
        broken: None,
    };
    let mut prev = String::new();
    let lines = log.strip_suffix(b"\n").unwrap_or(log);
    if lines.is_empty() {
        return report;
    }
    for (index, line) in lines.split(|&b| b == b'\n').enumerate() {
        let number = index + 1;
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some((seq, mac, body)) = chain_fields(line) else {
            let readable = serde_json::from_slice::<Value>(line).is_ok_and(|v| v.is_object());
            if report.signed == 0 && readable {
                report.unsigned_prefix += 1;
                continue;
            }
            let reason = if readable {
                "this line is not signed, but lines before it are: it was added by hand or written while AUDIT_KEY was not set"
            } else {
                "this line is not a complete JSON object"
            };
            report.broken = Some((number, reason.to_string()));
            return report;
        };
        if serde_json::from_str::<Value>(&body).map_or(true, |v| !v.is_object()) {
            report.broken = Some((number, "this line is not a complete JSON object".into()));
            return report;
        }
        let Some(mac) = unhex(&mac) else {
            report.broken = Some((number, "the MAC is not hex".into()));
            return report;
        };
        let mut check = <HmacSha256 as KeyInit>::new_from_slice(key)
            .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
        check.update(prev.as_bytes());
        check.update(b"\n");
        check.update(seq.to_string().as_bytes());
        check.update(b"\n");
        check.update(body.as_bytes());
        if check.verify_slice(&mac).is_err() {
            let reason = match report.last_seq {
                Some(last) if seq != last.saturating_add(1) => format!(
                    "the MAC does not match: seq jumps from {last} to {seq}, so lines are missing or out of order"
                ),
                None if seq != 0 => format!(
                    "the MAC does not match: the first signed line has seq {seq}, so earlier lines are missing"
                ),
                _ => "the MAC does not match: the line was changed, or a different AUDIT_KEY signed it".into(),
            };
            report.broken = Some((number, reason));
            return report;
        }
        prev = hex(&mac);
        report.signed += 1;
        report.last_seq = Some(seq);
    }
    report
}

/// Serialize an event as compact JSON with characters that can fool a
/// terminal or a reader escaped: DEL, the C1 control range, and the Unicode
/// direction and line-separator marks. JSON escapes the C0 controls already.
/// Escaping keeps the JSON the same value.
pub fn json_line(value: &Value) -> String {
    let raw = value.to_string();
    if !raw.chars().any(needs_escape) {
        return raw;
    }
    let mut out = String::with_capacity(raw.len() + 16);
    for c in raw.chars() {
        if needs_escape(c) {
            // Every escaped character is in the Basic Multilingual Plane.
            let _ = write!(out, "\\u{:04x}", c as u32);
        } else {
            out.push(c);
        }
    }
    out
}

fn needs_escape(c: char) -> bool {
    matches!(
        c,
        '\u{7f}'..='\u{9f}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    fn temp_log(name: &str) -> String {
        let dir = std::env::temp_dir().join("razorwire-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path.to_string_lossy().into_owned()
    }

    async fn write_events(path: &str, key: Option<Vec<u8>>, events: &[&str]) {
        let audit = Audit::open(path, key).await.unwrap();
        for name in events {
            audit
                .record(Some(1), json!({ "event": name, "note": "a,\"seq\":1}" }))
                .await;
        }
    }

    fn lines(path: &str) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn rewrite(path: &str, lines: &[String]) {
        std::fs::write(path, format!("{}\n", lines.join("\n"))).unwrap();
    }

    #[tokio::test]
    async fn a_signed_log_verifies_and_continues_after_a_restart() {
        let path = temp_log("chain");
        write_events(&path, Some(KEY.to_vec()), &["a", "b"]).await;
        write_events(&path, Some(KEY.to_vec()), &["c"]).await;

        let log = std::fs::read(&path).unwrap();
        let report = verify(&log, &KEY);
        assert_eq!(report.broken, None);
        assert_eq!(report.signed, 3);
        assert_eq!(report.last_seq, Some(2));

        for line in lines(&path) {
            let value: Value = serde_json::from_str(&line).unwrap();
            assert!(value["mac"].is_string() && value["seq"].is_u64(), "{line}");
        }
        // A different key does not verify.
        let other = verify(&log, &[8; 32]);
        assert_eq!(other.broken.map(|(line, _)| line), Some(1));
    }

    #[tokio::test]
    async fn events_are_read_back_only_from_a_log_that_checks_out() {
        let path = temp_log("read-back");
        let audit = Audit::open(&path, Some(KEY.to_vec())).await.unwrap();
        audit.record(None, json!({ "event": "a" })).await;
        audit
            .record(None, json!({ "event": "b", "amount": 470 }))
            .await;
        let events = audit.events().await.unwrap();
        let names: Vec<&str> = events.iter().filter_map(|e| e["event"].as_str()).collect();
        assert_eq!(names, ["a", "b"]);

        let mut changed = lines(&path);
        changed[1] = changed[1].replace("470", "47");
        rewrite(&path, &changed);
        let refused = audit.events().await.unwrap_err();
        assert!(refused.contains("line 2"), "{refused}");

        // An unsigned log is read as it is.
        let plain = temp_log("read-back-plain");
        let audit = Audit::open(&plain, None).await.unwrap();
        audit.record(None, json!({ "event": "a" })).await;
        assert_eq!(audit.events().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tampering_is_detected() {
        let path = temp_log("tamper");
        write_events(&path, Some(KEY.to_vec()), &["a", "b", "c", "d"]).await;
        let original = lines(&path);

        let check = |edited: Vec<String>| {
            rewrite(&path, &edited);
            verify(&std::fs::read(&path).unwrap(), &KEY).broken
        };

        let mut changed = original.clone();
        changed[1] = changed[1].replace("\"b\"", "\"B\"");
        assert_eq!(check(changed).map(|b| b.0), Some(2));

        let mut deleted = original.clone();
        deleted.remove(2);
        let broken = check(deleted).unwrap();
        assert_eq!(broken.0, 3);
        assert!(broken.1.contains("jumps"), "{}", broken.1);

        let mut swapped = original.clone();
        swapped.swap(1, 2);
        assert_eq!(check(swapped).map(|b| b.0), Some(2));

        let mut head_cut = original.clone();
        head_cut.remove(0);
        assert!(check(head_cut)
            .unwrap()
            .1
            .contains("earlier lines are missing"));

        let mut inserted = original.clone();
        inserted.insert(2, "{\"event\":\"tool_call\",\"tool\":\"fake\"}".into());
        assert!(check(inserted).unwrap().1.contains("not signed"));

        let mut garbage = original.clone();
        garbage.push("{\"event\":\"tool_ca".into());
        assert_eq!(check(garbage).map(|b| b.0), Some(5));

        assert_eq!(check(original).map(|b| b.0), None);
    }

    #[tokio::test]
    async fn signing_can_start_on_an_existing_unsigned_log() {
        let path = temp_log("prefix");
        write_events(&path, None, &["old"]).await;
        write_events(&path, Some(KEY.to_vec()), &["new", "newer"]).await;

        let report = verify(&std::fs::read(&path).unwrap(), &KEY);
        assert_eq!(report.unsigned_prefix, 1);
        assert_eq!(report.signed, 2);
        assert_eq!(report.broken, None);
    }

    #[tokio::test]
    async fn a_cut_short_last_line_is_not_glued_to_the_next() {
        let path = temp_log("cut");
        write_events(&path, Some(KEY.to_vec()), &["a"]).await;
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"event\":\"half");
        std::fs::write(&path, &text).unwrap();

        write_events(&path, Some(KEY.to_vec()), &["b"]).await;

        let all = lines(&path);
        assert_eq!(all.len(), 3);
        assert_eq!(all[1], "{\"event\":\"half");
        // The damage is reported where it is.
        let report = verify(&std::fs::read(&path).unwrap(), &KEY);
        assert_eq!(report.broken.map(|b| b.0), Some(2));
    }

    #[test]
    fn chain_fields_are_read_from_the_end_only() {
        let body = json_line(&json!({ "args": { "seq": 5, "mac": "x" }, "event": "e" }));
        let mac = "ab".repeat(32);
        let signed = sign(&body, 12, &mac);
        let (seq, found, unsigned) = chain_fields(signed.as_bytes()).unwrap();
        assert_eq!(
            (seq, found.as_str(), unsigned.as_str()),
            (12, mac.as_str(), body.as_str())
        );
        assert!(chain_fields(body.as_bytes()).is_none());
        assert!(chain_fields(b"").is_none());
        assert!(chain_fields("\u{e9}\"}".as_bytes()).is_none());
    }

    #[test]
    fn audit_keys_must_be_long_hex() {
        assert!(parse_key(&generate_key().unwrap()).is_ok());
        assert!(parse_key("abcd").unwrap_err().contains("too short"));
        assert!(parse_key(&"z".repeat(64)).unwrap_err().contains("hex"));
    }

    #[test]
    fn terminal_tricks_are_escaped_in_log_lines() {
        let event = json!({ "tool": "a\u{1b}[2Jb\u{9b}c\u{202e}d\u{7f}" });
        let line = json_line(&event);
        assert!(line.is_ascii(), "{line}");
        assert!(line.contains("\\u001b") && line.contains("\\u009b") && line.contains("\\u202e"));
        let back: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(back, event);
    }
}
