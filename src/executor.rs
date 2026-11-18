//! The executor: a small web service you run that holds the real credentials
//! and carries out actions when Razorwire asks. Razorwire never touches your
//! systems itself. It calls the executor to undo actions during a rollback,
//! and to run a parked call that a human approved after its agent stopped
//! waiting. `examples/executor.py` is a starting point.
//!
//! Each request is a JSON object POSTed to `EXECUTOR_URL`, signed with
//! `EXECUTOR_KEY`:
//!
//! ```text
//! x-razorwire-timestamp: <milliseconds since 1970>
//! x-razorwire-signature: v1=<hex HMAC-SHA256 of "<timestamp>.<body>">
//! ```
//!
//! The executor must check the signature and refuse old timestamps. A retry
//! carries the same `id`, so the executor can refuse to do one thing twice.

use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::Sha256;

use crate::{
    audit::{json_line, now_ms},
    auth::{hex, unhex},
    proxy::is_loopback_host,
};

pub const TIMESTAMP_HEADER: &str = "x-razorwire-timestamp";
pub const SIGNATURE_HEADER: &str = "x-razorwire-signature";

/// Shortest executor key accepted, in bytes.
const MIN_KEY_BYTES: usize = 32;

/// How long the executor may take over one action.
const TIMEOUT: Duration = Duration::from_secs(60);

/// How much of the executor's answer is kept.
const MAX_ANSWER_BYTES: usize = 16 * 1024;

pub struct Executor {
    http: reqwest::Client,
    url: String,
    key: Vec<u8>,
    /// Where it is, without the path, for the startup banner.
    shown: String,
}

impl Executor {
    /// Built from `EXECUTOR_URL` and `EXECUTOR_KEY`. Neither is echoed in
    /// errors.
    pub fn new(url: &str, key: &str) -> Result<Executor, String> {
        let parsed = reqwest::Url::parse(url.trim())
            .map_err(|_| "EXECUTOR_URL is not a valid URL".to_string())?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err("EXECUTOR_URL must not hold credentials".into());
        }
        let host = parsed.host_str().unwrap_or("");
        match parsed.scheme() {
            "https" => {}
            "http" if is_loopback_host(host) => {}
            "http" => {
                return Err(
                    "EXECUTOR_URL uses plain http to another machine, so the actions and their \
                     arguments would cross the network unencrypted. Use https"
                        .into(),
                )
            }
            _ => return Err("EXECUTOR_URL must start with https://".into()),
        }
        let key = unhex(key.trim()).ok_or_else(|| {
            "EXECUTOR_KEY must be hex. Create one with `razorwire new-executor-key`".to_string()
        })?;
        if key.len() < MIN_KEY_BYTES {
            return Err(format!(
                "EXECUTOR_KEY is too short: it needs at least {MIN_KEY_BYTES} bytes ({} hex characters)",
                MIN_KEY_BYTES * 2
            ));
        }
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(TIMEOUT)
            // An action is never sent anywhere but the configured address.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| format!("cannot build the HTTP client: {err}"))?;
        let shown = match parsed.port() {
            Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
            None => format!("{}://{host}", parsed.scheme()),
        };
        Ok(Executor {
            http,
            url: url.trim().to_string(),
            key,
            shown,
        })
    }

    pub fn shown(&self) -> &str {
        &self.shown
    }

    /// Ask the executor to carry out one action. A 2xx answer means it was
    /// done; the answer's body comes back as JSON, or as text if it is not
    /// JSON.
    pub async fn run(&self, job: &Value) -> Result<Value, String> {
        let body = job.to_string();
        let timestamp = now_ms().to_string();
        let signature = signature(&self.key, &timestamp, &body);
        let mut response = self
            .http
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(TIMESTAMP_HEADER, &timestamp)
            .header(SIGNATURE_HEADER, format!("v1={signature}"))
            .body(body)
            .send()
            .await
            .map_err(|err| format!("cannot reach the executor at {}: {err}", self.shown))?;
        let status = response.status();

        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|err| format!("the executor's answer was cut short: {err}"))?
        {
            bytes.extend_from_slice(&chunk);
            if bytes.len() > MAX_ANSWER_BYTES {
                bytes.truncate(MAX_ANSWER_BYTES);
                break;
            }
        }
        let answer = serde_json::from_slice::<Value>(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        if status.is_success() {
            return Ok(answer);
        }
        let why = match &answer {
            Value::String(text) if !text.trim().is_empty() => text.trim().to_string(),
            Value::String(_) => "no reason given".to_string(),
            other => match &other["error"] {
                Value::String(text) => text.clone(),
                Value::Null => json_line(other),
                error => json_line(error),
            },
        };
        let why: String = why.chars().take(500).collect();
        Err(format!("the executor answered {status}: {why}"))
    }
}

/// The signature over one request: HMAC-SHA256 of `<timestamp>.<body>`.
pub fn signature(key: &[u8], timestamp: &str, body: &str) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    hex(&mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn the_signature_is_an_hmac_of_the_timestamp_and_body() {
        // The same value Python gives with
        // hmac.new(key, b'1700000000000.{"id":"x"}', hashlib.sha256).hexdigest()
        let key = unhex(KEY).unwrap();
        assert_eq!(
            signature(&key, "1700000000000", r#"{"id":"x"}"#),
            "eb90e980d6fd530fe22fad2a71c9705a07d0f5a4e788e4f0d47ea12b7236a056"
        );
    }

    #[test]
    fn executor_settings_are_checked() {
        assert!(Executor::new("http://127.0.0.1:9100/run", KEY).is_ok());
        assert!(Executor::new("https://exec.example.com/run", KEY).is_ok());
        let refused = [
            ("http://exec.example.com/run", KEY, "plain http"),
            ("ftp://127.0.0.1/", KEY, "https://"),
            ("https://user:pw@exec.example.com/", KEY, "credentials"),
            ("not a url", KEY, "not a valid URL"),
            ("https://exec.example.com/", "zz", "hex"),
            ("https://exec.example.com/", "abcd", "too short"),
        ];
        for (url, key, expected) in refused {
            match Executor::new(url, key) {
                Ok(_) => panic!("{url} should be refused"),
                Err(err) => assert!(err.contains(expected), "{err}"),
            }
        }
        let shown = Executor::new("https://exec.example.com:8443/secret/path", KEY).unwrap();
        assert_eq!(shown.shown(), "https://exec.example.com:8443");
    }
}
