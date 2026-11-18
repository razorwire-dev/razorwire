//! Keys: which agents may use the proxy, and which people may approve held
//! tool calls and reload the configuration.
//!
//! A keys file holds one key per line as `<role> <name> <sha256 of the key>`.
//! Only hashes are stored, so a leaked keys file does not leak a key. Keys
//! are 32 random bytes, so a plain SHA-256 is enough: there is nothing to
//! guess.

use std::{collections::HashMap, fmt};

use axum::http::{header, HeaderMap};
use sha2::{Digest, Sha256};

/// Every Razorwire key starts with this, so it is easy to spot in a config
/// and cannot be mistaken for a provider key.
pub const KEY_PREFIX: &str = "rw_";

/// Header an agent can use for its key when `Authorization` must carry its
/// own provider key.
pub const KEY_HEADER: &str = "x-razorwire-key";

/// Written at the top of a new keys file.
pub const KEYS_FILE_HEADER: &str = "\
# Razorwire keys, one per line: <role> <name> <sha256 of the key>.
# Only hashes are stored here. Create keys with `razorwire new-key` and
# remove them with `razorwire revoke-key`, or delete a line and run
# `razorwire reload`.
";

/// How many characters of a key's hash are shown to tell keys with the same
/// name apart. The hash cannot be turned back into the key.
pub const FINGERPRINT_CHARS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// May send requests through the proxy. The key's name is the agent's
    /// name in policy rules and in the audit log.
    Agent,
    /// May approve or deny held tool calls and reload the configuration.
    Admin,
}

impl Role {
    pub fn parse(text: &str) -> Option<Role> {
        match text {
            "agent" => Some(Role::Agent),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Agent => "agent",
            Role::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub role: Role,
    pub name: String,
}

#[derive(Debug)]
pub struct KeyError(String);

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KeyError {}

/// The keys the proxy accepts, by the hash of the key.
#[derive(Debug, Default)]
pub struct Keys {
    by_hash: HashMap<String, Identity>,
}

impl Keys {
    pub fn load(path: &str) -> Result<Keys, KeyError> {
        let text = std::fs::read_to_string(path).map_err(|err| {
            KeyError(format!(
                "cannot read keys file {path}: {err} (it must be UTF-8 text)"
            ))
        })?;
        Keys::parse(&text).map_err(|err| KeyError(format!("{path}: {err}")))
    }

    pub fn parse(text: &str) -> Result<Keys, KeyError> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut keys = Keys::default();
        for (index, line) in text.lines().enumerate() {
            let number = index + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [role, name, hash] = fields[..] else {
                return Err(KeyError(format!(
                    "line {number}: expected `<role> <name> <hash>`, found {} fields",
                    fields.len()
                )));
            };
            let Some(role) = Role::parse(role) else {
                return Err(KeyError(format!(
                    "line {number}: role must be `agent` or `admin`"
                )));
            };
            if !valid_name(name) {
                return Err(KeyError(format!(
                    "line {number}: name must be 1 to 64 letters, digits, dots, dashes or underscores"
                )));
            }
            if hash.starts_with(KEY_PREFIX) {
                return Err(KeyError(format!(
                    "line {number} holds a key, not its hash. Remove it and create a key with `razorwire new-key`"
                )));
            }
            let hash = hash.to_ascii_lowercase();
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(KeyError(format!(
                    "line {number}: the hash must be 64 hex characters"
                )));
            }
            let identity = Identity {
                role,
                name: name.to_string(),
            };
            if keys.by_hash.insert(hash, identity).is_some() {
                return Err(KeyError(format!("line {number}: this key is listed twice")));
            }
        }
        Ok(keys)
    }

    pub fn count(&self, role: Role) -> usize {
        self.by_hash.values().filter(|id| id.role == role).count()
    }

    /// Every key, admins first, then by name. Only the start of each hash is
    /// given, to tell keys with the same name apart.
    pub fn listed(&self) -> Vec<Listed> {
        let mut all: Vec<Listed> = self
            .by_hash
            .iter()
            .map(|(hash, identity)| Listed {
                role: identity.role,
                name: identity.name.clone(),
                fingerprint: hash[..FINGERPRINT_CHARS].to_string(),
            })
            .collect();
        all.sort_by(|a, b| {
            (a.role == Role::Agent, &a.name, &a.fingerprint).cmp(&(
                b.role == Role::Agent,
                &b.name,
                &b.fingerprint,
            ))
        });
        all
    }

    /// Who a presented key belongs to, if anyone.
    pub fn identify(&self, key: &str) -> Option<&Identity> {
        if !key.starts_with(KEY_PREFIX) {
            return None;
        }
        self.by_hash.get(&hash(key))
    }
}

/// One key as `razorwire keys` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub role: Role,
    pub name: String,
    pub fingerprint: String,
}

/// The text of a keys file with one key taken out: the key named `name`, or,
/// when several keys share that name, the one whose hash starts with
/// `fingerprint`. Comments and every other line are kept as they are.
pub fn without_key(
    text: &str,
    name: &str,
    fingerprint: Option<&str>,
) -> Result<(String, Listed), KeyError> {
    // Never edit a file that is already broken.
    Keys::parse(text)?;
    let fingerprint = fingerprint.map(str::to_ascii_lowercase);
    if let Some(print) = &fingerprint {
        if print.len() < 4 || !print.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(KeyError(
                "a fingerprint is at least 4 hex characters, as `razorwire keys` shows it".into(),
            ));
        }
    }

    let mut kept = String::with_capacity(text.len());
    let mut removed = Vec::new();
    let mut same_name = Vec::new();
    for line in text.split_inclusive('\n') {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let entry = match fields[..] {
            [role, key_name, hash] if key_name == name => {
                // The file was checked above, so a line with this shape is a
                // key and its hash is 64 hex characters.
                Role::parse(role.trim_start_matches('\u{feff}')).map(|role| {
                    let hash = hash.to_ascii_lowercase();
                    let listed = Listed {
                        role,
                        name: key_name.to_string(),
                        fingerprint: hash[..FINGERPRINT_CHARS].to_string(),
                    };
                    (listed, hash)
                })
            }
            _ => None,
        };
        match entry {
            Some((listed, hash))
                if fingerprint
                    .as_deref()
                    .is_none_or(|print| hash.starts_with(print)) =>
            {
                removed.push(listed.clone());
                same_name.push(listed);
            }
            Some((listed, _)) => {
                same_name.push(listed);
                kept.push_str(line);
            }
            None => kept.push_str(line),
        }
    }

    match removed.len() {
        1 => Ok((kept, removed.remove(0))),
        0 if same_name.is_empty() => Err(KeyError(format!(
            "there is no key named {name}. Run `razorwire keys` to see them"
        ))),
        0 => Err(KeyError(format!(
            "no key named {name} has a fingerprint starting with that. Run `razorwire keys` to see them"
        ))),
        _ => {
            let prints: Vec<String> = removed.iter().map(|key| key.fingerprint.clone()).collect();
            Err(KeyError(format!(
                "{} keys are named {name} (fingerprints {}). Say which: `razorwire revoke-key {name} <fingerprint>`",
                removed.len(),
                prints.join(", ")
            )))
        }
    }
}

/// The Razorwire key a request carries: the `x-razorwire-key` header, or a
/// bearer token that starts with `rw_`. A header that is not valid text
/// counts as a key that matches nothing.
pub fn presented_key(headers: &HeaderMap) -> Option<&str> {
    if let Some(value) = headers.get(KEY_HEADER) {
        return Some(value.to_str().unwrap_or("").trim());
    }
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token)
        .filter(|token| token.starts_with(KEY_PREFIX))
}

/// The token in an `Authorization: Bearer <token>` value.
pub fn bearer_token(value: &str) -> Option<&str> {
    let (scheme, token) = value.trim().split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|token| !token.is_empty())
}

/// A new key: `rw_` and 32 random bytes in hex.
pub fn generate() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|err| format!("the system random number generator failed: {err}"))?;
    Ok(format!("{KEY_PREFIX}{}", hex(&bytes)))
}

/// SHA-256 of a key, in lowercase hex. This is what a keys file stores.
pub fn hash(key: &str) -> String {
    hex(&Sha256::digest(key.as_bytes()))
}

/// The line that goes in a keys file for this key.
pub fn key_line(role: Role, name: &str, key: &str) -> String {
    format!("{} {name} {}", role.as_str(), hash(key))
}

pub fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let digit = |b: u8| (b as char).to_digit(16);
    text.as_bytes()
        .chunks(2)
        .map(|pair| Some((digit(pair[0])? * 16 + digit(pair[1])?) as u8))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn file_with(lines: &[(Role, &str, &str)]) -> String {
        let mut text = KEYS_FILE_HEADER.to_string();
        for (role, name, key) in lines {
            text.push_str(&key_line(*role, name, key));
            text.push('\n');
        }
        text
    }

    #[test]
    fn generated_keys_are_long_random_and_prefixed() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert!(a.starts_with("rw_"));
        assert_eq!(a.len(), 3 + 64);
        assert_ne!(a, b);
        assert_eq!(hash(&a).len(), 64);
        assert_ne!(hash(&a), hash(&b));
    }

    #[test]
    fn keys_are_found_by_their_hash_with_their_role() {
        let agent = generate().unwrap();
        let admin = generate().unwrap();
        let keys = Keys::parse(&file_with(&[
            (Role::Agent, "ops-bot", &agent),
            (Role::Admin, "mann", &admin),
        ]))
        .unwrap();

        assert_eq!(keys.count(Role::Agent), 1);
        assert_eq!(keys.count(Role::Admin), 1);
        let found = keys.identify(&agent).unwrap();
        assert_eq!((found.role, found.name.as_str()), (Role::Agent, "ops-bot"));
        assert_eq!(keys.identify(&admin).unwrap().role, Role::Admin);
        // A key that is close is still wrong.
        let mut near = agent.clone();
        near.pop();
        near.push(if agent.ends_with('0') { '1' } else { '0' });
        assert!(keys.identify(&near).is_none());
        assert!(keys.identify("").is_none());
        // The hash itself is not a key.
        assert!(keys.identify(&hash(&agent)).is_none());
    }

    #[test]
    fn a_keys_file_tolerates_windows_editors() {
        let key = generate().unwrap();
        let text = format!(
            "\u{feff}# comment\r\n\r\n  {}  \r\n",
            key_line(Role::Agent, "a", &key)
        );
        let keys = Keys::parse(&text).unwrap();
        assert!(keys.identify(&key).is_some());
        // Upper-case hashes are accepted too.
        let upper = format!("agent a {}\n", hash(&key).to_uppercase());
        assert!(Keys::parse(&upper).unwrap().identify(&key).is_some());
    }

    #[test]
    fn bad_keys_files_are_rejected() {
        let key = generate().unwrap();
        let h = hash(&key);
        let cases = [
            (format!("agent ops {h} extra\n"), "fields"),
            (format!("root ops {h}\n"), "role"),
            (format!("agent bad/name {h}\n"), "name"),
            (format!("agent {} {h}\n", "x".repeat(65)), "name"),
            ("agent ops abc\n".to_string(), "64 hex"),
            (format!("agent ops {}\n", "g".repeat(64)), "64 hex"),
            (format!("agent ops {key}\n"), "not its hash"),
            (format!("agent a {h}\nadmin b {h}\n"), "twice"),
        ];
        for (text, expected) in cases {
            let err = Keys::parse(&text).expect_err(&text).to_string();
            assert!(
                err.contains(expected),
                "{err:?} should mention {expected:?}"
            );
            assert!(!err.contains(&key), "errors must not echo a key");
        }
    }

    #[test]
    fn keys_are_listed_without_their_hashes() {
        let agent = generate().unwrap();
        let admin = generate().unwrap();
        let keys = Keys::parse(&file_with(&[
            (Role::Agent, "ops-bot", &agent),
            (Role::Admin, "mann", &admin),
        ]))
        .unwrap();
        let listed = keys.listed();
        assert_eq!(listed.len(), 2);
        assert_eq!(
            (listed[0].role, listed[0].name.as_str()),
            (Role::Admin, "mann")
        );
        assert_eq!(listed[0].fingerprint, hash(&admin)[..FINGERPRINT_CHARS]);
        assert_eq!(listed[1].name, "ops-bot");
    }

    #[test]
    fn a_key_is_revoked_by_name_and_the_rest_of_the_file_is_kept() {
        let (a, b, c) = (
            generate().unwrap(),
            generate().unwrap(),
            generate().unwrap(),
        );
        let text = format!(
            "{}\r\n# keep me\n{}\n{}\n",
            key_line(Role::Admin, "mann", &a),
            key_line(Role::Admin, "ada", &b),
            key_line(Role::Admin, "ada", &c)
        );

        let (kept, removed) = without_key(&format!("\u{feff}{text}"), "mann", None).unwrap();
        assert_eq!((removed.role, removed.name.as_str()), (Role::Admin, "mann"));
        assert!(!kept.contains(&hash(&a)));
        assert!(kept.contains("# keep me\n"));
        let keys = Keys::parse(&kept).unwrap();
        assert!(keys.identify(&a).is_none());
        assert!(keys.identify(&b).is_some());

        // Two keys share a name, so the fingerprint says which one goes.
        let err = without_key(&text, "ada", None).unwrap_err().to_string();
        assert!(err.contains("2 keys are named ada"), "{err}");
        let print = hash(&c)[..FINGERPRINT_CHARS].to_uppercase();
        let (kept, removed) = without_key(&text, "ada", Some(&print)).unwrap();
        assert_eq!(removed.fingerprint, hash(&c)[..FINGERPRINT_CHARS]);
        let keys = Keys::parse(&kept).unwrap();
        assert!(keys.identify(&b).is_some());
        assert!(keys.identify(&c).is_none());

        let missing = without_key(&text, "nobody", None).unwrap_err().to_string();
        assert!(missing.contains("no key named nobody"), "{missing}");
        assert!(without_key(&text, "ada", Some("zz")).is_err());
        assert!(without_key(&text, "ada", Some("0000000")).is_err());
        assert!(without_key("agent broken\n", "broken", None).is_err());
    }

    #[test]
    fn a_key_is_read_from_its_header_or_a_bearer_token() {
        let mut headers = HeaderMap::new();
        assert_eq!(presented_key(&headers), None);

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer sk-provider-key"),
        );
        assert_eq!(presented_key(&headers), None, "provider keys are not ours");

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer  rw_abc "),
        );
        assert_eq!(presented_key(&headers), Some("rw_abc"));

        headers.insert(KEY_HEADER, HeaderValue::from_static("rw_from_header"));
        assert_eq!(presented_key(&headers), Some("rw_from_header"));

        headers.insert(KEY_HEADER, HeaderValue::from_bytes(b"rw_\xff").unwrap());
        assert_eq!(
            presented_key(&headers),
            Some(""),
            "unreadable is not absent"
        );
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 1, 0x7f, 0x80, 0xff];
        assert_eq!(hex(&bytes), "00017f80ff");
        assert_eq!(unhex("00017F80ff").unwrap(), bytes);
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }

    #[test]
    fn names_are_plain() {
        assert!(valid_name("ops-bot_2.prod"));
        assert!(!valid_name(""));
        assert!(!valid_name("has space"));
        assert!(!valid_name("émoji"));
        assert!(!valid_name("a\u{1b}[31m"));
    }
}
