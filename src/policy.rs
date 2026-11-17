//! Policy files: loading, validating, and deciding what happens to a tool call.
//!
//! The file format is described by `policy/policy.schema.json`. Rules are
//! evaluated top to bottom and the first one that matches decides.

use std::{collections::HashMap, collections::HashSet, fmt, sync::Arc};

use cel::{Context, Env, Program, RuntimeOptions, Value as CelValue};
use serde::Deserialize;
use serde_json::{json, Value};

/// Upper bound on loop iterations inside one `when` expression, so a rule such
/// as `args.items.all(...)` cannot be made to spin on a huge argument list.
const MAX_CEL_ITERATIONS: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Decisions are applied: denied calls never reach the agent.
    #[default]
    Enforce,
    /// Decisions are only logged. Every call goes through.
    Shadow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Allow,
    Deny,
    /// Hold for a human. There is no approval flow yet, so a held call is
    /// blocked exactly like a denied one.
    Review,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Review => "review",
        }
    }
}

/// What the policy says about one tool call.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub action: Action,
    /// The rule that decided, or `None` when the file's default applied.
    pub rule: Option<String>,
    /// Explanation shown to the agent when the call is not allowed.
    pub message: String,
    /// Set when a rule could not be evaluated and the call was denied for it.
    pub error: Option<String>,
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        self.action == Action::Allow
    }
}

/// What already happened in the agent's run before this tool call, counted
/// from the conversation the agent sent with its request. Rules read it as
/// `run`, so a policy can stop an agent that is stuck or has done too much.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunCounts {
    /// Tool calls the agent received earlier in this run.
    pub calls: u64,
    /// Of those, calls to the same tool.
    pub same_tool: u64,
    /// Of those, calls to the same tool with the same arguments.
    pub repeats: u64,
    /// How many times in a row, just before this call, the agent made exactly
    /// this call. Asking for the same thing over and over is a stuck loop.
    pub streak: u64,
    /// Tool calls Razorwire blocked earlier in this run.
    pub blocked: u64,
}

impl RunCounts {
    /// The counts as a JSON object, for the audit log and for rules. Counts
    /// are capped at the largest signed integer so that rules always see CEL
    /// integers and `run.calls > 50` compares like with like.
    pub fn as_json(&self) -> Value {
        let int = |count: u64| i64::try_from(count).unwrap_or(i64::MAX);
        json!({
            "calls": int(self.calls),
            "same_tool": int(self.same_tool),
            "repeats": int(self.repeats),
            "streak": int(self.streak),
            "blocked": int(self.blocked),
        })
    }
}

#[derive(Debug)]
pub struct PolicyError(String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    #[serde(default)]
    mode: Mode,
    #[serde(default, rename = "default")]
    default_action: Action,
    rules: Vec<RuleFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    id: String,
    #[serde(default)]
    #[allow(dead_code)] // documentation for humans; not used by the engine
    description: Option<String>,
    #[serde(rename = "match")]
    matcher: MatchFile,
    #[serde(default)]
    when: Option<String>,
    action: Action,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MatchFile {
    tool: String,
    #[serde(default)]
    agent: Option<String>,
}

struct Rule {
    id: String,
    tool: String,
    agent: Option<String>,
    when: Option<Program>,
    action: Action,
    message: Option<String>,
}

/// A validated policy with its `when` expressions already compiled.
pub struct Policy {
    mode: Mode,
    default_action: Action,
    rules: Vec<Rule>,
    env: Arc<Env>,
}

impl Policy {
    /// Read and validate a policy file.
    pub fn load(path: &str) -> Result<Policy, PolicyError> {
        let text = std::fs::read_to_string(path)
            .map_err(|err| PolicyError(format!("cannot read policy file {path}: {err}")))?;
        Policy::parse(&text).map_err(|err| PolicyError(format!("{path}: {err}")))
    }

    /// Validate policy text. Every problem is reported before the proxy
    /// starts, never while a tool call is waiting on a decision.
    pub fn parse(text: &str) -> Result<Policy, PolicyError> {
        let file: PolicyFile = serde_saphyr::from_str(text)
            .map_err(|err| PolicyError(format!("invalid policy: {err}")))?;

        if file.version != 1 {
            return Err(PolicyError(format!(
                "unsupported policy version {}, expected 1",
                file.version
            )));
        }

        let mut env = Env::stdlib();
        env.set_options(RuntimeOptions::default().with_max_iterations(MAX_CEL_ITERATIONS));
        let env = Arc::new(env);

        let mut seen_ids = HashSet::new();
        let mut rules = Vec::with_capacity(file.rules.len());
        for rule in file.rules {
            if !is_valid_id(&rule.id) {
                return Err(PolicyError(format!(
                    "rule id {:?} must be lowercase letters, digits and dashes, and start with a letter or digit",
                    rule.id
                )));
            }
            if !seen_ids.insert(rule.id.clone()) {
                return Err(PolicyError(format!("rule id {:?} is used twice", rule.id)));
            }
            if rule.matcher.tool.is_empty() {
                return Err(PolicyError(format!(
                    "rule {}: match.tool is empty",
                    rule.id
                )));
            }
            if rule.matcher.agent.as_deref() == Some("") {
                return Err(PolicyError(format!(
                    "rule {}: match.agent is empty",
                    rule.id
                )));
            }
            let when = match rule.when {
                None => None,
                Some(source) if source.trim().is_empty() => {
                    return Err(PolicyError(format!("rule {}: when is empty", rule.id)));
                }
                Some(source) => Some(env.compile(&source).map_err(|err| {
                    PolicyError(format!("rule {}: invalid when expression: {err}", rule.id))
                })?),
            };
            rules.push(Rule {
                id: rule.id,
                tool: rule.matcher.tool,
                agent: rule.matcher.agent,
                when,
                action: rule.action,
                message: rule.message,
            });
        }

        Ok(Policy {
            mode: file.mode,
            default_action: file.default_action,
            rules,
            env,
        })
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Decide what happens to one tool call. Fails closed: a rule that applies
    /// to the call but cannot be evaluated denies it.
    pub fn decide(&self, agent: &str, tool: &str, args: &Value, run: &RunCounts) -> Decision {
        for rule in &self.rules {
            if !glob_match(&rule.tool, tool) {
                continue;
            }
            if let Some(pattern) = &rule.agent {
                if !glob_match(pattern, agent) {
                    continue;
                }
            }
            let fires = match &rule.when {
                None => Ok(true),
                Some(program) => self.evaluate(program, agent, args, run),
            };
            match fires {
                Ok(false) => continue,
                Ok(true) => {
                    return Decision {
                        action: rule.action,
                        rule: Some(rule.id.clone()),
                        message: rule.message.clone().unwrap_or_else(|| match rule.action {
                            Action::Allow => String::new(),
                            Action::Deny => format!("Blocked by policy rule {}.", rule.id),
                            Action::Review => {
                                format!("Held for human approval by policy rule {}.", rule.id)
                            }
                        }),
                        error: None,
                    };
                }
                Err(error) => {
                    return Decision {
                        action: Action::Deny,
                        rule: Some(rule.id.clone()),
                        message: format!(
                            "Policy rule {} could not be evaluated for this call, so it was blocked.",
                            rule.id
                        ),
                        error: Some(error),
                    };
                }
            }
        }

        Decision {
            action: self.default_action,
            rule: None,
            message: match self.default_action {
                Action::Allow => String::new(),
                Action::Deny => "No policy rule allows this tool call.".to_string(),
                Action::Review => {
                    "No policy rule covers this tool call, so it is held for human approval."
                        .to_string()
                }
            },
            error: None,
        }
    }

    fn evaluate(
        &self,
        program: &Program,
        agent: &str,
        args: &Value,
        run: &RunCounts,
    ) -> Result<bool, String> {
        let mut context = Context::with_env(self.env.clone());
        context.add_variable_from_value("args", to_cel(args));
        context.add_variable_from_value("agent", agent);
        // `run`, not `loop`: CEL reserves the word `loop`.
        context.add_variable_from_value("run", to_cel(&run.as_json()));
        match program.execute(&context) {
            Ok(CelValue::Bool(result)) => Ok(result),
            Ok(other) => Err(format!(
                "expression returned {other:?}, expected true or false"
            )),
            Err(err) => Err(err.to_string()),
        }
    }
}

/// Convert decoded tool arguments into CEL values. Whole numbers become CEL
/// integers so that `args.amount > 500` compares like with like.
fn to_cel(value: &Value) -> CelValue {
    match value {
        Value::Null => CelValue::Null,
        Value::Bool(flag) => CelValue::Bool(*flag),
        Value::Number(number) => {
            if let Some(int) = number.as_i64() {
                CelValue::Int(int)
            } else if let Some(uint) = number.as_u64() {
                CelValue::UInt(uint)
            } else {
                CelValue::Float(number.as_f64().unwrap_or(f64::NAN))
            }
        }
        Value::String(text) => CelValue::String(Arc::new(text.clone())),
        Value::Array(items) => CelValue::List(Arc::new(items.iter().map(to_cel).collect())),
        Value::Object(fields) => CelValue::from(
            fields
                .iter()
                .map(|(key, item)| (key.clone(), to_cel(item)))
                .collect::<HashMap<String, CelValue>>(),
        ),
    }
}

fn is_valid_id(id: &str) -> bool {
    let mut chars = id.chars();
    let starts_well = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    starts_well && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Match `text` against `pattern`, where `*` stands for any run of characters
/// (including none). Everything else must match exactly, case included.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0, 0);
    let mut last_star: Option<usize> = None;
    let mut star_text = 0;

    while t < text.len() {
        if p < pattern.len() && pattern[p] == '*' {
            last_star = Some(p);
            star_text = t;
            p += 1;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some(star) = last_star {
            // Let the last `*` swallow one more character and retry.
            p = star + 1;
            star_text += 1;
            t = star_text;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const EXAMPLE: &str = include_str!("../policy/example.policy.yaml");

    fn policy(text: &str) -> Policy {
        Policy::parse(text).expect("policy should parse")
    }

    impl Policy {
        /// `decide` for a call that starts a run, with nothing before it.
        fn check(&self, agent: &str, tool: &str, args: &Value) -> Decision {
            self.decide(agent, tool, args, &RunCounts::default())
        }
    }

    fn run(calls: u64, same_tool: u64, repeats: u64, streak: u64, blocked: u64) -> RunCounts {
        RunCounts {
            calls,
            same_tool,
            repeats,
            streak,
            blocked,
        }
    }

    #[test]
    fn rules_can_read_the_run() {
        let policy = policy(
            r#"
version: 1
rules:
  - id: polls
    match: { tool: deploy_status }
    when: run.same_tool >= 10 || run.streak >= 5
    action: deny
  - id: busy
    match: { tool: "*" }
    when: run.calls > 3 && run.blocked == 0 && run.repeats < 1
    action: review
"#,
        );
        let args = json!({ "deploy_id": 42 });

        let fresh = policy.decide("", "deploy_status", &args, &run(0, 0, 0, 0, 0));
        assert!(fresh.is_allowed(), "{fresh:?}");

        let polled = policy.decide("", "deploy_status", &args, &run(10, 10, 0, 0, 0));
        assert_eq!(polled.rule.as_deref(), Some("polls"));
        assert!(polled.error.is_none());

        let streak = policy.decide("", "deploy_status", &args, &run(5, 5, 5, 5, 0));
        assert_eq!(streak.rule.as_deref(), Some("polls"));

        let busy = policy.decide("", "other", &args, &run(4, 0, 0, 0, 0));
        assert_eq!(busy.rule.as_deref(), Some("busy"));
        assert_eq!(busy.action, Action::Review);

        let repeated = policy.decide("", "other", &args, &run(4, 0, 1, 0, 0));
        assert!(repeated.is_allowed(), "{repeated:?}");
    }

    #[test]
    fn example_policy_guards_the_loop() {
        let policy = policy(EXAMPLE);
        let harmless = json!({ "query": "status" });
        let decide = |counts| policy.decide("", "web_search", &harmless, &counts);

        // Repeating a call with other calls in between is not being stuck.
        assert!(decide(run(49, 49, 9, 1, 2)).is_allowed());

        let stuck = run(2, 2, 2, 2, 0);
        let strikes = run(3, 0, 0, 0, 3);
        let budget = run(50, 0, 0, 0, 0);
        assert_eq!(decide(stuck).rule.as_deref(), Some("stuck-in-a-loop"));
        assert_eq!(decide(strikes).rule.as_deref(), Some("three-strikes"));
        assert_eq!(decide(budget).rule.as_deref(), Some("run-budget"));
        for counts in [stuck, strikes, budget] {
            let decision = decide(counts);
            assert_eq!(decision.action, Action::Deny, "{decision:?}");
            assert!(decision.error.is_none(), "{decision:?}");
        }
    }

    #[test]
    fn a_polled_tool_can_be_let_through_for_longer() {
        // The tip in the example policy, uncommented, must work as described.
        let tip = "  # - id: deploys-can-be-polled\n  #   match:\n  #     tool: deploy_status\n  #   when: run.streak < 20\n  #   action: allow\n";
        assert!(EXAMPLE.contains(tip), "the example policy lost the tip");
        let policy = policy(&EXAMPLE.replace(tip, &tip.replace("  # ", "  ")));
        let args = json!({ "deploy_id": 42 });
        let at = |counts| policy.decide("", "deploy_status", &args, &counts);

        assert!(at(run(5, 5, 5, 5, 0)).is_allowed());
        assert_eq!(
            at(run(20, 20, 20, 20, 0)).rule.as_deref(),
            Some("stuck-in-a-loop")
        );
        // The strikes and the budget still apply to the polled tool.
        assert_eq!(
            at(run(5, 5, 5, 5, 3)).rule.as_deref(),
            Some("three-strikes")
        );
        assert_eq!(at(run(50, 5, 5, 5, 0)).rule.as_deref(), Some("run-budget"));
        // Other tools are still stopped early.
        let other = policy.decide("", "web_search", &args, &run(2, 2, 2, 2, 0));
        assert_eq!(other.rule.as_deref(), Some("stuck-in-a-loop"));
    }

    #[test]
    fn run_counts_reach_rules_and_the_log_as_numbers() {
        let counts = run(1, 2, 3, 4, 5).as_json();
        assert_eq!(
            counts,
            json!({ "calls": 1, "same_tool": 2, "repeats": 3, "streak": 4, "blocked": 5 })
        );
        // The largest count is capped, and still compares without an error.
        assert_eq!(run(u64::MAX, 0, 0, 0, 0).as_json()["calls"], i64::MAX);
        let policy = policy(
            "version: 1\nrules:\n  - id: a\n    match: { tool: x }\n    when: run.calls > 0\n    action: deny\n",
        );
        let huge = policy.decide("", "x", &json!({}), &run(u64::MAX, 0, 0, 0, 0));
        assert_eq!(huge.action, Action::Deny, "{huge:?}");
        assert!(huge.error.is_none(), "{huge:?}");
    }

    #[test]
    fn glob_matches_wildcards() {
        assert!(glob_match("db_drop", "db_drop"));
        assert!(glob_match("db_*", "db_drop"));
        assert!(glob_match("db_*", "db_"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("*_drop", "db_drop"));
        assert!(glob_match("a*b*c", "a-x-b-y-c"));
        assert!(glob_match("a**c", "abc"));
        assert!(!glob_match("db_*", "database_drop"));
        assert!(!glob_match("db_drop", "db_drop_all"));
        assert!(!glob_match("db_drop", "DB_DROP"));
        assert!(!glob_match("a*b", "a-b-c"));
        assert!(!glob_match("", "x"));
        assert!(glob_match("", ""));
    }

    #[test]
    fn example_policy_blocks_production_drop() {
        let policy = policy(EXAMPLE);
        let decision = policy.check("", "db_drop", &json!({ "database": "production" }));
        assert_eq!(decision.action, Action::Deny);
        assert_eq!(decision.rule.as_deref(), Some("no-production-db-drop"));
        assert!(decision.error.is_none());
    }

    #[test]
    fn example_policy_allows_staging_drop() {
        let policy = policy(EXAMPLE);
        let decision = policy.check("", "db_drop", &json!({ "database": "staging" }));
        assert!(decision.is_allowed());
        assert_eq!(decision.rule, None);
    }

    #[test]
    fn example_policy_holds_large_refunds() {
        let policy = policy(EXAMPLE);
        let large = policy.check("", "stripe_refund", &json!({ "amount": 47000 }));
        assert_eq!(large.action, Action::Review);
        assert_eq!(large.rule.as_deref(), Some("refund-cap"));

        let small = policy.check("", "stripe_refund", &json!({ "amount": 20 }));
        assert!(small.is_allowed());

        let boundary = policy.check("", "stripe_refund", &json!({ "amount": 500 }));
        assert!(boundary.is_allowed());
    }

    #[test]
    fn refund_cap_handles_decimal_amounts() {
        let policy = policy(EXAMPLE);
        let over = policy.check("", "stripe_refund", &json!({ "amount": 500.01 }));
        assert_eq!(over.action, Action::Review, "{over:?}");
        let under = policy.check("", "stripe_refund", &json!({ "amount": 499.99 }));
        assert!(under.is_allowed(), "{under:?}");
    }

    #[test]
    fn example_policy_checks_every_email_recipient() {
        let policy = policy(EXAMPLE);
        let inside = policy.check(
            "",
            "email_send",
            &json!({ "to": ["a@example.com", "b@example.com"] }),
        );
        assert!(inside.is_allowed(), "{inside:?}");

        let outside = policy.check(
            "",
            "email_send",
            &json!({ "to": ["a@example.com", "attacker@evil.test"] }),
        );
        assert_eq!(outside.action, Action::Deny);
        assert_eq!(outside.rule.as_deref(), Some("email-allowlist"));
    }

    #[test]
    fn a_rule_that_cannot_be_evaluated_denies() {
        let policy = policy(EXAMPLE);
        // No `database` field, so `args.database == "production"` has no answer.
        let decision = policy.check("", "db_drop", &json!({}));
        assert_eq!(decision.action, Action::Deny);
        assert_eq!(decision.rule.as_deref(), Some("no-production-db-drop"));
        assert!(decision.error.is_some());
    }

    #[test]
    fn arguments_that_are_not_an_object_deny_on_matching_rules() {
        let policy = policy(EXAMPLE);
        let decision = policy.check("", "db_drop", &json!("drop everything"));
        assert_eq!(decision.action, Action::Deny);
        assert!(decision.error.is_some());
    }

    #[test]
    fn first_matching_rule_wins() {
        let policy = policy(
            r#"
version: 1
rules:
  - id: allow-reads
    match: { tool: "db_*" }
    when: args.operation == "read"
    action: allow
  - id: deny-db
    match: { tool: "db_*" }
    action: deny
"#,
        );
        let read = policy.check("", "db_query", &json!({ "operation": "read" }));
        assert_eq!(read.rule.as_deref(), Some("allow-reads"));
        assert!(read.is_allowed());

        let write = policy.check("", "db_query", &json!({ "operation": "write" }));
        assert_eq!(write.rule.as_deref(), Some("deny-db"));
        assert_eq!(write.action, Action::Deny);
        assert_eq!(write.message, "Blocked by policy rule deny-db.");
    }

    #[test]
    fn default_deny_blocks_unlisted_tools() {
        let policy = policy(
            r#"
version: 1
default: deny
rules:
  - id: allow-search
    match: { tool: web_search }
    action: allow
"#,
        );
        assert!(policy.check("", "web_search", &json!({})).is_allowed());
        let other = policy.check("", "shell_exec", &json!({}));
        assert_eq!(other.action, Action::Deny);
        assert_eq!(other.rule, None);
    }

    #[test]
    fn rules_can_target_one_agent() {
        let policy = policy(
            r#"
version: 1
rules:
  - id: intern-cannot-pay
    match: { tool: "stripe_*", agent: "intern-*" }
    action: deny
  - id: support-small-refunds-only
    match: { tool: stripe_refund }
    when: agent == "support" && args.amount > 100
    action: deny
"#,
        );
        let intern = policy.check("intern-7", "stripe_refund", &json!({ "amount": 1 }));
        assert_eq!(intern.rule.as_deref(), Some("intern-cannot-pay"));

        let support = policy.check("support", "stripe_refund", &json!({ "amount": 150 }));
        assert_eq!(support.rule.as_deref(), Some("support-small-refunds-only"));

        let finance = policy.check("finance", "stripe_refund", &json!({ "amount": 150 }));
        assert!(finance.is_allowed());
    }

    #[test]
    fn has_guards_optional_fields() {
        let policy = policy(
            r#"
version: 1
rules:
  - id: no-force
    match: { tool: git_push }
    when: has(args.force) && args.force
    action: deny
"#,
        );
        assert!(policy.check("", "git_push", &json!({})).is_allowed());
        assert!(policy
            .check("", "git_push", &json!({ "force": false }))
            .is_allowed());
        let forced = policy.check("", "git_push", &json!({ "force": true }));
        assert_eq!(forced.action, Action::Deny);
        assert!(forced.error.is_none());
    }

    #[test]
    fn a_when_that_is_not_true_or_false_denies() {
        let policy = policy(
            r#"
version: 1
rules:
  - id: bad-type
    match: { tool: "*" }
    when: args.amount
    action: allow
"#,
        );
        let decision = policy.check("", "anything", &json!({ "amount": 5 }));
        assert_eq!(decision.action, Action::Deny);
        assert!(decision.error.is_some());
    }

    #[test]
    fn shadow_mode_and_defaults_are_read() {
        let shadow = policy("version: 1\nmode: shadow\nrules: []\n");
        assert_eq!(shadow.mode(), Mode::Shadow);
        let plain = policy("version: 1\nrules: []\n");
        assert_eq!(plain.mode(), Mode::Enforce);
        assert!(plain.check("", "anything", &json!({})).is_allowed());
    }

    #[test]
    fn unusual_argument_values_are_handled() {
        let policy = policy(
            r#"
version: 1
rules:
  - id: big-or-flagged
    match: { tool: "*" }
    when: args.count > 10 || args.nested[1].flag || args.missing == null
    action: deny
"#,
        );
        let args = json!({
            "count": 18446744073709551615u64,
            "ratio": 1.5,
            "missing": null,
            "nested": [1, { "flag": true }],
            "text": "",
        });
        // Whatever the answer, deciding must not panic, and must not allow.
        let decision = policy.check("", "anything", &args);
        assert_eq!(decision.action, Action::Deny, "{decision:?}");

        let empty = policy.check("", "anything", &Value::Null);
        assert_eq!(empty.action, Action::Deny, "{empty:?}");
    }

    #[test]
    fn invalid_policies_are_rejected() {
        let cases = [
            ("version: 2\nrules: []\n", "version"),
            ("rules: []\n", "version"),
            ("version: 1\n", "rules"),
            ("version: 1\nrules: []\nextra: true\n", "extra"),
            (
                "version: 1\nrules:\n  - id: Bad_ID\n    match: { tool: x }\n    action: deny\n",
                "rule id",
            ),
            (
                "version: 1\nrules:\n  - id: a\n    match: { tool: x }\n    action: deny\n  - id: a\n    match: { tool: y }\n    action: deny\n",
                "twice",
            ),
            (
                "version: 1\nrules:\n  - id: a\n    match: { tool: x }\n    action: explode\n",
                "explode",
            ),
            (
                "version: 1\nrules:\n  - id: a\n    match: { tool: x }\n    when: \"args.amount >\"\n    action: deny\n",
                "when",
            ),
            (
                "version: 1\nrules:\n  - id: a\n    match: { tool: \"\" }\n    action: deny\n",
                "match.tool",
            ),
            (
                "version: 1\nrules:\n  - id: a\n    match: { tool: x, typo: y }\n    action: deny\n",
                "typo",
            ),
        ];
        for (text, expected) in cases {
            match Policy::parse(text) {
                Ok(_) => panic!("policy should be rejected:\n{text}"),
                Err(err) => assert!(
                    err.to_string().contains(expected),
                    "error {:?} should mention {expected:?}",
                    err.to_string()
                ),
            }
        }
    }
}
