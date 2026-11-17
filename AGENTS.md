# AGENTS.md

Context for coding agents (Antigravity, Claude Code) working in this repo.

The project is named **Razorwire** (chosen 2026-11-16). The code lives in the
private GitHub repo `razorwire-dev/razorwire`; keep it private until launch.
The name is not yet registered on crates.io, npm or PyPI. The folder on disk
is still called `agent-firewall`.

## What this is

A runtime that sits between an AI agent and the real world. Every action the
agent tries to take is policy-checked before it runs, executed with a rollback
point, independently verified, and written to a signed audit log.

Open-source core (MIT), paid hosted control plane later.

## The four stages

| Stage | Job | Status |
|---|---|---|
| 1. Policy | Block an action before it executes: scope, limits, blast radius | Working, streamed and non-streamed, with a loop guard and human approval |
| 2. Sandbox | Shadow mode (log what would have happened) and rollback | Shadow mode works. Rollback not started |
| 3. Verify | Check ground truth through a separate path, never the agent's own "done" | Not started |
| 4. Attest | Tamper-evident, exportable log of every decision | HMAC-chained JSONL, checked by `razorwire verify-log`. No public-key signatures or export yet |

## Product rules

- **Structural guardrails first.** Policy enforcement, sandboxing and rollback
  are the product. "The agent double-checks itself" is weak and is not.
- **Not an eval or observability tool.** This runs in the hot path and prevents
  an action. It does not score an agent after the fact.
- **The proxy is a security product.** No `unsafe`, no panics on bad input,
  never log or print a key or an `Authorization` header. `SECURITY.md` is
  the threat model; keep it true when behaviour changes.
- **Fail closed.** Under an enforced policy, anything that cannot be checked is
  blocked: a rule that errors, a tool call with no name, a response or a
  stream that cannot be read, a held call nobody decided. A config file that
  is asked for but invalid stops startup, and a reload that finds one keeps
  the old config.
- **Agent and admin keys never mix.** An agent key cannot use the admin API
  and an admin key cannot be used by an agent, so no agent can approve its
  own calls.

## Where things are

```
README.md                    public front page: what it is, demo, how to run
SECURITY.md                  what is protected, how, and what is not
Cargo.toml                   crate manifest
src/main.rs                  the command line: serve, new-key, verify-log, approve...
src/proxy.rs                 the proxy: auth, forwarding, policing, waiting on approvals
src/admin.rs                 the admin API under /razorwire/, and its command-line client
src/auth.rs                  keys files, key hashing, reading a key from a request
src/approvals.rs             tool calls held for a human decision
src/audit.rs                 the audit log: HMAC chain, verification, safe escaping
src/policy.rs                policy files: load, validate, decide
src/openai.rs                find tool calls in provider payloads, plan and apply
                             decisions, count the run from the conversation history
src/sse.rs                   streamed replies: reassemble them, rebuild them after a block
examples/demo_agent.rs       reckless agents: one drops databases, one gets stuck polling
policy/policy.schema.json    JSON Schema for policy files
policy/example.policy.yaml   example policy, also used by the unit tests
```

## How blocking works

The agent points its SDK at the proxy instead of the provider. Requests are
forwarded unchanged apart from keys. The model's tool calls come back in the
provider's response, and that is where the proxy acts:

1. `openai::plan` matches each tool call against the policy rules, top to
   bottom, without changing the response. The first rule that matches
   decides: `allow`, `deny` or `review`.
2. A `review` call is held when an admin key is set up (see Approvals). With
   no admin key, it is blocked at once.
3. `openai::apply` removes blocked calls, and held calls that were not
   approved. A note that starts with `[razorwire] Blocked tool call` is added
   to the assistant message so the model and the operator can see what was
   stopped and by which rule.
4. Calls that are allowed or approved stay in the response. If none are
   left, the `finish_reason` becomes `stop`.
5. The response carries an `x-razorwire-blocked: <count>` header.

The agent never receives a blocked call, so it has nothing to execute.

Both the Chat Completions shape (`tool_calls`, legacy `function_call`, custom
tools) and the Responses API shape (`function_call`, `custom_tool_call`) are
handled. `plan` and `apply` walk the response in the same order through one
`visit` function; if they ever disagree, the extra call is blocked.

### Streamed replies

A streamed reply (`"stream": true`) spreads each tool call over many events.

- **Policy enforced:** the whole stream is held back, reassembled into the
  non-streamed shape, and checked by the same code. If nothing is blocked the
  provider's original bytes are sent on unchanged. If something is blocked, a
  rebuilt stream is sent with the blocked calls removed. Either way the agent
  receives the reply in one burst when it is complete, not word by word.
- **No policy, or shadow mode:** the stream passes through live and is read
  on the side, so tool calls and decisions still reach the audit log.

### Loop guard

Agents resend the whole conversation with every request, so the proxy reads
where a run stands from the request itself and keeps no state between
requests. `openai::History` counts the assistant's earlier tool calls (Chat
Completions `messages`, Responses API `input`) and the `[razorwire]` block
notes in the assistant's earlier messages. Calls earlier in the same response
count too: those passed on, those blocked and those held. Each choice of an
`n > 1` reply is counted on its own.

Rules read the counts as `run` (`calls`, `same_tool`, `repeats`, `streak`,
`blocked`). The variable is `run` because CEL reserves the word `loop`. A
blocked or held call never reaches the agent before a decision, so it is not
in `calls` and does not break or extend a streak; it is counted in `blocked`.

## Keys and identity

`KEYS_FILE` lists keys as `<role> <name> <sha256 of the key>`, one per line.
Roles are `agent` and `admin`. Keys are `rw_` plus 32 random bytes in hex,
made by `razorwire new-key`, which appends the hash line and shows the key
once. A line holding a raw key instead of a hash is rejected.

- **With agent keys:** every proxied request needs one, as
  `Authorization: Bearer rw_...` or in `x-razorwire-key`. The agent's name
  is the key's name. `x-agent-name` is ignored.
- **Without agent keys:** anyone who can reach the proxy can use it, and
  `x-agent-name` is trusted. Allowed only when listening on loopback.
- **`UPSTREAM_API_KEY`:** the proxy replaces the agent's `Authorization` with
  the provider key, so agents never hold it.
- Never forwarded upstream: Razorwire keys, any `x-razorwire-*` header,
  `x-agent-name`, hop-by-hop headers and headers named in `Connection`.
  Dropped from the provider's response: any `x-razorwire-*` header.
- Paths under `/razorwire` are never forwarded.

## Approvals

When a `review` rule fires under an enforced policy and an admin key exists,
`proxy::police` registers each held call in `approvals::Approvals` (at most
256 at once) and waits up to `APPROVAL_TIMEOUT_SECS` (default 300). The
agent's request stays open. An admin decides through the admin API:

| Endpoint | Does |
|---|---|
| `GET /razorwire/approvals` | List held calls, oldest first |
| `POST /razorwire/approvals/{id}/approve` | Let the call through unchanged |
| `POST /razorwire/approvals/{id}/deny` | Block it. Optional body `{"reason": "..."}`, cleaned, up to 500 characters |
| `POST /razorwire/reload` | Re-read the policy and keys files |

Every endpoint needs an admin key in `Authorization: Bearer`. A denied call's
note says who denied it and why. An expired call's note says nobody approved
it in time. If the agent hangs up, the held call is withdrawn and
`approval_abandoned` is logged. Admin responses are `no-store` and
`nosniff`, and admin bodies are capped at 16 KB.

## Policy files

Format: `policy/policy.schema.json`. Example: `policy/example.policy.yaml`.

- `match.tool` and `match.agent` take `*` as a wildcard.
- `when` is a CEL expression. `args` is the tool call's decoded arguments,
  `agent` is the agent's name (from its key, or `x-agent-name` without agent
  keys; empty if unset), `run` holds the loop guard counts.
- A rule that matches a call but whose `when` cannot be evaluated (for example
  a missing argument) blocks the call. Guard optional fields with
  `has(args.field)`.
- `mode: shadow` logs every decision and blocks or holds nothing.
- `razorwire reload` re-reads the policy and keys files. Each request uses
  the configuration it started with.

## Audit log

One JSON object per line in `audit.jsonl`:

- `tool_call`: a tool call the model asked for, with its `run` counts. With a
  policy loaded it also carries `decision`, `rule`, `reason` when not
  allowed, and either `blocked` or, for a held call, `held: true` and
  `approval_id`.
- `tool_result`: a tool result the agent sent back, logged once per call id.
- `approval_requested`, `approval_decided` (`approved`, `denied` or
  `expired`, with `by` and `reason`), `approval_abandoned`.
- `auth_failed` (never with the key), and `auth_failures_suppressed` when
  more than 20 a minute were not logged.
- `proxy_started`, `config_reloaded`, `reload_failed`, `response_refused`.

With `AUDIT_KEY` (hex, at least 32 bytes; `razorwire new-audit-key`), each
line ends with `,"seq":<n>,"mac":"<hex>"}`. The MAC is HMAC-SHA256 over the
previous line's MAC, the seq and the rest of the line, so lines vouch for
each other. On restart the chain continues from the file's last line.
`razorwire verify-log` reports the first broken line. DEL, C1 controls and
Unicode direction marks are escaped as `\uXXXX` in every line.

## Known limits

- **Streaming is delayed under enforcement.** The reply is held until it is
  complete (up to 32 MB), so the agent loses word-by-word output.
- **Rebuilt streams are minimal.** When a call is blocked, the rebuilt Chat
  Completions stream carries the text and the remaining tool calls; other
  streamed fields such as reasoning are dropped. The rebuilt Responses API
  stream has only the start, item and final events. Both parse in the
  OpenAI Python SDK.
- **Clients tested.** Groq with raw HTTP clients, the OpenAI Python SDK 3.53
  (Chat Completions plain, streamed and the stream helper; the Responses API
  plain and streamed), and LangGraph 1.2 through langchain-openai 1.8
  (plain and streamed). Not yet tested with CrewAI.
- **Loop counts trust the conversation.** An agent that trims or rewrites
  its history starts its counts over. With the Responses API's
  `previous_response_id`, only the turns in the request are counted. In
  shadow mode nothing is blocked, so `run.blocked` stays 0.
- **Coverage.** Only OpenAI-compatible payloads are understood. Tools the
  provider runs itself (web search, code interpreter) and the Responses API's
  computer and shell calls are not checked.
- **Approvals hold the whole response** and live in memory; a restart drops
  them and the waiting request fails.
- **No TLS.** Plain HTTP only; a TLS proxy goes in front for remote use.
- **Log truncation.** Lines cut off the end of the audit log cannot be
  detected from the file. Someone with `AUDIT_KEY` can forge the log.
- **Bypass.** An agent that can reach the provider directly skips the proxy.
  `UPSTREAM_API_KEY` takes away the key; the network must take away the route.

## Run it

```
cargo run
```

Environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `UPSTREAM_URL` | `https://api.openai.com` | Provider to forward to, path appended as-is. https only, unless on loopback |
| `UPSTREAM_API_KEY` | unset | Provider key the proxy sends in place of the agent's |
| `LISTEN_ADDR` | `127.0.0.1:8080` | Where the proxy listens. Non-loopback needs agent keys |
| `POLICY_FILE` | unset | Policy to load. Unset means log only, nothing is blocked |
| `KEYS_FILE` | unset | Agent and admin keys. `new-key` writes `razorwire.keys` by default |
| `AUDIT_LOG` | `audit.jsonl` | File that events are appended to |
| `AUDIT_KEY` | unset | Hex key that signs the audit log |
| `APPROVAL_TIMEOUT_SECS` | `300` | How long a held call waits, 1 to 3600 |

Commands: `razorwire [serve]`, `new-key <agent|admin> <name>`,
`new-audit-key`, `check-policy <file>`, `verify-log [file]`, `approvals`,
`approve <id> [reason]`, `deny <id> [reason]`, `reload`, `help`. The admin
commands use `RAZORWIRE_URL` (default `http://127.0.0.1:8080`, https
required for anything not on loopback) and `RAZORWIRE_ADMIN_KEY`.

Point an agent at it:

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:8080/v1")  # key still comes from OPENAI_API_KEY
```

With keys and `UPSTREAM_API_KEY`, the agent's API key is its `rw_` key.

For Groq, set `UPSTREAM_URL=https://api.groq.com/openai` and keep the same
`base_url`.

## The demo

Terminal 1, the proxy with the example policy (PowerShell):

```
$env:UPSTREAM_URL="https://api.groq.com/openai"; $env:POLICY_FILE="policy/example.policy.yaml"; cargo run
```

Terminal 2, the agent:

```
cargo run --example demo_agent
cargo run --example demo_agent -- loop
```

The first agent is told to drop the staging and production databases. With
the policy loaded, staging is dropped and production survives. Start the
proxy without `POLICY_FILE` and both are dropped.

The second agent is told to wait for a deploy that never finishes. With the
policy loaded, `stuck-in-a-loop` stops it after two status checks. Without
it, the agent keeps checking until the demo's own cap of 12 turns.

The agents read `GROQ_API_KEY` from the environment or from `.env`, and run
without keys, so the demo proxy must not have agent keys set up.

## Stack

| Part | Choice |
|---|---|
| Proxy and policy engine | Rust: tokio, axum, reqwest |
| Policy expressions | CEL, via the `cel` crate |
| Policy file parsing | `serde-saphyr` |
| Keys and log signing | `sha2`, `hmac`, `getrandom` |
| SDKs | Python and TypeScript, thin wrappers over the Rust core |
| Control plane | Next.js on Vercel |
| Storage | Postgres, ClickHouse for traces |
| Billing | Stripe |

## Roadmap

| Weeks | Ship |
|---|---|
| 1-2 | Proxy intercepts and logs tool calls. Done. Repo is private until launch |
| 3-4 | Policy engine: YAML rules that block an action, and the demo. Done. Loop guard, approvals, keys, signed log and reload: done |
| 5-6 | Python SDK, LangGraph and CrewAI adapters, docs. Verification for Postgres, Stripe, SendGrid, GitHub, Slack |
| 7 | Rollback. Show HN launch |
| 8 | Hosted control plane and Stripe billing |

Next up, in order: an easy install (release binaries), testing with CrewAI,
live streaming under enforcement, rollback.

## Conventions

- `cargo fmt` and `cargo clippy --all-targets -- -D warnings` before committing.
- Every parser for a provider payload gets a unit test with a real-shaped sample.
- Keep dependencies few. Each new crate needs a reason.
