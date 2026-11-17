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
| 1. Policy | Block an action before it executes: scope, limits, blast radius | Working, streamed and non-streamed, with a loop guard |
| 2. Sandbox | Shadow mode (log what would have happened) and rollback | Shadow mode works. Rollback not started |
| 3. Verify | Check ground truth through a separate path, never the agent's own "done" | Not started |
| 4. Attest | Tamper-evident, exportable log of every decision | Plain JSONL only, not signed |

## Product rules

- **Structural guardrails first.** Policy enforcement, sandboxing and rollback
  are the product. "The agent double-checks itself" is weak and is not.
- **Not an eval or observability tool.** This runs in the hot path and prevents
  an action. It does not score an agent after the fact.
- **The proxy is a security product.** No `unsafe`, no panics on bad input,
  never log API keys or `Authorization` headers.
- **Fail closed.** Under an enforced policy, anything that cannot be checked is
  blocked: a rule that errors, a tool call with no name, a response or a
  stream that cannot be read.

## Where things are

```
README.md                    public front page: what it is, demo, how to run
Cargo.toml                   crate manifest
src/main.rs                  the proxy: startup, forwarding, refusals
src/policy.rs                policy files: load, validate, decide
src/openai.rs                find tool calls in provider payloads, remove blocked ones,
                             count the run from the conversation history
src/sse.rs                   streamed replies: reassemble them, rebuild them after a block
examples/demo_agent.rs       reckless agents: one drops databases, one gets stuck polling
policy/policy.schema.json    JSON Schema for policy files
policy/example.policy.yaml   example policy, also used by the unit tests
```

## How blocking works

The agent points its SDK at the proxy instead of the provider. Requests are
forwarded unchanged. The model's tool calls come back in the provider's
response, and that is where the proxy acts:

1. Each tool call is matched against the policy rules, top to bottom. The
   first rule that matches decides: `allow`, `deny` or `review`.
2. A blocked call is removed from the response. A note that starts with
   `[razorwire]` is added to the assistant message so the model and the
   operator can see what was stopped and by which rule.
3. Calls that are allowed stay in the response. If none are left, the
   `finish_reason` becomes `stop`.
4. The response carries an `x-razorwire-blocked: <count>` header.

The agent never receives a blocked call, so it has nothing to execute.

`review` blocks exactly like `deny` for now. There is no approval flow yet.

Both the Chat Completions shape (`tool_calls`, legacy `function_call`, custom
tools) and the Responses API shape (`function_call`, `custom_tool_call`) are
handled.

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
count too: those passed on, and those blocked. Each choice of an `n > 1`
reply is counted on its own.

Rules read the counts as `run` (`calls`, `same_tool`, `repeats`, `streak`,
`blocked`). The variable is `run` because CEL reserves the word `loop`. A
blocked call never reaches the agent, so it is not in `calls` and does not
break or extend a streak; it is counted in `blocked`.

## Policy files

Format: `policy/policy.schema.json`. Example: `policy/example.policy.yaml`.

- `match.tool` and `match.agent` take `*` as a wildcard.
- `when` is a CEL expression. `args` is the tool call's decoded arguments,
  `agent` is the value of the `x-agent-name` request header (empty if unset),
  `run` holds the loop guard counts.
- A rule that matches a call but whose `when` cannot be evaluated (for example
  a missing argument) blocks the call. Guard optional fields with
  `has(args.field)`.
- `mode: shadow` logs every decision and blocks nothing.
- The policy is read once at startup. A file that is missing or invalid stops
  the proxy from starting.

## Audit log

One JSON object per line in `audit.jsonl`:

- `tool_call`: a tool call the model asked for, with its `run` counts. With a
  policy loaded it also carries `decision`, `rule`, `blocked`, and `reason`
  when not allowed.
- `tool_result`: a tool result the agent sent back, logged once per call id.
- `response_refused`: the proxy withheld a response it could not check.

## Known limits

- **Streaming is delayed under enforcement.** The reply is held until it is
  complete (up to 32 MB), so the agent loses word-by-word output.
- **Rebuilt streams are minimal.** When a call is blocked, the rebuilt Chat
  Completions stream carries the text and the remaining tool calls; other
  streamed fields such as reasoning are dropped. The rebuilt Responses API
  stream has only the start, item and final events. Both parse in the
  OpenAI Python SDK.
- **One SDK tested.** Verified against Groq with raw HTTP clients and with
  the OpenAI Python SDK 3.53: Chat Completions (plain, streamed, and the
  SDK's stream helper) and the Responses API (plain and streamed). Not yet
  tested with LangGraph or CrewAI.
- **Loop counts trust the conversation.** An agent that trims or rewrites
  its history starts its counts over. With the Responses API's
  `previous_response_id`, only the turns in the request are counted. In
  shadow mode nothing is blocked, so `run.blocked` stays 0.
- **Coverage.** Only OpenAI-compatible payloads are understood. Tools the
  provider runs itself (web search, code interpreter) and the Responses API's
  computer and shell calls are not checked.
- **Agent identity.** `x-agent-name` is whatever the agent claims. It is not
  authenticated.
- **Bypass.** An agent that can reach the provider directly skips the proxy.
  The proxy only protects traffic that goes through it.
- **No reload.** Changing the policy file needs a restart.

## Run it

```
cargo run
```

Environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `UPSTREAM_URL` | `https://api.openai.com` | Provider to forward to. The request path is appended as-is |
| `LISTEN_ADDR` | `127.0.0.1:8080` | Where the proxy listens |
| `AUDIT_LOG` | `audit.jsonl` | File that events are appended to |
| `POLICY_FILE` | unset | Policy to load. Unset means log only, nothing is blocked |

Point an agent at it:

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:8080/v1")  # key still comes from OPENAI_API_KEY
```

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

The agents read `GROQ_API_KEY` from the environment or from `.env`.

## Stack

| Part | Choice |
|---|---|
| Proxy and policy engine | Rust: tokio, axum, reqwest |
| Policy expressions | CEL, via the `cel` crate |
| Policy file parsing | `serde-saphyr` |
| SDKs | Python and TypeScript, thin wrappers over the Rust core |
| Control plane | Next.js on Vercel |
| Storage | Postgres, ClickHouse for traces |
| Billing | Stripe |

## Roadmap

| Weeks | Ship |
|---|---|
| 1-2 | Proxy intercepts and logs tool calls. Done. Repo is private until launch |
| 3-4 | Policy engine: YAML rules that block an action, and the demo. Done |
| 5-6 | Python SDK, LangGraph and CrewAI adapters, docs. Verification for Postgres, Stripe, SendGrid, GitHub, Slack |
| 7 | Rollback. Show HN launch |
| 8 | Hosted control plane and Stripe billing |

Next up, in order: an approval flow for `review`, policy reload without a
restart, testing with LangGraph and CrewAI, an easy install.

## Conventions

- `cargo fmt` and `cargo clippy --all-targets -- -D warnings` before committing.
- Every parser for a provider payload gets a unit test with a real-shaped sample.
- Keep dependencies few. Each new crate needs a reason.
