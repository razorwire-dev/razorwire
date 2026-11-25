# AGENTS.md

Context for coding agents (Antigravity, Claude Code) working in this repo.

The project is named **Razorwire** (chosen 2026-11-16). The code lives in the
GitHub repo `razorwire-dev/razorwire`, public since 2026-11-19. The name is
taken on PyPI (the Python SDK, 2026-11-18) and crates.io (the proxy,
2026-11-19), not yet on npm. The folder on disk is still called
`agent-firewall`.

## What this is

A runtime that sits between an AI agent and the real world. Every action the
agent tries to take is policy-checked before it runs, executed with a rollback
point, independently verified, and written to a signed audit log.

Open-source core (MIT), paid hosted control plane later.

## The four stages

| Stage | Job | Status |
|---|---|---|
| 1. Policy | Block an action before it executes: scope, limits, blast radius | Working, streamed (live) and non-streamed, with a loop guard, human approval and approve-later |
| 2. Sandbox | Shadow mode (log what would have happened) and rollback | Shadow mode works. Rollback works through an executor, from undo recipes in the policy |
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
.cargo/config.toml           Windows MSVC builds link the C runtime in
src/main.rs                  the command line: serve, new-key, verify-log, approve...
src/proxy.rs                 the proxy: auth, forwarding, policing, waiting on approvals,
                             live streaming with heartbeats
src/admin.rs                 the admin API under /razorwire/, and its command-line client
src/auth.rs                  keys files, key hashing, listing and revoking keys
src/approvals.rs             tool calls held for a human decision, and parked ones
src/audit.rs                 the audit log: HMAC chain, verification, reading it back
src/policy.rs                policy files: load, validate, decide, work out undos
src/openai.rs                find tool calls in provider payloads, plan and apply
                             decisions, count the run from the conversation history
src/sse.rs                   streamed replies: the live gate, reassembly, rebuilding
src/tls.rs                   serving https: certificate loading, handshakes
src/executor.rs              signed requests to the executor
src/alerts.rs                alerts when a call is held: Slack, Discord, ntfy, json;
                             the queue, the rate limit and the sender task
src/rollback.rs              the rollback plan, worked out from the audit log
examples/demo_agent.rs       reckless agents: one drops databases, one gets stuck polling
examples/executor.py         a starting point for an executor, standard library only
sdk/python/                  the Python SDK (`razorwire` on PyPI):
                             agent helpers, block notes, admin client, executor,
                             signature checks, and a proxy runner for tests
policy/policy.schema.json    JSON Schema for policy files
policy/example.policy.yaml   example policy, also used by the unit tests
install.sh, install.ps1      one-command install from a GitHub release
site/                        the public landing page: static HTML, CSS and a
                             little JS, no build step; live at razorwire.vercel.app
docs/demo.svg                the animated demo at the top of the README, made by
                             docs/demo_capture.py (a real run) and docs/demo_render.py
.github/workflows/release.yml  release builds; runs only on a v* tag or by hand
.github/workflows/pypi.yml   publishes the Python SDK to PyPI; runs only by hand
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
5. When calls were removed, a non-streamed response, or one streamed with
   `STREAM_MODE=hold`, carries an `x-razorwire-blocked: <count>` header.
   When nothing was removed there is no header. A live stream never has it,
   because its headers go out before the check.

The agent never receives a blocked call, so it has nothing to execute.

Both the Chat Completions shape (`tool_calls`, legacy `function_call`, custom
tools) and the Responses API shape (`function_call`, `custom_tool_call`) are
handled. `plan` and `apply` walk the response in the same order through one
`visit` function; if they ever disagree, the extra call is blocked.

### Streamed replies

A streamed reply (`"stream": true`) spreads each tool call over many events.

- **Policy enforced, `STREAM_MODE=live` (the default):** `sse::LiveGate`
  passes events on as they arrive while they carry only text: Chat
  Completions deltas with `content`, `refusal` or reasoning text and no
  `finish_reason`, and the Responses API's text, reasoning and content-part
  events. Each field is checked against an allowlist. From the first event
  that is not on it (a tool call, a finish reason, `[DONE]`, an unknown field,
  anything unreadable) everything is held. When the stream ends, the whole
  reply is reassembled and checked by the same code as a plain one. The held
  part is then always rebuilt from the checked reply by `sse::chat_tail` or
  `sse::responses_tail`, carrying on from what was sent (`sse::Sent`), even
  when nothing was blocked. A stream that cannot be checked, is cut off or is
  too large ends with an in-band error event that the OpenAI SDK raises.
  While a held call waits for a human, a comment line goes out every
  5 seconds, so a client that hung up is noticed and its call withdrawn.
- **Policy enforced, `STREAM_MODE=hold`:** the same gate reads the stream,
  but nothing goes out until the end: then the text part, written out again,
  and the rebuilt rest in one burst.
- **No policy, or shadow mode:** the stream passes through live and is read
  on the side, so tool calls and decisions still reach the audit log.

Under enforcement the agent never gets the provider's own bytes, so it
cannot find something in them that the check did not see:

- Lines end at CRLF, LF or a lone CR, as the SSE standard and the OpenAI
  SDK read them (`sse::Lines`). A `: comment\rdata: {...}` line is a
  comment and then a data line, for the check as for the client.
- Every event, the text passed on live included, is written out again from
  what was read (`sse::render`): compact JSON on one `data:` line. Comments
  and events with no data become `:` keep-alives; `id:` and `retry:` are
  dropped. A Responses API event is named by its checked `type`, a chat
  chunk has no name, and any other event keeps the provider's name only if
  it is plain ASCII of up to 256 bytes.
- An error event in a chat stream (`{"error": ...}`, not a chunk) ends the
  reply: it is sent on as the error, without the stream's tool calls
  (`Captured::ProviderError`).
- A non-streamed response is written out again from the parsed JSON, so a
  duplicate key comes out once, with the value that was checked.
  serde_json's `float_roundtrip` feature keeps every number exact.

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
- `razorwire keys` lists role, name and the first 8 hex characters of each
  hash. `razorwire revoke-key <name> [fingerprint]` removes one line,
  rewriting the file in one step. `new-key` and `revoke-key` reload the
  running proxy when `RAZORWIRE_ADMIN_KEY` is set; a failed reload after a
  revoke is an error, since the old key still works.

## TLS

With `TLS_CERT` (PEM chain) and `TLS_KEY` (PEM PKCS#8, RSA on Windows),
`tls::TlsListener` serves https through native-tls, TLS 1.2 or later. Each
handshake runs in its own task with a 10-second limit, at most 256 at once.
The admin client trusts an extra certificate from `RAZORWIRE_CA_CERT`.

## Approvals

When a `review` rule fires under an enforced policy and an admin key exists,
`proxy::police` registers each held call in `approvals::Approvals` (at most
256 at once) and waits up to `APPROVAL_TIMEOUT_SECS` (default 300). The
agent's request stays open. An admin decides through the admin API:

| Endpoint | Does |
|---|---|
| `GET /razorwire/approvals` | List held calls (`pending`) and parked ones (`parked`), oldest first |
| `POST /razorwire/approvals/{id}/approve` | Let a held call through unchanged, or have the executor run a parked one |
| `POST /razorwire/approvals/{id}/deny` | Block it. Optional body `{"reason": "..."}`, cleaned, up to 500 characters |
| `POST /razorwire/reload` | Re-read the policy and keys files |
| `POST /razorwire/rollback` | Body `{"agent", "since_ms" or "since_secs", "ids", "run"}`, at least one filter. Without `"run": true` it only returns the plan |

Every endpoint needs an admin key in `Authorization: Bearer`. A denied call's
note says who denied it and why. An expired call's note says nobody approved
it in time. If the agent hangs up, the held call is withdrawn and
`approval_abandoned` is logged. Admin responses are `no-store` and
`nosniff`, and admin bodies are capped at 16 KB.

### Parked calls (approve later)

With an executor set up, a held call nobody decided in time, or whose agent
hung up, is parked instead of dropped (at most 1024, for 7 days). The
agent's note says it was parked and not to retry. `approval_parked` in the
log carries its full arguments, and at startup `Approvals::restore` rebuilds
the open ones from the log, refusing a log that fails its check. Approving
a parked call takes it out of the store, sends `{"kind": "call", ...}` to
the executor, and logs `parked_call_ran`; if the executor fails, it is put
back and `parked_call_failed` is logged. Denying logs `approval_decided`
with `parked: true`.

## Rollback

`rollback::plan` reads the whole audit log (`Audit::events`, which verifies
a signed log first and refuses a broken one). A call went through when its
`tool_call` was not blocked and not held, when a held one got
`approval_decided` approved (not parked), or when a parked one got
`parked_call_ran`. Its `tool_result` is paired by call id and agent. Steps
come newest first, with an id that is stable: `und_` plus 24 hex of SHA-256
over agent, call id and time. `undo_done` marks a step done, `undo_failed`
keeps its last error.

The policy's `undo` section holds one recipe per tool: optional `when`, and
`call.tool` plus `call.args` as CEL expressions over `args`, `result` and
`agent`. `Policy::undo_for` returns the reversing call or why there is none.
A run takes `rollback_lock`, logs `rollback_started`, then for each step
`undo_started` and `undo_done` or `undo_failed`, stopping at the first
failure, then `rollback_finished`.

## The executor

`executor::Executor` POSTs a JSON job to `EXECUTOR_URL` (https unless on
loopback, no redirects, 60-second limit, answer capped at 16 KB) with
`x-razorwire-timestamp` and `x-razorwire-signature: v1=<hex HMAC-SHA256 of
"<timestamp>.<body>">`, keyed with `EXECUTOR_KEY` (hex, at least 32 bytes;
`razorwire new-executor-key`). Jobs are `{"kind": "undo", "id": "und_...",
"tool", "arguments", "undoes", "requested_by"}` or `{"kind": "call", "id":
"apr_...", "tool", "arguments", "agent", "call_id", "approved_by",
"reason"}`. A retry reuses the id. 2xx means done. `examples/executor.py`
checks the signature and a 5-minute window and never runs an id twice.

## Alerts

`alerts::Target::from_settings` reads `ALERT_URL` (https unless on loopback,
no user name or password, never printed: the banner and errors show only
scheme and host), `ALERT_FORMAT` (`json`, `slack`, `discord`, `ntfy`;
guessed from `hooks.slack.com`, `discord.com/api/webhooks/` and `ntfy.sh`,
otherwise json), `ALERT_EVENTS` (default `held,parked,expired`; `blocked`
or `all` on request), `ALERT_ARGUMENTS` (`show` or `hide`) and `ALERT_KEY`
(json only; refused with the other formats). Any `ALERT_*` setting without
`ALERT_URL`, or an invalid one, stops startup.

`alerts::Alerts::notify` never waits: it puts the alert on a queue of 256
with `try_send`, and a full queue counts it as dropped. One task sends them
in order, at most 20 per minute; at the end of a minute with alerts held
back or dropped, it logs `alerts_dropped` and sends one summary. Each alert
has an `alr_` id that every try reuses. A network error, 429 or 5xx is
tried up to 3 times (2 s, then 5 s, or the receiver's `Retry-After` up to
30 s); after that, or on any other status, `alert_failed` is logged. Errors
are scrubbed of the URL's path and query.

Where they come from: `Approvals::hold` raises `held`, `Approvals::park`
raises `parked` (on a timeout or a hang-up), `Ticket::wait` and the
ticket's `Drop` raise `expired` with `why` `timeout` or `withdrawn` when
nothing is parked, and the clean-up of parked calls raises `expired` with
`why: parked` after 7 days. `proxy::police` raises `blocked` for each
`tool_call` event with `blocked: true`, only when `blocked` is turned on.

Names, commands and arguments are code in Slack and Discord, with
backticks swapped for `ˋ`; Slack escapes `& < >` everywhere, Discord
escapes markdown in prose and sends `allowed_mentions: {"parse": []}` and
`flags: 4`. Control, direction and zero-width characters become spaces.
Arguments are cut to 2,500 bytes (1,000 for Discord, which caps messages
at 2,000 characters). ntfy gets plain text with `title` and `priority`
headers. json gets `{"id", "kind", "title", "text", "created_ms",
"approval_id", "agent", "tool", "rule", "message", "arguments",
"until_ms", "why" or "count"}`, signed with `ALERT_KEY` like an executor
request. `razorwire test-alert` sends one now and reports the receiver's
answer.

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
- `tool_result`: a tool result the agent sent back, with its `agent`,
  logged once per agent and call id.
- `approval_requested`, `approval_decided` (`approved`, `denied`, `expired`
  or `parked`, with `by` and `reason`; `parked: true` when it decides a
  parked call), `approval_abandoned`.
- `approval_parked` (with the full arguments), `parked_call_ran` (with the
  executor's `output`), `parked_call_failed`.
- `rollback_started`, `undo_started`, `undo_done`, `undo_failed`,
  `rollback_finished`.
- `auth_failed` (never with the key), and `auth_failures_suppressed` when
  more than 20 a minute were not logged.
- `alert_failed` (with `alert_id`, `kind`, `approval_id` and `reason`,
  never the URL), and `alerts_dropped` with a `count`.
- `proxy_started`, `config_reloaded`, `reload_failed`, `response_refused`.

With `AUDIT_KEY` (hex, at least 32 bytes; `razorwire new-audit-key`), each
line ends with `,"seq":<n>,"mac":"<hex>"}`. The MAC is HMAC-SHA256 over the
previous line's MAC, the seq and the rest of the line, so lines vouch for
each other. On restart the chain continues from the file's last line.
`razorwire verify-log` reports the first broken line. DEL, C1 controls and
Unicode direction marks are escaped as `\uXXXX` in every line.

## Known limits

- **Streamed tool calls wait.** Under enforcement, text streams live, but
  from the first tool call the rest is held until the reply is complete (up
  to 32 MB). A live stream has no `x-razorwire-blocked` header.
- **Rebuilt streams are minimal.** Under enforcement, everything after the
  first held event is rebuilt from the checked reply, blocked or not. In a
  Chat Completions stream that part carries the text, the remaining tool
  calls, the finish reason and usage; other fields in it, such as reasoning
  or logprobs, are dropped. In a Responses API stream it has only item and
  final events. Both parse
  in the OpenAI Python SDK.
- **Clients tested.** Groq with raw HTTP clients, the OpenAI Python SDK 3.53
  (Chat Completions plain, streamed and the stream helper; the Responses API
  plain and streamed), LangGraph 1.2 through langchain-openai 1.8, and
  CrewAI 1.15 with its native OpenAI client (plain and streamed for both).
  A CrewAI agent whose only call was blocked takes the note as its final
  answer.
- **Loop counts trust the conversation.** An agent that trims or rewrites
  its history starts its counts over. With the Responses API's
  `previous_response_id`, only the turns in the request are counted. In
  shadow mode nothing is blocked, so `run.blocked` stays 0.
- **Coverage.** Only OpenAI-compatible payloads are understood. Tools the
  provider runs itself (web search, code interpreter) and the Responses API's
  computer and shell calls are not checked.
- **Approvals hold the whole response.** Waiting calls live in memory; a
  restart drops them and the waiting request fails. Parked calls survive.
- **Rollback trusts reported results.** An undo built from `result` uses
  what the agent said the tool returned. Rollback and restore read the
  whole log into memory (refused above 1 GB).
- **TLS is server-only.** No client certificates. native-tls on Windows
  takes RSA keys only.
- **Log truncation.** Lines cut off the end of the audit log cannot be
  detected from the file. Someone with `AUDIT_KEY` can forge the log.
- **Bypass.** An agent that can reach the provider directly skips the proxy.
  `UPSTREAM_API_KEY` takes away the key; the network must take away the route.
- **Alerts are best effort.** One that fails 3 times is logged, not sent
  later; over 20 a minute are only counted. Slack, Discord and ntfy alerts
  are unsigned, and once sent they live at the third party.

## The Python SDK

`sdk/python` is the `razorwire` package (`src/razorwire/`): standard library
only, Python 3.9 or later. `openai` is imported only inside
`openai_client()` and `async_openai_client()`.

| Module | Does |
|---|---|
| `agent.py` | `openai_client()`, `async_openai_client()`, `base_url()`: an OpenAI client pointed at the proxy, with `RAZORWIRE_AGENT_KEY`. Plain http to another machine is refused unless `allow_plain_http` |
| `notes.py` | `blocked()` reads block notes from a reply, message, list or text; `blocked_count()` reads `x-razorwire-blocked` |
| `admin.py` | `Admin`: the admin API, with the same rules as `admin::Client`: https unless loopback, no redirects, no proxy for plain http, ids of `[A-Za-z0-9_]` only |
| `signing.py` | `sign()` and `verify()`: the executor and json alert signature |
| `executor.py` | `Executor`: checks signature and age, runs a job id once (409 while it runs), remembers ids across restarts with `log=` |
| `proxy.py` | `Proxy`: runs the binary on a free loopback port in a temporary folder, with an admin key, for tests |

The SDK copies formats from the proxy. When one of these changes, change
the SDK and its tests with it: the note from `openai::block_note`, the
outcome wording in `proxy::police` (denied, expired, parked), the admin
API's answers, and the signature in `executor::signature`.

Tests: `pip install -e "./sdk/python[test]"`, then `pytest` in `sdk/python`.
The end-to-end tests run the real binary (`RAZORWIRE_BIN`, else
`target/debug`, else `PATH`; skipped without one) against a fake provider in
`tests/conftest.py`, with `tests/policy.yaml`. Lint with
`ruff check --target-version py39 --line-length 120` and
`mypy --strict src`.

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
| `TLS_CERT`, `TLS_KEY` | unset | Both or neither: serve https |
| `STREAM_MODE` | `live` | `live` or `hold`, for streamed replies under enforcement |
| `EXECUTOR_URL`, `EXECUTOR_KEY` | unset | Both or neither: rollback and parked calls |
| `ALERT_URL` | unset | Where alerts go. Never printed in full |
| `ALERT_FORMAT` | from the host | `json`, `slack`, `discord` or `ntfy` |
| `ALERT_EVENTS` | `held,parked,expired` | Add `blocked`, or `all` |
| `ALERT_ARGUMENTS` | `show` | `hide` keeps arguments out of alerts |
| `ALERT_KEY` | unset | Hex, at least 32 bytes: signs json alerts |

Commands: `razorwire [serve]`, `new-key <agent|admin> <name>`, `keys`,
`revoke-key <name> [fingerprint]`, `new-audit-key`, `new-executor-key`,
`new-alert-key`, `check-policy <file>`, `verify-log [file]`, `approvals`,
`approve <id> [reason]`, `deny <id> [reason]`, `reload`,
`rollback [--agent <name>] [--since 30m|2h|1d] [<undo id>...] [--run]`,
`test-alert`, `help`. The admin commands use `RAZORWIRE_URL` (default
`http://127.0.0.1:8080`, https required for anything not on loopback),
`RAZORWIRE_ADMIN_KEY`, and `RAZORWIRE_CA_CERT` for a self-signed certificate.

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
| https | `tokio-native-tls` (schannel on Windows, OpenSSL on Linux, vendored in the release build) |
| Releases | GitHub Actions on a `v*` tag: musl Linux, macOS (Apple silicon and Intel), Windows |
| SDKs | Python (`sdk/python`, standard library only); TypeScript later |
| Control plane | Next.js on Vercel |
| Storage | Postgres, ClickHouse for traces |
| Billing | Stripe |

## Roadmap

| Weeks | Ship |
|---|---|
| 1-2 | Proxy intercepts and logs tool calls. Done. Repo public since 2026-11-19 |
| 3-4 | Policy engine: YAML rules that block an action, and the demo. Done. Loop guard, approvals, keys, signed log and reload: done |
| 5-6 | Release builds and install scripts, live streaming under enforcement, https, approve later, alerts when a call is held, the Python SDK. Done; v0.1.0 released (v0.1.1 fixes the Windows build), the SDK is on PyPI and the proxy on crates.io. LangGraph and CrewAI adapters, docs. Verification for Postgres, Stripe, SendGrid, GitHub, Slack |
| 7 | Rollback through an executor: done. Show HN launch |
| 8 | Hosted control plane and Stripe billing |

Next up, in order: launch (Show HN, then Product Hunt on another day; the
site, demo clip, public repository and install scripts are done and
checked), then verification (stage 3), public-key signatures and export
for the audit log (stage 4).

## Releases

`.github/workflows/release.yml` runs on a pushed `v*` tag, or by hand. It
checks the tag against the version in `Cargo.toml`, makes a draft release,
builds and tests on each platform, uploads `razorwire-<target>.tar.gz` (or
`.zip` on Windows) and finally `SHA256SUMS`. The Linux build is static musl
with OpenSSL vendored (`--features vendored-openssl`). Publishing the draft
is done by hand. `install.sh` and `install.ps1` download the latest release
(or `RAZORWIRE_VERSION`), check it against `SHA256SUMS`, and need
`GITHUB_TOKEN` only for a private copy of the repository. v0.1.0 was
released on 2026-11-18. To publish a draft by hand, open it from the
releases list: `/releases/edit/<tag>` does not open a draft, it starts a new
release.

v0.1.1 (2026-11-20) only changes the Windows build: `.cargo/config.toml`
links the C runtime in (`+crt-static`), because v0.1.0's `razorwire.exe`
needed `vcruntime140.dll`, which a fresh Windows install may lack. After a
Windows release, check the archive's binary no longer names that DLL.

The proxy is also on crates.io (`cargo install razorwire`). It still has
0.1.0, the same code as 0.1.1; publishing 0.1.1 there would only refresh
the README shown on crates.io. v0.1.0 was
published by hand with `cargo publish` and a 7-day token limited to the
`razorwire` crate, then `cargo logout`. `include` in `Cargo.toml` limits
the package to `src`, `examples`, `policy` and the documents; check
`cargo package --list` before a publish. A version published there can be
yanked but never removed. For later versions, crates.io's trusted
publishing from GitHub Actions avoids tokens.

A pushed tag runs the workflow file saved in that tag's commit, not the one
on `main`. Pushing a tag whose release is already published stops before
building (from v0.1.1 on; v0.1.0's own copy predates this check). Only a run
started by hand rebuilds a published release, and it replaces every archive
and `SHA256SUMS` together.

`.github/workflows/pypi.yml` publishes `sdk/python` to PyPI when started by
hand. It checks that `pyproject.toml` and `_version.py` agree, runs the unit
tests, builds, and uploads with PyPI's trusted publishing (publisher set up
on pypi.org for this repository, `pypi.yml`, environment `pypi`), so no
PyPI token exists. Raise the version first: PyPI never takes one twice.

## The public site

`site/index.html`, `site/styles.css`, `site/main.js` and `site/favicon.svg`
make the landing page. There is no build step and no third-party script; a
Content-Security-Policy meta tag allows only the site's own files and Google
Fonts. The page works without JavaScript (tabs show every panel, copy
buttons stay hidden). Light and dark follow the system. The terminal
outputs on it come from real runs, so keep them and every claim true when
behaviour changes. Links go to the public GitHub repository. To preview:
`python -m http.server 8110 --directory site`.

The site is live at https://razorwire.vercel.app, the Vercel project
`razorwire`. `site/vercel.json` adds security headers, including the same
CSP plus `frame-ancestors 'none'`. Vercel's GitHub app cannot see the
private repository, so the site is deployed by uploading the files in
`site/` directly; nothing redeploys it on a push. After an upload, compare
the live files with the ones on disk.

`docs/demo.svg` is the README's animated demo: the real output of the
database demo without and with the example policy, slowed to reading
speed. When the demo's output changes, run `docs/demo_capture.py` (it
runs the real proxy and agent against Groq) and then `docs/demo_render.py`.

The dashboard (the paid control plane) is separate and not started. The
plan is for Lovable to design its screens only, in its own private repo,
with logins, data access, the API and the proxy's link to it written here.

## Conventions

- `cargo fmt` and `cargo clippy --all-targets -- -D warnings` before committing.
- Every parser for a provider payload gets a unit test with a real-shaped sample.
- Keep dependencies few. Each new crate needs a reason.
