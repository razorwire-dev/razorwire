# Razorwire

An action firewall for AI agents, written in Rust.

Razorwire is a proxy that sits between an AI agent and its model provider.
Every tool call the model asks for is checked against your rules. A call that
breaks a rule is removed from the response before the agent receives it, so
the agent has nothing to execute. A risky call can be held until a human
approves it. Every decision goes into an audit log that can be signed, so
tampering shows.

Status: early. It works for OpenAI-compatible APIs, streamed and
non-streamed. See [Limits](#limits) and [SECURITY.md](SECURITY.md).

## The demo

An agent with a `db_drop` tool is told to delete two databases. It runs
whatever tool calls come back, with no checks of its own.

Without a policy:

```
OPERATOR  We are out of disk space. Drop the staging database and the production database.
AGENT     calls db_drop("staging")
DATABASE  staging has been DELETED
AGENT     calls db_drop("production")
DATABASE  production has been DELETED

RESULT    production: DELETED
RESULT    staging: DELETED
```

With this rule loaded:

```yaml
- id: no-production-db-drop
  match:
    tool: db_drop
  when: args.database == "production"
  action: deny
  message: Dropping the production database is blocked by policy.
```

```
OPERATOR  We are out of disk space. Drop the staging database and the production database.
AGENT     calls db_drop("staging")
DATABASE  staging has been DELETED
AGENT     [razorwire] Blocked tool call "db_drop": Dropping the production database is blocked by policy. (rule: no-production-db-drop)

RESULT    production: still there
RESULT    staging: DELETED
```

The model still asked for it. The agent never got the chance to do it.

## The loop guard

An agent runs in a loop: ask the model, run the tool it picks, send back the
result, repeat. Nothing in that loop knows when to stop. An agent can call
the same tool forever, or keep pushing against a rule it was told about, and
every turn costs money.

Razorwire puts brakes on the loop. Every request from an agent carries the
whole conversation so far, so Razorwire can count what already happened in
the run without keeping any state of its own. Rules read those counts as
`run`:

| Count | Meaning |
|---|---|
| `run.calls` | Tool calls the agent received earlier in this run |
| `run.same_tool` | Of those, calls to the same tool |
| `run.repeats` | Of those, calls with the same arguments |
| `run.streak` | Times in a row, just before this one, the agent made exactly this call |
| `run.blocked` | Calls Razorwire blocked earlier in this run |

The example policy ships three brakes:

```yaml
- id: three-strikes         # after three blocked calls, block everything
  match: { tool: "*" }
  when: run.blocked >= 3
  action: deny

- id: run-budget            # a hard cap on one run
  match: { tool: "*" }
  when: run.calls >= 50
  action: deny

- id: stuck-in-a-loop       # the same call three times in a row
  match: { tool: "*" }
  when: run.streak >= 2
  action: deny
```

A demo agent is told to wait for a deploy that never finishes. Without a
policy it never stops:

```
OPERATOR  Deploy 42 is rolling out. Check its status until it has finished, then tell me.
AGENT     calls deploy_status(42)
DEPLOY    42 is still pending
AGENT     calls deploy_status(42)
DEPLOY    42 is still pending
          ... ten more times ...

RESULT    deploy_status was called 12 times
RESULT    the agent was still going when the demo cut it off after 12 turns
```

With the loop guard:

```
OPERATOR  Deploy 42 is rolling out. Check its status until it has finished, then tell me.
AGENT     calls deploy_status(42)
DEPLOY    42 is still pending
AGENT     calls deploy_status(42)
DEPLOY    42 is still pending
AGENT     [razorwire] Blocked tool call "deploy_status": This exact call was just made twice in a row, so the agent looks stuck. Stop and report back instead of retrying. (rule: stuck-in-a-loop)

RESULT    deploy_status was called 2 times
RESULT    the agent stopped
```

A tool that is meant to be polled can be let through for longer. Rules run
top to bottom and the first match decides, so put an allow rule just above
`stuck-in-a-loop`:

```yaml
- id: deploys-can-be-polled
  match: { tool: deploy_status }
  when: run.streak < 20
  action: allow
```

## Human approval

A rule with `action: review` holds a tool call until a person decides. The
agent waits; nothing reaches it until then.

```yaml
- id: refund-cap
  match: { tool: stripe_refund }
  when: args.amount > 500
  action: review
  message: Refunds above 500 are held for human approval.
```

From a live run against Groq, where a real model asked for a $750 refund:

```
$ razorwire approvals
1 tool call is waiting for approval:

  apr_b79940b196c10054ebcf413132bc8f62  stripe_refund  agent: support-bot  rule: refund-cap  1m 59s left
      arguments: {"amount":750,"order":"A-17"}
      why held:  Refunds above 500 are held for human approval.

$ razorwire approve apr_b79940b196c10054ebcf413132bc8f62 checked with the customer
Approved apr_b79940b196c10054ebcf413132bc8f62: stripe_refund for agent support-bot.
```

An approved call goes to the agent unchanged. A denied one is removed, and
the agent is told who said no and why:

```
[razorwire] Blocked tool call "stripe_refund": Refunds above 500 are held for human approval. Denied by mann: already refunded last week. (rule: refund-cap)
```

If nobody decides within `APPROVAL_TIMEOUT_SECS` (default 300), or the
agent hangs up, the call is blocked. Approving needs an admin key, and an
agent's key can never approve, so an agent cannot wave its own calls
through. With no admin key set up, `review` blocks at once.

## Run it

You need [Rust](https://rustup.rs) and an API key for an OpenAI-compatible
provider. The demo uses Groq; put `GROQ_API_KEY=...` in a `.env` file.

Start the proxy with the example policy.

macOS and Linux:

```
UPSTREAM_URL=https://api.groq.com/openai POLICY_FILE=policy/example.policy.yaml cargo run
```

Windows PowerShell:

```
$env:UPSTREAM_URL="https://api.groq.com/openai"; $env:POLICY_FILE="policy/example.policy.yaml"; cargo run
```

In a second terminal, run the agent that drops databases, or the one that
gets stuck in a loop:

```
cargo run --example demo_agent
cargo run --example demo_agent -- loop
```

## Use it with your own agent

Point your SDK's base URL at the proxy. Nothing else changes.

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8080/v1")
```

It works the same from LangChain and LangGraph:

```python
from langchain_openai import ChatOpenAI

model = ChatOpenAI(model="openai/gpt-oss-120b", base_url="http://127.0.0.1:8080/v1")
```

| Variable | Default | Meaning |
|---|---|---|
| `UPSTREAM_URL` | `https://api.openai.com` | Provider to forward to. Must be https unless it is on this machine |
| `UPSTREAM_API_KEY` | unset | Provider key the proxy sends, so agents never hold it |
| `LISTEN_ADDR` | `127.0.0.1:8080` | Where the proxy listens |
| `POLICY_FILE` | unset | Policy to load. Unset means log only |
| `KEYS_FILE` | unset | Agent and admin keys. See [Lock it down](#lock-it-down) |
| `AUDIT_LOG` | `audit.jsonl` | Where events are written |
| `AUDIT_KEY` | unset | Signs the audit log so tampering shows |
| `APPROVAL_TIMEOUT_SECS` | `300` | How long a held call waits for a human, 1 to 3600 |

## Lock it down

Out of the box Razorwire trusts any program on the same machine. Before
other people or other machines can reach it, give every agent a key, keep
the provider key inside the proxy, and sign the log.

Install the `razorwire` command with `cargo install --path .`, or use
`cargo run --release --` in its place.

1. Create the keys. Each is shown once; the keys file keeps only its hash.

   ```
   razorwire new-key agent support-bot
   razorwire new-key admin mann
   razorwire new-audit-key
   ```

2. Start the proxy with them. The provider key goes to the proxy only.

   ```
   UPSTREAM_URL=https://api.groq.com/openai UPSTREAM_API_KEY=gsk_... \
   POLICY_FILE=policy/example.policy.yaml KEYS_FILE=razorwire.keys AUDIT_KEY=<audit key> \
   cargo run --release
   ```

3. Give each agent its own key as its API key. It cannot reach the
   provider with it, only Razorwire.

   ```python
   client = OpenAI(base_url="http://127.0.0.1:8080/v1", api_key="rw_...")
   ```

4. Approve and reload from your own terminal with the admin key.

   ```
   RAZORWIRE_ADMIN_KEY=rw_... razorwire approvals
   ```

With agent keys set up, a request without a valid key is refused with 401,
and the agent's name in rules and in the log comes from its key, not from
anything the agent says. Razorwire refuses to listen on a network address
unless agent keys are set up. It speaks plain HTTP, so put a TLS proxy such
as Caddy in front before keys cross a network. [SECURITY.md](SECURITY.md)
lists what this protects against and what it does not.

## Commands

```
razorwire                        start the proxy
razorwire new-key <agent|admin> <name>
razorwire new-audit-key
razorwire check-policy <file>
razorwire verify-log [file]
razorwire approvals
razorwire approve <id> [reason]
razorwire deny <id> [reason]
razorwire reload                 re-read the policy and keys files without a restart
```

The admin commands talk to `RAZORWIRE_URL` (default
`http://127.0.0.1:8080`) with `RAZORWIRE_ADMIN_KEY`. A reload that finds an
invalid file changes nothing and keeps the last good configuration.

## Policies

A policy is a YAML file. Rules run top to bottom and the first match decides.

```yaml
version: 1
mode: enforce      # or shadow: log decisions, block nothing
default: allow     # what happens when no rule matches

rules:
  - id: refund-cap
    match:
      tool: stripe_refund
    when: args.amount > 500
    action: review
    message: Refunds above 500 are held for human approval.

  - id: email-allowlist
    match:
      tool: "email_*"
    when: '!args.to.all(r, r.endsWith("@example.com"))'
    action: deny
    message: At least one recipient is outside the allowed domain.
```

- `match.tool` and `match.agent` accept `*` as a wildcard.
- `when` is a [CEL](https://github.com/cel-expr/cel-spec) expression. `args`
  is the tool call's arguments. `agent` is the agent's name: the name of its
  key, or the `x-agent-name` request header when no agent keys are set up.
  `run` holds the [loop guard](#the-loop-guard) counts.
- Actions are `allow`, `deny` and `review`. `review` holds the call for
  [human approval](#human-approval).
- Start in `mode: shadow` to see what would be blocked before you enforce it.
- Check a policy without starting the proxy: `razorwire check-policy <file>`.

The full format is in [policy/policy.schema.json](policy/policy.schema.json).

## It fails closed

When a policy is enforced, anything Razorwire cannot check is blocked:

- a rule whose `when` cannot be evaluated for a call, such as a missing argument
- a tool call with no name
- a provider response that cannot be read
- a held call nobody approved in time
- a policy, keys or audit setting that is missing or invalid, which stops the
  proxy from starting

## The audit log

Every tool call and every decision is appended to `audit.jsonl`, one JSON
object per line. A shortened example:

```json
{"event":"tool_call","tool":"db_drop","arguments":{"database":"production"},"run":{"calls":1,"same_tool":1,"repeats":0,"streak":0,"blocked":0},"decision":"deny","rule":"no-production-db-drop","blocked":true,"agent":"demo-agent"}
```

Approvals, refused keys, reloads and startups are logged too. With
`AUDIT_KEY` set, each line ends with a sequence number and an HMAC that
covers the line before it, so a line that is edited, added, removed or moved
breaks the chain:

```
$ razorwire verify-log audit.jsonl
razorwire: audit.jsonl FAILED at line 4: the MAC does not match: seq jumps from 2 to 4, so lines are missing or out of order. The 3 signed lines before it are intact.
```

Text from the model is escaped in the log, so a tool argument cannot hide
terminal control codes. Keys are never logged.

## Limits

- **Streamed replies are delayed under enforcement.** To check a streamed
  reply, Razorwire holds it until it is complete, so the agent gets it in one
  burst instead of word by word. In shadow mode and with no policy, streams
  pass through live.
- **Tested with a few clients so far.** Verified against Groq with raw HTTP
  clients, the official OpenAI Python SDK (Chat Completions and the Responses
  API, streamed and not) and LangGraph through `langchain-openai` (plain and
  streamed). Not yet tested with CrewAI.
- **Loop counts come from the conversation the agent sends.** An agent that
  trims or rewrites its history starts its counts over. With the Responses
  API's `previous_response_id`, only the turns sent in the request are counted.
- **OpenAI-compatible payloads only.** Chat Completions and the Responses API
  function and custom tool calls. Tools the provider runs itself are not checked.
- **Only traffic through the proxy is protected.** An agent that can reach the
  provider directly bypasses it. Keeping the provider key in
  `UPSTREAM_API_KEY` means the agent has no key to do that with.
- **Without agent keys, the agent name is self-declared.** `x-agent-name` is
  taken at its word until you [set up keys](#lock-it-down).
- **Approvals hold the whole response.** Other calls in the same response
  wait with the held one. Pending approvals live in memory, so a restart
  drops them, and the agent's request fails.
- **No TLS of its own.** Put a TLS proxy in front for anything beyond this
  machine.
- **The log cannot show lines cut off its end.** Keep a copy elsewhere if
  that matters. See [SECURITY.md](SECURITY.md).

## Roadmap

Live streaming under enforcement, rollback of executed actions, independent
verification of results, an approvals dashboard, and an easier install.

## License

MIT. See [LICENSE](LICENSE).
