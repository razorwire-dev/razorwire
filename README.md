# Razorwire

An action firewall for AI agents, written in Rust.

Razorwire is a proxy that sits between an AI agent and its model provider.
Every tool call the model asks for is checked against your rules. A call that
breaks a rule is removed from the response before the agent receives it, so
the agent has nothing to execute.

Status: early. It works for OpenAI-compatible APIs, streamed and
non-streamed. See [Limits](#limits).

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

| Variable | Default | Meaning |
|---|---|---|
| `UPSTREAM_URL` | `https://api.openai.com` | Provider to forward to |
| `LISTEN_ADDR` | `127.0.0.1:8080` | Where the proxy listens |
| `POLICY_FILE` | unset | Policy to load. Unset means log only |
| `AUDIT_LOG` | `audit.jsonl` | Where events are written |

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
  is the tool call's arguments. `agent` is the `x-agent-name` request header.
  `run` holds the [loop guard](#the-loop-guard) counts.
- Actions are `allow`, `deny` and `review`. For now `review` blocks like `deny`.
- Start in `mode: shadow` to see what would be blocked before you enforce it.

The full format is in [policy/policy.schema.json](policy/policy.schema.json).

## It fails closed

When a policy is enforced, anything Razorwire cannot check is blocked:

- a rule whose `when` cannot be evaluated for a call, such as a missing argument
- a tool call with no name
- a provider response that cannot be read
- a policy file that is missing or invalid, which stops the proxy from starting

## The audit log

Every tool call and every decision is appended to `audit.jsonl`, one JSON
object per line. A shortened example:

```json
{"event":"tool_call","tool":"db_drop","arguments":{"database":"production"},"run":{"calls":1,"same_tool":1,"repeats":0,"streak":0,"blocked":0},"decision":"deny","rule":"no-production-db-drop","blocked":true,"agent":"demo-agent"}
```

## Limits

- **Streamed replies are delayed under enforcement.** To check a streamed
  reply, Razorwire holds it until it is complete, so the agent gets it in one
  burst instead of word by word. In shadow mode and with no policy, streams
  pass through live.
- **Tested with one SDK so far.** Verified against Groq with raw HTTP clients
  and with the official OpenAI Python SDK: Chat Completions and the Responses
  API, streamed and not. Not yet tested with LangGraph or CrewAI.
- **Loop counts come from the conversation the agent sends.** An agent that
  trims or rewrites its history starts its counts over. With the Responses
  API's `previous_response_id`, only the turns sent in the request are counted.
- **OpenAI-compatible payloads only.** Chat Completions and the Responses API
  function and custom tool calls. Tools the provider runs itself are not checked.
- **Only traffic through the proxy is protected.** An agent that can reach the
  provider directly bypasses it.
- **The agent name is self-declared.** `x-agent-name` is not authenticated.
- **Policy changes need a restart.**

## Roadmap

An approval flow for `review`, policy reload, live streaming under
enforcement, rollback of executed actions, independent verification of
results, and a signed audit log.

## License

MIT. See [LICENSE](LICENSE).
