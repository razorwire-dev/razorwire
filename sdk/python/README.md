# Razorwire for Python

[Razorwire](https://github.com/razorwire-dev/razorwire) is an action firewall
for AI agents. It sits between an agent and its model provider and checks
every tool call against a policy before the agent can run it: allowed,
blocked, or held for a person to approve.

This package is the Python side of it. It needs only the standard library,
and works on Python 3.9 and later.

```
pip install razorwire
```

From a checkout of the repository: `pip install ./sdk/python`. The proxy
itself is a separate binary; see the main README to install it.

| You are writing | Use |
|---|---|
| An agent | `openai_client()`, `base_url()`, `blocked()` |
| An approval bot or dashboard | `Admin` |
| The service that carries out rollbacks and approved parked calls | `Executor` |
| Something that receives Razorwire's JSON alerts | `verify()` |
| Tests for your policy and your agent | `Proxy` |

## Point an agent at Razorwire

```python
import razorwire

client = razorwire.openai_client()   # an openai.OpenAI (pip install openai)
```

It talks to `RAZORWIRE_URL` (default `http://127.0.0.1:8080`) with the
agent's key from `RAZORWIRE_AGENT_KEY`. Other frameworks take the base URL:

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4.1", base_url=razorwire.base_url(),
                 api_key=os.environ["RAZORWIRE_AGENT_KEY"])
```

A key is never sent over plain http to another machine; pass
`allow_plain_http=True` for a private network you trust.

## See what was blocked

A blocked call never reaches the agent. In its place, the assistant's text
gets a note saying which call was stopped and by which rule. `blocked()`
reads those notes:

```python
reply = client.chat.completions.create(model=..., messages=..., tools=...)

for block in razorwire.blocked(reply):
    print(block.tool, block.rule, block.outcome, block.message)
    # db_drop no-production-db-drop blocked Dropping the production database is blocked by policy.
```

`outcome` is `blocked`, or for a call held for a person, `denied` (with
`by`), `expired`, or `parked`. A parked call may still be approved and
carried out later, so the agent must not retry it.

It takes a Chat Completions reply, a Responses API reply, a message, a
list of messages, or text gathered from a stream.

The notes are in the model's own text, so a model could write a fake one.
Use them to steer the agent, not as proof. The `x-razorwire-blocked`
header comes from the proxy alone, which drops any such header from the
provider; read it with `blocked_count()` on a raw response:

```python
raw = client.chat.completions.with_raw_response.create(...)
razorwire.blocked_count(raw)   # 1, or None when nothing was removed
```

## Approve held calls from Python

```python
from razorwire import Admin

admin = Admin()   # RAZORWIRE_URL and RAZORWIRE_ADMIN_KEY

for call in admin.approvals().pending:
    print(call.id, call.agent, call.tool, call.arguments, call.message)

admin.approve(call, reason="checked the order")
admin.deny(call, reason="wrong customer")      # the reason is shown to the agent

held = admin.wait_for_held(tool="stripe_refund", timeout=60)
plan = admin.rollback(agent="support-bot", since="2h")          # what would be undone
done = admin.rollback(agent="support-bot", since="2h", run=True)
admin.reload()                                                  # re-read policy and keys
```

Refusals raise `RazorwireError`, with `status` and Razorwire's `code`
(`not_pending`, `no_executor`, `wrong_key_role`, ...). The admin key goes
only over https, or plain http to this machine, and redirects are never
followed, so the key cannot be sent anywhere else. `RAZORWIRE_CA_CERT`
trusts a self-signed certificate.

## Build an executor

Razorwire never touches your systems itself. To roll back what an agent
did, or to carry out a parked call approved after its agent stopped
waiting, it sends a signed job to your executor:

```python
from razorwire import Executor

executor = Executor(log="executor.jsonl")    # the key from EXECUTOR_KEY

@executor.action("close_ticket")
def close_ticket(job):
    tickets.close(job.arguments["id"])
    return {"closed": job.arguments["id"]}

@executor.action("stripe_refund")
def refund(job):
    stripe.Refund.create(charge=job.arguments["charge"], amount=job.arguments["amount"])
    return {"refunded": job.arguments["amount"]}

executor.serve(port=9100)
```

Start Razorwire with `EXECUTOR_URL=http://127.0.0.1:9100` and the same
`EXECUTOR_KEY` (`razorwire new-executor-key`). The executor checks every
job's signature and age, runs a job id at most once, and answers a retry
with the first result; with `log=`, that holds across restarts too. A job
that raises is reported as failed and can be tried again.

`job.kind` is `undo` or `call`, `job.by` is the admin who asked, and
`job.undoes` holds the call an undo reverses. To serve it from your own web
framework, pass the raw body and headers to `executor.handle()` and send
back the status and JSON it returns.

Keep the executor where agents cannot reach it: it holds the real
credentials.

## Check a signed alert

With `ALERT_KEY` set, Razorwire signs its JSON alerts:

```python
from razorwire import verify, SignatureError

try:
    verify(os.environ["ALERT_KEY"], raw_body, request.headers)
except SignatureError:
    return 401
```

Pass the body exactly as received, before parsing it.

## Test your policy

`Proxy` runs the real binary with your policy in a fresh folder, on a free
port, for as long as a test needs it:

```python
from razorwire import Proxy, blocked

def test_production_is_safe():
    with Proxy(policy="policy.yaml", upstream="https://api.groq.com/openai",
               upstream_key=os.environ["GROQ_API_KEY"]) as proxy:
        client = proxy.openai_client(agent="ops-bot")
        reply = client.chat.completions.create(model=..., messages=..., tools=...)
        assert [b.rule for b in blocked(reply)] == ["no-production-db-drop"]
        assert any(e.get("blocked") for e in proxy.audit())
```

It finds the binary from `binary=`, `RAZORWIRE_BIN` or `PATH`, ignores
Razorwire settings in your environment, makes an admin key (`proxy.admin`)
and agent keys for the names in `agents=`, and signs its audit log.

## Settings

| Variable | Used by | Meaning |
|---|---|---|
| `RAZORWIRE_URL` | agents, `Admin` | The proxy. Default `http://127.0.0.1:8080` |
| `RAZORWIRE_AGENT_KEY` | `openai_client()` | The agent's `rw_` key |
| `RAZORWIRE_ADMIN_KEY` | `Admin` | An admin's `rw_` key |
| `RAZORWIRE_CA_CERT` | `Admin` | A PEM certificate to trust as well |
| `EXECUTOR_KEY` | `Executor` | Hex key shared with the proxy |
| `RAZORWIRE_BIN` | `Proxy` | The razorwire binary |

MIT licensed.
