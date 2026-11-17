# Security

Razorwire is a security product, so this file says plainly what it protects
against, how, and where its protection stops. No software is unbreakable.
The aim is to close the known ways in, to block whatever cannot be checked,
and to make tampering visible.

## What it protects against

| Threat | What Razorwire does |
|---|---|
| A tricked or buggy agent runs a dangerous tool call | The policy removes the call from the model's response before the agent sees it. Anything that cannot be checked is blocked. |
| An agent approves its own held call | Approving needs an admin key. Agent keys are refused on the admin API, and admin keys are refused on the proxy path, so the two roles never mix. |
| A stranger on the network uses the proxy | Razorwire will not start on an address other machines can reach unless agent keys are set up. Every request then needs a valid key. |
| An agent claims to be a different agent to get looser rules | With agent keys, the name comes from the key. The `x-agent-name` header is ignored and never forwarded. |
| An agent goes around the proxy straight to the provider | With `UPSTREAM_API_KEY`, the proxy holds the provider key and the agent never has one. The agent's own `Authorization` header is replaced. |
| Keys leak | The keys file stores SHA-256 hashes only. Keys are never written to the log or the console. The provider key is marked sensitive and never printed. Razorwire keys are stripped before a request is forwarded. |
| The provider, or something between it and the proxy, fakes Razorwire's answers | Headers starting with `x-razorwire-` from the provider are dropped. Redirects are passed back to the agent, never followed, so the provider key cannot be sent on to another host. The provider must be reached over https unless it runs on this machine. |
| Someone edits the audit log to hide what happened | With `AUDIT_KEY`, every line carries an HMAC that also covers the line before it. `razorwire verify-log` finds the first line that was edited, added, removed or moved. |
| Text from the model tries to trick the operator's terminal | Control characters and Unicode direction marks are escaped in log lines and in `razorwire approvals`. Reasons typed by an approver are cleaned the same way. |
| A flood of requests | Request bodies are capped at 32 MB (16 KB on the admin API). At most 512 requests run at once; more get 503. At most 256 calls wait for approval at once. Failed key checks are logged at most 20 times a minute. A provider that goes silent for 10 minutes is given up on. |
| The admin key crosses a network in the clear | The admin commands refuse a plain-http `RAZORWIRE_URL` unless it points at this machine. |
| A bad config silently turns protection off | A policy, keys file or audit key that is missing or invalid stops the proxy from starting. A reload that finds an invalid file changes nothing. |

## What it does not protect against

- **Anyone who can read the proxy's environment, memory or files.** They
  have the provider key and the audit key. Run Razorwire as its own
  operating-system user, and make sure the agent cannot read that user's
  files or environment.
- **Someone who holds `AUDIT_KEY`.** They can rewrite the log so that it
  still verifies. Keep the key away from the machine the agent runs on if you
  can, and copy the log somewhere the agent cannot reach.
- **Lines cut off the end of the log.** The file alone cannot show that its
  last lines were removed. Compare the last `seq` with a copy kept elsewhere.
- **Plain HTTP.** Razorwire has no TLS of its own. Anything beyond this
  machine needs a TLS proxy in front, such as Caddy or nginx, or keys and
  prompts can be read on the wire.
- **Tool calls that never pass through it.** Tools the agent runs without
  asking the model, tools the provider runs itself (web search, code
  interpreter), and the Responses API's computer and shell calls are not
  checked.
- **An agent that can still reach the provider.** Holding the provider key
  stops an agent from using it, but the network should also stop the agent's
  machine from reaching the provider at all.
- **A wrong policy, or a wrong approval.** Razorwire does what the policy and
  the approver say. Start a new policy in `mode: shadow` and read the log.
- **Network-level denial of service.** Slow or half-open connections are a
  job for the reverse proxy in front.

## A safe setup

1. Give every agent its own key: `razorwire new-key agent <name>`. Give admin
   keys to people only.
2. Set `UPSTREAM_API_KEY`, and give agents no provider key.
3. Set `AUDIT_KEY` from `razorwire new-audit-key`, and copy the log off the
   machine regularly.
4. Run the proxy as its own user. The agent must not be able to read or
   write the keys file, the policy, the audit log or the proxy's environment.
5. Listen on `127.0.0.1`, or put TLS in front.
6. Block the agent's direct network access to the provider.
7. To rotate a key: create the new one, `razorwire reload`, switch the agent
   over, delete the old line, `razorwire reload` again.

## Reporting a problem

Report security problems privately to the maintainer. Do not open a public
issue.
