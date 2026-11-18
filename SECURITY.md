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
| The admin key crosses a network in the clear | The admin commands refuse a plain-http `RAZORWIRE_URL` unless it points at this machine. With `TLS_CERT` and `TLS_KEY`, Razorwire serves https itself (TLS 1.2 or later). A slow TLS handshake is cut off after 10 seconds, and at most 256 run at once. |
| A bad config silently turns protection off | A policy, keys file, audit key, certificate, executor or alert setting that is missing or invalid stops the proxy from starting. A reload that finds an invalid file changes nothing. |
| A streamed reply slips a tool call through while it is still arriving | Under enforcement, only events known to carry nothing but text go out as they arrive. From the first event that could carry a tool call, or that is not understood, everything is held until the whole reply is checked. A stream that cannot be read, or that is cut off, ends with an error instead of the rest. |
| Someone forges a request to the executor | Every request is signed with HMAC-SHA256 over a timestamp and the body, using `EXECUTOR_KEY`. The example executor refuses a bad signature or a timestamp more than 5 minutes off, and never runs the same id twice. `EXECUTOR_URL` must be https unless it is on this machine, and redirects are not followed. |
| A rollback acts on a doctored log | Rollback and the restore of parked calls read the signed audit log, and refuse it if any line fails its check. The calls and arguments they act on come from the log, not from anything an agent sends. |
| Two admins carry out the same thing twice | A parked call is taken out while it runs, and one rollback runs at a time. A step that was undone is recorded and skipped next time. |
| An alert leaks its webhook address | `ALERT_URL` is never printed or logged; the banner and every error show only its scheme and host. It must be https unless it is on this machine, it may not carry a user name or password, and redirects are not followed. |
| Text from the model tricks an approver through an alert | Names and arguments go into an alert as code, with backticks swapped for a look-alike so they cannot end the code early. Slack gets `&`, `<` and `>` escaped everywhere, so nothing can make a link or mention anyone. Discord gets mentions and link previews turned off. Control characters, direction marks and zero-width characters are replaced. An alert carries no power: approving still needs an admin key. |
| A flood of held or blocked calls floods the alert channel | At most 20 alerts go out a minute. The rest are counted, logged as `alerts_dropped`, and summed up in one message. The queue holds 256 and never makes a request wait; a full queue drops and counts. A receiver that is down is tried 3 times, then `alert_failed` is logged. |
| Someone forges an alert | JSON alerts can be signed with `ALERT_KEY`, the same way as requests to the executor. Slack, Discord and ntfy cannot check a signature, and `ALERT_KEY` is refused with them rather than silently ignored. |
| A revoked person keeps approving | `razorwire revoke-key` removes the key and reloads the running proxy when it can, and says so plainly when it cannot. |

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
- **Plain HTTP by default.** Without `TLS_CERT` and `TLS_KEY`, Razorwire
  speaks plain HTTP. Anything beyond this machine needs https, from
  Razorwire itself or a TLS proxy in front, or keys and prompts can be read
  on the wire. Razorwire does not ask clients for certificates.
- **Results an agent reports.** An undo recipe that uses `result` trusts what
  the agent said the tool returned. A lying agent could point an undo at
  something else, such as another ticket. Read the plan before `--run`,
  prefer recipes built from `args`, and have the executor check that what it
  is asked to undo is something the agent made.
- **The executor itself.** It holds real credentials. Run it where agents
  cannot reach it, keep `EXECUTOR_KEY` secret, and give it only the actions
  it needs. Anyone with the key can ask it to act.
- **Approving a parked call later.** Its arguments are the ones the model
  asked for back then. The world may have changed since; check before you
  approve.
- **What an alert says, once it is sent.** Slack, Discord, ntfy or your own
  endpoint keep it. Arguments can hold customer data; set
  `ALERT_ARGUMENTS=hide` if they must not leave. On ntfy.sh anyone who knows
  the topic name can read it, so use a long random name, or your own ntfy
  server with access control.
- **A model that argues for its own call.** A model can write "this is
  safe, approve it" into its arguments, and an alert shows them. Decide on
  what the call does, not on what it says about itself.
- **An unsigned alert.** Slack, Discord and ntfy alerts cannot be checked.
  Treat an alert as a reason to look, and check `razorwire approvals`
  before approving.
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
5. Listen on `127.0.0.1`, or turn on https with `TLS_CERT` and `TLS_KEY`.
6. Block the agent's direct network access to the provider.
7. To rotate a key: create the new one, switch the agent over, then
   `razorwire revoke-key <old name> <fingerprint>`. With
   `RAZORWIRE_ADMIN_KEY` set, both commands reload the proxy themselves.
8. If you use rollback or parked calls, run the executor as yet another
   user, on a machine or network the agent cannot reach.
9. If you use alerts, keep `ALERT_URL` as secret as a key, and set
   `ALERT_ARGUMENTS=hide` when tool arguments carry personal data.

## Reporting a problem

Report security problems privately to the maintainer. Do not open a public
issue.
