"""A starting point for a Razorwire executor.

Razorwire never touches your systems itself. When you roll back what an agent
did, or approve a parked call after its agent stopped waiting, Razorwire asks
this service to carry out one action. This service holds the real
credentials, so keep it on a machine agents cannot reach.

Run it:

    razorwire new-executor-key            # once; keep the key secret
    EXECUTOR_KEY=<that key> python examples/executor.py

and start Razorwire with the same key:

    EXECUTOR_URL=http://127.0.0.1:9100 EXECUTOR_KEY=<that key> razorwire

Each request is a JSON object, for example

    {"kind": "undo", "id": "und_...", "tool": "close_ticket",
     "arguments": {"id": 812}, "undoes": {"tool": "create_ticket", ...}}
    {"kind": "call", "id": "apr_...", "tool": "stripe_refund",
     "arguments": {"amount": 4700}, "approved_by": "mann"}

signed in two headers:

    x-razorwire-timestamp: milliseconds since 1970
    x-razorwire-signature: v1=<hex HMAC-SHA256 of "<timestamp>.<body>">

Answer 2xx with a JSON body when the action is done, or another status with
{"error": "..."} when it is not. Razorwire sends the same id when it retries,
so an action is never carried out twice.

Replace the functions in ACTIONS with calls to your real systems. Python 3.9
or later, standard library only.
"""
import hashlib
import hmac
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = bytes.fromhex(os.environ.get("EXECUTOR_KEY", "").strip() or "00")
PORT = int(os.environ.get("EXECUTOR_PORT", "9100"))
# Every action carried out is appended here, one JSON object per line.
LOG = os.environ.get("EXECUTOR_LOG", "executor.jsonl")
MAX_AGE_MS = 5 * 60 * 1000
MAX_BODY = 1024 * 1024

# Ids already carried out, with their answers. In production, keep these in
# a database so a restart does not forget them.
DONE = {}
LOCK = threading.Lock()


# The actions this executor can carry out. Each gets the call's arguments and
# returns what to answer. Raise an exception to say it could not be done.

def close_ticket(arguments):
    # e.g. requests.patch(f"{TICKETS}/{arguments['id']}", json={"state": "closed"})
    return {"closed": arguments["id"]}


def revoke_role(arguments):
    # e.g. directory.remove_role(arguments["user"], arguments["role"])
    return {"revoked": arguments["role"], "user": arguments["user"]}


def stripe_refund(arguments):
    # e.g. stripe.Refund.create(charge=arguments["charge"], amount=arguments["amount"])
    return {"refunded": arguments["amount"]}


ACTIONS = {
    "close_ticket": close_ticket,
    "revoke_role": revoke_role,
    "stripe_refund": stripe_refund,
}


def signed_by_razorwire(headers, body):
    timestamp = headers.get("x-razorwire-timestamp", "")
    signature = headers.get("x-razorwire-signature", "")
    if not timestamp.isdigit() or not signature.startswith("v1="):
        return False
    if abs(time.time() * 1000 - int(timestamp)) > MAX_AGE_MS:
        return False
    expected = hmac.new(KEY, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature[3:])


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def answer(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("content-length") or 0)
        if length > MAX_BODY:
            return self.answer(413, {"error": "request too large"})
        body = self.rfile.read(length)
        if not signed_by_razorwire(self.headers, body):
            return self.answer(401, {"error": "not signed by Razorwire, or too old"})
        try:
            job = json.loads(body)
            job_id, tool, arguments = job["id"], job["tool"], job["arguments"]
        except (ValueError, KeyError, TypeError):
            return self.answer(400, {"error": "not a Razorwire request"})
        with LOCK:
            if job_id in DONE:
                return self.answer(200, DONE[job_id])
        action = ACTIONS.get(tool)
        if action is None:
            return self.answer(400, {"error": f"this executor has no action for {tool}"})
        try:
            result = action(arguments)
        except Exception as err:  # the action failed; Razorwire may retry later
            return self.answer(500, {"error": f"{tool} failed: {err}"})
        with LOCK:
            DONE[job_id] = result
            with open(LOG, "a", encoding="utf-8") as log:
                log.write(json.dumps({"ts_ms": int(time.time() * 1000), "job": job, "result": result}) + "\n")
        return self.answer(200, result)


if __name__ == "__main__":
    if len(KEY) < 32:
        sys.exit("Set EXECUTOR_KEY to the key from `razorwire new-executor-key`.")
    print(f"executor listening on http://127.0.0.1:{PORT}, actions: {', '.join(ACTIONS)}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
