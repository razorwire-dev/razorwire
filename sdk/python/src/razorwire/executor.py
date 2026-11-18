"""Build the executor: the service that carries out actions for Razorwire.

Razorwire never touches your systems itself. When you roll back what an
agent did, or approve a parked call after its agent stopped waiting, it
sends one signed job to your executor, which holds the real credentials.

    from razorwire import Executor

    executor = Executor()              # the key from EXECUTOR_KEY

    @executor.action("close_ticket")
    def close_ticket(job):
        tickets.close(job.arguments["id"])
        return {"closed": job.arguments["id"]}

    executor.serve(port=9100)

Start Razorwire with EXECUTOR_URL=http://127.0.0.1:9100 and the same
EXECUTOR_KEY. Every job's signature and age are checked, and a job id that
was already carried out gets the same answer again without running twice.
Pass `log=` to keep that memory across restarts.

To mount it in a web framework instead of `serve()`, pass the raw body and
the headers to `handle()` and send back the status and JSON it returns.

Keep the executor where agents cannot reach it. Razorwire only talks to an
executor over https unless it runs on the same machine, so put one on
another machine behind a TLS proxy.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional, Set, Tuple

from .signing import DEFAULT_MAX_AGE, Key, SignatureError, key_bytes, verify

MAX_BODY = 1024 * 1024
MAX_ERROR = 500

Action = Callable[["Job"], Any]


@dataclass(frozen=True)
class Job:
    """One action Razorwire asks for."""

    kind: str
    """"undo" for a rollback step, "call" for an approved parked call."""
    id: str
    """und_... or apr_... The same on every retry."""
    tool: str
    arguments: Any
    by: Optional[str]
    """The admin who asked: who approved the call or ran the rollback."""
    agent: Optional[str]
    call_id: Optional[str]
    reason: Optional[str]
    undoes: Optional[Dict[str, Any]]
    """For an undo, the call it reverses: its tool, arguments and result."""
    raw: Dict[str, Any] = field(repr=False, compare=False)

    @classmethod
    def _read(cls, raw: Dict[str, Any]) -> Job:
        job_id, tool = raw.get("id"), raw.get("tool")
        if not isinstance(job_id, str) or not job_id or not isinstance(tool, str) or not tool:
            raise ValueError("a job needs an id and a tool")
        if "arguments" not in raw:
            raise ValueError("a job needs arguments")
        return cls(
            kind=str(raw.get("kind") or ""),
            id=job_id,
            tool=tool,
            arguments=raw["arguments"],
            by=raw.get("approved_by") or raw.get("requested_by"),
            agent=raw.get("agent"),
            call_id=raw.get("call_id"),
            reason=raw.get("reason"),
            undoes=raw.get("undoes"),
            raw=raw,
        )


class Executor:
    def __init__(
        self,
        key: Optional[Key] = None,
        *,
        log: Optional[str] = None,
        max_age: float = DEFAULT_MAX_AGE,
    ):
        """
        key:     EXECUTOR_KEY, hex, at least 32 bytes. Default: the
                 EXECUTOR_KEY environment variable.
        log:     a file to append every action carried out to, one JSON
                 object per line. It is read back at start, so a restart
                 still answers a retried id without running it again.
        max_age: seconds a signature stays valid.
        """
        if key is None:
            key = os.environ.get("EXECUTOR_KEY", "")
        if not key:
            raise ValueError("Pass key= or set EXECUTOR_KEY to the key from `razorwire new-executor-key`.")
        self._key = key_bytes(key)
        self._max_age = max_age
        self._actions: Dict[str, Action] = {}
        self._done: Dict[str, Any] = {}
        self._running: Set[str] = set()
        self._lock = threading.Lock()
        self._log = log
        if log and os.path.exists(log):
            self._load(log)

    def __repr__(self) -> str:
        return f"Executor(actions={sorted(self._actions)!r})"

    @property
    def actions(self) -> Tuple[str, ...]:
        return tuple(sorted(self._actions))

    def action(self, tool: str) -> Callable[[Action], Action]:
        """Register the function that carries out `tool`. It gets the Job and
        returns what to answer, anything JSON can hold. Raise to say it
        could not be done; Razorwire records the error, and an approved
        parked call stays parked so it can be approved again."""

        def register(function: Action) -> Action:
            self.add(tool, function)
            return function

        return register

    def add(self, tool: str, function: Action) -> None:
        if not tool or not callable(function):
            raise ValueError("add() takes a tool name and a function")
        self._actions[tool] = function

    def handle(self, body: bytes, headers: Any) -> Tuple[int, Any]:
        """Check and carry out one request. Returns the status and the JSON answer."""
        if len(body) > MAX_BODY:
            return 413, {"error": "request too large"}
        try:
            verify(self._key, body, headers, max_age=self._max_age)
        except SignatureError:
            return 401, {"error": "not signed by Razorwire, or too old"}
        try:
            raw = json.loads(body)
            job = Job._read(raw if isinstance(raw, dict) else {})
        except ValueError:
            return 400, {"error": "not a Razorwire job"}
        with self._lock:
            if job.id in self._done:
                return 200, self._done[job.id]
            if job.id in self._running:
                return 409, {"error": "this job is already running; ask again when it is done"}
            action = self._actions.get(job.tool)
            if action is None:
                return 400, {"error": f"this executor has no action for {job.tool}"}
            self._running.add(job.id)
        try:
            result = action(job)
        except Exception as err:  # the action failed; Razorwire may ask again
            with self._lock:
                self._running.discard(job.id)
            return 500, {"error": f"{job.tool} failed: {err}"[:MAX_ERROR]}
        # Anything the action returns is kept as JSON, so the answer to a
        # retry is the same as the first.
        try:
            result = json.loads(json.dumps({} if result is None else result, default=str))
        except ValueError:
            result = str(result)
        with self._lock:
            self._done[job.id] = result
            self._running.discard(job.id)
            if self._log:
                entry = {
                    "ts_ms": int(time.time() * 1000),
                    "id": job.id,
                    "kind": job.kind,
                    "tool": job.tool,
                    "arguments": job.arguments,
                    "by": job.by,
                    "result": result,
                }
                # The action ran, so it is answered as done even if the log
                # cannot be written; this process still remembers it.
                try:
                    with open(self._log, "a", encoding="utf-8") as log:
                        log.write(json.dumps(entry, default=str) + "\n")
                except OSError as err:
                    print(f"razorwire executor: cannot write {self._log}: {err}", file=sys.stderr, flush=True)
        return 200, result

    def server(self, host: str = "127.0.0.1", port: int = 9100) -> ThreadingHTTPServer:
        """An HTTP server for this executor, not yet started. Port 0 picks a free one."""
        executor = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "razorwire-executor"

            def log_message(self, format: str, *args: Any) -> None:
                pass

            def answer(self, status: int, payload: Any) -> None:
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self) -> None:
                try:
                    length = int(self.headers.get("content-length") or 0)
                except ValueError:
                    return self.answer(400, {"error": "bad content-length"})
                if length < 0 or length > MAX_BODY:
                    return self.answer(413, {"error": "request too large"})
                body = self.rfile.read(length)
                status, payload = executor.handle(body, self.headers)
                self.answer(status, payload)

            def do_GET(self) -> None:
                self.answer(405, {"error": "send jobs with POST"})

        httpd = ThreadingHTTPServer((host, port), Handler)
        httpd.daemon_threads = True
        return httpd

    def serve(self, host: str = "127.0.0.1", port: int = 9100) -> None:
        """Answer jobs until stopped."""
        httpd = self.server(host, port)
        bound_port = httpd.server_address[1]
        print(
            f"executor listening on http://{host}:{bound_port}, actions: {', '.join(self.actions) or 'none'}",
            flush=True,
        )
        try:
            httpd.serve_forever()
        finally:
            httpd.server_close()

    def _load(self, path: str) -> None:
        with open(path, encoding="utf-8") as log:
            for line in log:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if isinstance(entry, dict) and isinstance(entry.get("id"), str) and "result" in entry:
                    self._done[entry["id"]] = entry["result"]
