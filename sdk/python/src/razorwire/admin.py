"""The admin API: held calls, approvals, reloads and rollbacks.

    from razorwire import Admin

    admin = Admin()                    # RAZORWIRE_URL and RAZORWIRE_ADMIN_KEY
    for call in admin.approvals().pending:
        print(call.id, call.tool, call.arguments)
    admin.approve(call.id, reason="checked the order")

An admin key is only sent over https, or plain http to this machine.
Redirects are never followed, so the key never goes anywhere else.
"""

from __future__ import annotations

import datetime as _dt
import http.client
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Union
from urllib.parse import urlsplit

from ._urls import KEY_PREFIX, check_url, proxy_url, shown_url
from ._version import __version__

MAX_ANSWER_BYTES = 32 * 1024 * 1024
_APPROVAL_ID = re.compile(r"[A-Za-z0-9_]{1,128}")
_SPAN = re.compile(r"(\d+)([smhd])")
_SPAN_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

Since = Union[int, float, str, _dt.timedelta, _dt.datetime]


class RazorwireError(Exception):
    """Razorwire refused a request, or could not be reached."""

    def __init__(self, message: str, status: Optional[int] = None, code: Optional[str] = None):
        super().__init__(message)
        self.status = status
        """The HTTP status, when Razorwire answered."""
        self.code = code
        """Razorwire's error code, such as "not_pending" or "no_executor"."""


@dataclass(frozen=True)
class HeldCall:
    """A tool call waiting for a person, or parked after nobody decided in time."""

    id: str
    tool: Optional[str]
    agent: str
    rule: Optional[str]
    message: str
    arguments: Any
    call_id: Optional[str]
    created_ms: Optional[int]
    expires_ms: Optional[int]
    """When a waiting call stops waiting."""
    parked_until_ms: Optional[int]
    """When a parked call is dropped. None for a call that is still waiting."""
    raw: Dict[str, Any] = field(repr=False, compare=False)

    @property
    def parked(self) -> bool:
        return self.parked_until_ms is not None

    @classmethod
    def _read(cls, raw: Dict[str, Any]) -> HeldCall:
        return cls(
            id=str(raw.get("id", "")),
            tool=raw.get("tool"),
            agent=raw.get("agent") or "",
            rule=raw.get("rule"),
            message=raw.get("message") or "",
            arguments=raw.get("arguments"),
            call_id=raw.get("call_id"),
            created_ms=raw.get("created_ms"),
            expires_ms=raw.get("expires_ms"),
            parked_until_ms=raw.get("parked_until_ms"),
            raw=raw,
        )


@dataclass(frozen=True)
class Approvals:
    pending: List[HeldCall]
    """Calls whose agent is waiting, oldest first."""
    parked: List[HeldCall]
    """Calls nobody decided in time. Approving one has the executor carry it out."""
    now_ms: int


@dataclass(frozen=True)
class Decision:
    approval_id: str
    decision: str
    """"approved" or "denied"."""
    by: str
    reason: Optional[str]
    agent: Optional[str]
    tool: Optional[str]
    parked: bool
    ran: bool
    """True when a parked call was approved and the executor carried it out."""
    output: Any
    """What the executor answered, when it ran."""


@dataclass(frozen=True)
class RollbackStep:
    id: str
    """The undo id, und_ and 24 hex characters."""
    ts_ms: Optional[int]
    agent: Optional[str]
    tool: Optional[str]
    call_id: Optional[str]
    arguments: Any
    result: Any
    undo: Optional[Dict[str, Any]]
    """The reversing call, {"tool": ..., "arguments": ...}, or None."""
    cannot_undo: Optional[str]
    """Why there is no reversing call."""
    done: bool
    """Already undone by an earlier rollback."""
    last_error: Optional[str]
    outcome: Optional[str]
    """After a run: "undone", "failed", "already_undone", "cannot_undo" or "not_tried"."""
    output: Any
    error: Optional[str]
    raw: Dict[str, Any] = field(repr=False, compare=False)

    @classmethod
    def _read(cls, raw: Dict[str, Any]) -> RollbackStep:
        return cls(
            id=str(raw.get("id", "")),
            ts_ms=raw.get("ts_ms"),
            agent=raw.get("agent"),
            tool=raw.get("tool"),
            call_id=raw.get("call_id"),
            arguments=raw.get("arguments"),
            result=raw.get("result"),
            undo=raw.get("undo"),
            cannot_undo=raw.get("cannot_undo"),
            done=raw.get("done") is True,
            last_error=raw.get("last_error"),
            outcome=raw.get("outcome"),
            output=raw.get("output"),
            error=raw.get("error"),
            raw=raw,
        )


@dataclass(frozen=True)
class Rollback:
    run: bool
    """False for a plan only."""
    steps: List[RollbackStep]
    """Newest first, the order they are undone in."""
    undone: int
    failed: bool
    now_ms: int


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


class Admin:
    """A client for Razorwire's admin API."""

    def __init__(
        self,
        url: Optional[str] = None,
        key: Optional[str] = None,
        *,
        ca_cert: Optional[str] = None,
        timeout: float = 90.0,
    ):
        """
        url:     the proxy, default RAZORWIRE_URL or http://127.0.0.1:8080
        key:     an admin key, default RAZORWIRE_ADMIN_KEY
        ca_cert: a PEM certificate to trust as well, for a self-signed
                 proxy, default RAZORWIRE_CA_CERT
        timeout: seconds per request. Approving a parked call waits for
                 the executor, which may take up to 60 seconds.
        """
        self.url = proxy_url(url)
        check_url(self.url, "RAZORWIRE_URL")
        key = key if key is not None else os.environ.get("RAZORWIRE_ADMIN_KEY", "")
        key = key.strip()
        if not key.startswith(KEY_PREFIX):
            raise ValueError(
                "Pass key= or set RAZORWIRE_ADMIN_KEY to an admin key. "
                "Create one with `razorwire new-key admin <name>`."
            )
        self._key = key
        self.timeout = timeout
        if ca_cert is None:
            ca_cert = os.environ.get("RAZORWIRE_CA_CERT", "").strip() or None
        context = ssl.create_default_context()
        if ca_cert:
            context.load_verify_locations(cafile=ca_cert)
        handlers: List[Any] = [_NoRedirects(), urllib.request.HTTPSHandler(context=context)]
        if urlsplit(self.url).scheme == "http":
            # Plain http only goes to this machine, never through a proxy.
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers)

    def __repr__(self) -> str:
        return f"Admin(url={self.url!r})"

    def approvals(self) -> Approvals:
        """Held calls, waiting and parked."""
        answer = self._call("GET", "/razorwire/approvals")
        return Approvals(
            pending=[HeldCall._read(item) for item in answer.get("pending") or []],
            parked=[HeldCall._read(item) for item in answer.get("parked") or []],
            now_ms=answer.get("now_ms") or int(time.time() * 1000),
        )

    def approve(self, approval_id: Union[str, HeldCall], reason: Optional[str] = None) -> Decision:
        """Let a held call through, or have the executor carry out a parked one."""
        return self._decide(approval_id, "approve", reason)

    def deny(self, approval_id: Union[str, HeldCall], reason: Optional[str] = None) -> Decision:
        """Block a held or parked call. The reason is shown to the agent."""
        return self._decide(approval_id, "deny", reason)

    def reload(self) -> Dict[str, Any]:
        """Re-read the policy and keys files. Nothing changes if either is invalid."""
        return self._call("POST", "/razorwire/reload").get("config") or {}

    def rollback(
        self,
        *,
        agent: Optional[str] = None,
        since: Optional[Since] = None,
        ids: Optional[Iterable[str]] = None,
        run: bool = False,
    ) -> Rollback:
        """What would be undone, or with `run=True`, undo it.

        Say at least one of: `agent`, `since` (seconds, a timedelta, a
        datetime, or a span like "30m", "2h" or "1d") and `ids`. Steps are
        undone newest first, stopping at the first failure.
        """
        body: Dict[str, Any] = {"run": bool(run)}
        if agent is not None:
            body["agent"] = agent
        if since is not None:
            body.update(_since(since))
        if ids is not None:
            body["ids"] = list(ids)
        if len(body) == 1:
            raise ValueError("say what to roll back: agent=, since= or ids=")
        answer = self._call("POST", "/razorwire/rollback", body)
        return Rollback(
            run=answer.get("run") is True,
            steps=[RollbackStep._read(item) for item in answer.get("steps") or []],
            undone=answer.get("undone") or 0,
            failed=answer.get("failed") is True,
            now_ms=answer.get("now_ms") or int(time.time() * 1000),
        )

    def wait_for_held(
        self,
        *,
        tool: Optional[str] = None,
        agent: Optional[str] = None,
        timeout: float = 60.0,
        interval: float = 0.5,
    ) -> HeldCall:
        """Wait until a call is held, optionally for this tool or agent, and return the oldest."""
        deadline = time.monotonic() + timeout
        while True:
            for call in self.approvals().pending:
                if (tool is None or call.tool == tool) and (agent is None or call.agent == agent):
                    return call
            if time.monotonic() >= deadline:
                raise TimeoutError("no matching call was held in time")
            time.sleep(interval)

    def _decide(self, approval_id: Union[str, HeldCall], action: str, reason: Optional[str]) -> Decision:
        if isinstance(approval_id, HeldCall):
            approval_id = approval_id.id
        if not isinstance(approval_id, str) or not _APPROVAL_ID.fullmatch(approval_id):
            raise ValueError("that is not an approval id; approvals() lists them")
        body = {"reason": reason} if reason is not None else None
        answer = self._call("POST", f"/razorwire/approvals/{approval_id}/{action}", body)
        return Decision(
            approval_id=answer.get("approval_id") or approval_id,
            decision=answer.get("decision") or ("approved" if action == "approve" else "denied"),
            by=answer.get("by") or "",
            reason=answer.get("reason"),
            agent=answer.get("agent"),
            tool=answer.get("tool"),
            parked=answer.get("parked") is True,
            ran=answer.get("ran") is True,
            output=answer.get("output"),
        )

    def _call(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = json.dumps(body).encode() if body is not None else (b"" if method == "POST" else None)
        request = urllib.request.Request(self.url + path, data=data, method=method)
        request.add_header("Authorization", f"Bearer {self._key}")
        request.add_header("Accept", "application/json")
        request.add_header("User-Agent", f"razorwire-python/{__version__}")
        if body is not None:
            request.add_header("Content-Type", "application/json")
        where = shown_url(self.url)
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                status, raw = response.status, response.read(MAX_ANSWER_BYTES)
        except urllib.error.HTTPError as err:
            status = err.code
            raw = err.read(MAX_ANSWER_BYTES) if err.fp is not None else b""
            err.close()
        except (urllib.error.URLError, OSError, http.client.HTTPException) as err:
            reason = getattr(err, "reason", err)
            raise RazorwireError(f"cannot reach Razorwire at {where}: {reason}") from None
        if 300 <= status < 400:
            raise RazorwireError(
                f"Razorwire at {where} answered {status} with a redirect, which is not followed "
                "so the admin key goes nowhere else",
                status,
            )
        try:
            answer = json.loads(raw)
        except ValueError:
            answer = None
        if not isinstance(answer, dict):
            raise RazorwireError(f"Razorwire answered {status} with something that is not JSON", status)
        if status >= 400:
            error = answer.get("error")
            if not isinstance(error, dict):
                error = {}
            message = error.get("message") or "no reason given"
            raise RazorwireError(f"Razorwire said no ({status}): {message}", status, error.get("code"))
        return answer


def _since(since: Since) -> Dict[str, int]:
    if isinstance(since, _dt.datetime):
        moment = since if since.tzinfo else since.astimezone()
        return {"since_ms": max(0, int(moment.timestamp() * 1000))}
    if isinstance(since, _dt.timedelta):
        seconds = since.total_seconds()
    elif isinstance(since, str):
        match = _SPAN.fullmatch(since.strip())
        if match is None:
            raise ValueError('since takes a span like "30m", "2h" or "1d"')
        seconds = int(match.group(1)) * _SPAN_SECONDS[match.group(2)]
    elif isinstance(since, (int, float)) and not isinstance(since, bool):
        seconds = since
    else:
        raise TypeError('since takes seconds, a timedelta, a datetime or a span like "2h"')
    if seconds < 0:
        raise ValueError("since must not be negative")
    return {"since_secs": int(seconds)}
