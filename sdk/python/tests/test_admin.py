import datetime as dt
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from razorwire import Admin, HeldCall, RazorwireError

KEY = "rw_" + "a1" * 32


class Stub:
    """A stand-in for the admin API that records what it is sent."""

    def __init__(self, routes):
        self.routes = routes
        self.seen = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def handle_any(self):
                length = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(length)
                stub.seen.append((self.command, self.path, dict(self.headers), body))
                status, payload, headers = stub.routes.get(
                    (self.command, self.path), (404, {"error": {"message": "no route"}}, {})
                )
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = handle_any

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def stub():
    servers = []

    def make(routes):
        server = Stub(routes)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


PENDING = {
    "id": "apr_" + "3" * 32,
    "agent": "support-bot",
    "tool": "stripe_refund",
    "arguments": {"amount": 750},
    "call_id": "call_1",
    "rule": "refund-cap",
    "message": "Refunds above 500 are held for human approval.",
    "request_id": 4,
    "created_ms": 1000,
    "expires_ms": 301000,
}
PARKED = dict(PENDING, id="apr_" + "4" * 32, parked_until_ms=605_000_000, expires_ms=None)


def test_listing_held_calls(stub):
    server = stub(
        {("GET", "/razorwire/approvals"): (200, {"now_ms": 5000, "pending": [PENDING], "parked": [PARKED]}, {})}
    )
    answer = Admin(server.url, KEY).approvals()
    [held] = answer.pending
    assert (held.id, held.tool, held.agent, held.arguments, held.expires_ms) == (
        PENDING["id"],
        "stripe_refund",
        "support-bot",
        {"amount": 750},
        301000,
    )
    assert not held.parked and answer.parked[0].parked
    assert answer.now_ms == 5000
    headers = server.seen[0][2]
    assert headers["Authorization"] == f"Bearer {KEY}"
    assert headers["User-Agent"].startswith("razorwire-python/")


def test_approve_and_deny(stub):
    approved = {
        "approval_id": PENDING["id"],
        "decision": "approved",
        "by": "mann",
        "reason": None,
        "agent": "support-bot",
        "tool": "stripe_refund",
    }
    ran = {
        "approval_id": PARKED["id"],
        "decision": "approved",
        "by": "mann",
        "reason": "fine",
        "agent": "support-bot",
        "tool": "stripe_refund",
        "parked": True,
        "ran": True,
        "output": {"refunded": 750},
    }
    denied = dict(approved, decision="denied", reason="wrong order")
    server = stub(
        {
            ("POST", f"/razorwire/approvals/{PENDING['id']}/approve"): (200, approved, {}),
            ("POST", f"/razorwire/approvals/{PARKED['id']}/approve"): (200, ran, {}),
            ("POST", f"/razorwire/approvals/{PENDING['id']}/deny"): (200, denied, {}),
        }
    )
    admin = Admin(server.url, KEY)
    decision = admin.approve(HeldCall._read(PENDING))
    assert (decision.decision, decision.by, decision.ran) == ("approved", "mann", False)
    assert server.seen[-1][3] == b""
    decision = admin.approve(PARKED["id"], reason="fine")
    assert decision.parked and decision.ran and decision.output == {"refunded": 750}
    assert json.loads(server.seen[-1][3]) == {"reason": "fine"}
    assert admin.deny(PENDING["id"], "wrong order").reason == "wrong order"


def test_refusals_become_errors(stub):
    refusal = {
        "error": {"message": "No tool call is waiting under that id.", "type": "razorwire_error", "code": "not_pending"}
    }
    server = stub(
        {
            ("POST", "/razorwire/approvals/apr_gone/approve"): (404, refusal, {}),
            ("POST", "/razorwire/reload"): (502, b"<html>bad gateway</html>", {}),
        }
    )
    admin = Admin(server.url, KEY)
    with pytest.raises(RazorwireError) as err:
        admin.approve("apr_gone")
    assert (err.value.status, err.value.code) == (404, "not_pending")
    assert "No tool call is waiting" in str(err.value)
    with pytest.raises(RazorwireError, match="not JSON"):
        admin.reload()


def test_bad_ids_never_reach_the_network(stub):
    server = stub({})
    admin = Admin(server.url, KEY)
    for bad in ["", "../reload", "apr_1/deny", "apr 1", "a" * 200]:
        with pytest.raises(ValueError):
            admin.approve(bad)
    assert server.seen == []


def test_redirects_are_not_followed(stub):
    elsewhere = stub({("GET", "/razorwire/approvals"): (200, {"pending": [], "parked": []}, {})})
    server = stub({("GET", "/razorwire/approvals"): (302, b"", {"Location": elsewhere.url + "/razorwire/approvals"})})
    with pytest.raises(RazorwireError, match="redirect"):
        Admin(server.url, KEY).approvals()
    assert elsewhere.seen == []


def test_the_key_only_goes_where_it_is_safe(monkeypatch):
    monkeypatch.delenv("RAZORWIRE_ADMIN_KEY", raising=False)
    with pytest.raises(ValueError, match="https"):
        Admin("http://razorwire.internal:8080", KEY)
    with pytest.raises(ValueError, match="user name"):
        Admin("https://me:secret@razorwire.example.com", KEY)
    with pytest.raises(ValueError, match="RAZORWIRE_ADMIN_KEY"):
        Admin("https://razorwire.example.com")
    with pytest.raises(ValueError, match="RAZORWIRE_ADMIN_KEY"):
        Admin("https://razorwire.example.com", "not-a-key")
    Admin("https://razorwire.example.com", KEY)
    Admin("http://[::1]:8080", KEY)
    assert KEY not in repr(Admin("http://localhost:8080", KEY))


def test_settings_from_the_environment(monkeypatch, stub):
    server = stub({("POST", "/razorwire/reload"): (200, {"reloaded": True, "config": {"policy": "p.yaml"}}, {})})
    monkeypatch.setenv("RAZORWIRE_URL", server.url + "/")
    monkeypatch.setenv("RAZORWIRE_ADMIN_KEY", f"  {KEY}\n")
    assert Admin().reload() == {"policy": "p.yaml"}
    assert server.seen[0][2]["Authorization"] == f"Bearer {KEY}"


def test_unreachable_errors_do_not_show_the_key():
    admin = Admin("http://127.0.0.1:9", KEY, timeout=2)
    with pytest.raises(RazorwireError) as err:
        admin.approvals()
    assert "cannot reach Razorwire at http://127.0.0.1:9" in str(err.value)
    assert KEY not in str(err.value)


def test_rollback_requests(stub):
    plan = {
        "run": False,
        "now_ms": 9,
        "steps": [
            {
                "id": "und_" + "a" * 24,
                "ts_ms": 5,
                "agent": "ops-bot",
                "tool": "create_ticket",
                "call_id": "call_1",
                "arguments": {"title": "x"},
                "result": {"id": 812},
                "undo": {"tool": "close_ticket", "arguments": {"id": 812}},
                "cannot_undo": None,
                "done": False,
                "last_error": None,
            }
        ],
    }
    server = stub({("POST", "/razorwire/rollback"): (200, plan, {})})
    admin = Admin(server.url, KEY)
    result = admin.rollback(agent="ops-bot")
    [step] = result.steps
    assert not result.run and step.undo == {"tool": "close_ticket", "arguments": {"id": 812}} and not step.done
    assert json.loads(server.seen[-1][3]) == {"run": False, "agent": "ops-bot"}

    admin.rollback(since="2h", ids=["und_" + "a" * 24], run=True)
    assert json.loads(server.seen[-1][3]) == {"run": True, "since_secs": 7200, "ids": ["und_" + "a" * 24]}
    admin.rollback(since=dt.timedelta(minutes=30))
    assert json.loads(server.seen[-1][3])["since_secs"] == 1800
    moment = dt.datetime(2026, 11, 18, 12, 0, tzinfo=dt.timezone.utc)
    admin.rollback(since=moment)
    assert json.loads(server.seen[-1][3])["since_ms"] == int(moment.timestamp() * 1000)

    with pytest.raises(ValueError):
        admin.rollback()
    with pytest.raises(ValueError):
        admin.rollback(since="soon")
    with pytest.raises(TypeError):
        admin.rollback(since=True)


def test_waiting_for_a_held_call(stub):
    server = stub({("GET", "/razorwire/approvals"): (200, {"pending": [PENDING], "parked": []}, {})})
    admin = Admin(server.url, KEY)
    assert admin.wait_for_held(tool="stripe_refund", agent="support-bot").id == PENDING["id"]
    with pytest.raises(TimeoutError):
        admin.wait_for_held(tool="db_drop", timeout=0.2, interval=0.05)
