import json
import threading
import urllib.error
import urllib.request

import pytest

from razorwire import Executor, Job, sign

KEY = "5a" * 32


def job(job_id="und_0123456789abcdef01234567", tool="close_ticket", **extra):
    body = {"kind": "undo", "id": job_id, "tool": tool, "arguments": {"id": 812}, "requested_by": "mann", **extra}
    return json.dumps(body).encode()


def signed(body):
    return sign(KEY, body)


def make():
    executor = Executor(KEY)
    calls = []

    @executor.action("close_ticket")
    def close_ticket(j):
        calls.append(j)
        return {"closed": j.arguments["id"]}

    return executor, calls


def test_a_job_runs_once_even_when_retried():
    executor, calls = make()
    body = job()
    assert executor.handle(body, signed(body)) == (200, {"closed": 812})
    assert executor.handle(body, signed(body)) == (200, {"closed": 812})
    assert len(calls) == 1
    [seen] = calls
    assert isinstance(seen, Job)
    assert (seen.kind, seen.tool, seen.by, seen.arguments) == ("undo", "close_ticket", "mann", {"id": 812})


def test_unsigned_or_bad_jobs_are_refused():
    executor, calls = make()
    body = job()
    assert executor.handle(body, {})[0] == 401
    assert executor.handle(body, sign("6b" * 32, body))[0] == 401
    assert executor.handle(b"[1, 2]", signed(b"[1, 2]"))[0] == 400
    assert executor.handle(b"not json", signed(b"not json"))[0] == 400
    no_tool = json.dumps({"id": "apr_1", "arguments": {}}).encode()
    assert executor.handle(no_tool, signed(no_tool))[0] == 400
    unknown = job(tool="drop_everything")
    status, answer = executor.handle(unknown, signed(unknown))
    assert status == 400 and "no action for drop_everything" in answer["error"]
    assert calls == []


def test_a_failed_action_can_be_tried_again():
    executor = Executor(KEY)
    attempts = []

    @executor.action("stripe_refund")
    def refund(j):
        attempts.append(1)
        if len(attempts) == 1:
            raise RuntimeError("stripe is down")
        return {"refunded": 750}

    body = job("apr_" + "1" * 32, "stripe_refund", kind="call")
    status, answer = executor.handle(body, signed(body))
    assert status == 500 and answer == {"error": "stripe_refund failed: stripe is down"}
    assert executor.handle(body, signed(body)) == (200, {"refunded": 750})
    assert len(attempts) == 2


def test_the_same_job_twice_at_once_runs_once():
    executor = Executor(KEY)
    started, release, runs = threading.Event(), threading.Event(), []

    @executor.action("close_ticket")
    def slow(j):
        runs.append(1)
        started.set()
        release.wait(5)
        return {"closed": 812}

    body = job()
    first = []
    thread = threading.Thread(target=lambda: first.append(executor.handle(body, signed(body))))
    thread.start()
    assert started.wait(5)
    status, _ = executor.handle(body, signed(body))
    release.set()
    thread.join(5)
    assert status == 409
    assert first == [(200, {"closed": 812})]
    assert runs == [1]


def test_the_log_remembers_jobs_across_restarts(tmp_path):
    log = str(tmp_path / "executor.jsonl")
    body = job()
    first = Executor(KEY, log=log)
    first.add("close_ticket", lambda j: {"closed": 812, "at": object()})
    status, answer = first.handle(body, signed(body))
    assert status == 200 and answer["closed"] == 812 and isinstance(answer["at"], str)

    second = Executor(KEY, log=log)
    second.add("close_ticket", lambda j: pytest.fail("ran twice"))
    assert second.handle(body, signed(body)) == (200, answer)
    with open(log, encoding="utf-8") as lines:
        entry = json.loads(lines.readline())
    assert entry["id"] == "und_0123456789abcdef01234567" and entry["by"] == "mann"


def test_a_key_is_required():
    with pytest.raises(ValueError):
        Executor("ab" * 8)


def test_over_http(monkeypatch):
    executor, calls = make()
    server = executor.server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        body = job()
        request = urllib.request.Request(url, data=body, headers=signed(body), method="POST")
        with opener.open(request, timeout=5) as response:
            assert json.loads(response.read()) == {"closed": 812}
        forged = urllib.request.Request(url, data=body, method="POST")
        with pytest.raises(urllib.error.HTTPError) as refused:
            opener.open(forged, timeout=5)
        assert refused.value.code == 401
    finally:
        server.shutdown()
        server.server_close()
    assert len(calls) == 1
