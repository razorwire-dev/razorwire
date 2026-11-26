"""The SDK against a real Razorwire proxy and a fake model provider.

Skipped when there is no razorwire binary; see conftest.find_test_binary.
"""

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from conftest import POLICY, FakeProvider

from razorwire import Admin, Executor, Proxy, RazorwireError, blocked, blocked_count, verify

openai = pytest.importorskip("openai")

TOOLS = [
    {"type": "function", "function": {"name": name, "parameters": {"type": "object"}}}
    for name in ("db_drop", "stripe_refund", "create_ticket")
]
MODEL = "test-model"


def ask(client, text, **extra):
    return client.chat.completions.create(
        model=MODEL, messages=[{"role": "user", "content": text}], tools=TOOLS, **extra
    )


def tool_calls(completion):
    calls = completion.choices[0].message.tool_calls or []
    return [(call.function.name, json.loads(call.function.arguments)) for call in calls]


@pytest.fixture
def proxy(binary, provider):
    with Proxy(policy=POLICY, upstream=provider.url, binary=binary) as running:
        yield running


def test_a_blocked_call_is_reported(proxy):
    client = proxy.openai_client(agent="ops-bot", max_retries=0)
    raw = client.chat.completions.with_raw_response.create(
        model=MODEL,
        tools=TOOLS,
        messages=[
            {
                "role": "user",
                "content": 'Dropping both now.\nCALL db_drop {"database": "production"}\n'
                'CALL db_drop {"database": "staging"}',
            }
        ],
    )
    completion = raw.parse()
    assert tool_calls(completion) == [("db_drop", {"database": "staging"})]
    [block] = blocked(completion)
    assert (block.tool, block.rule, block.outcome) == ("db_drop", "no-production-db-drop", "blocked")
    assert blocked_count(raw) == 1
    events = [e for e in proxy.audit() if e.get("event") == "tool_call"]
    assert [(e["agent"], e["blocked"]) for e in events] == [("ops-bot", True), ("ops-bot", False)]


def test_nothing_blocked(proxy):
    client = proxy.openai_client(agent="ops-bot", max_retries=0)
    raw = client.chat.completions.with_raw_response.create(
        model=MODEL, tools=TOOLS, messages=[{"role": "user", "content": 'CALL stripe_refund {"amount": 20}'}]
    )
    assert blocked(raw.parse()) == []
    # The header is only sent when something was removed.
    assert blocked_count(raw) is None


def test_responses_api(proxy):
    client = proxy.openai_client(agent="ops-bot", max_retries=0)
    response = client.responses.create(model=MODEL, input='CALL db_drop {"database": "production"}', tools=[])
    [block] = blocked(response)
    assert block.rule == "no-production-db-drop"
    assert not [item for item in response.output if item.type == "function_call"]


def test_a_live_stream(proxy):
    client = proxy.openai_client(agent="ops-bot", max_retries=0)
    stream = ask(client, 'Working on it.\nCALL db_drop {"database": "production"}', stream=True)
    text = "".join(chunk.choices[0].delta.content or "" for chunk in stream if chunk.choices)
    assert text.startswith("Working on it.")
    [block] = blocked(text)
    assert block.tool == "db_drop"


def streamed_reply(stream):
    """The text and tool calls an agent gets from a streamed reply."""
    text, calls = "", {}
    for chunk in stream:
        if not chunk.choices:
            continue
        delta = chunk.choices[0].delta
        text += delta.content or ""
        for call in delta.tool_calls or []:
            joined = calls.setdefault(call.index, {"name": "", "arguments": ""})
            joined["name"] += (call.function and call.function.name) or ""
            joined["arguments"] += (call.function and call.function.arguments) or ""
    return text, [(call["name"], json.loads(call["arguments"])) for _, call in sorted(calls.items())]


@pytest.mark.parametrize("stream_mode", ["live", "hold"])
def test_a_call_hidden_behind_a_lone_cr_is_still_checked(binary, provider, stream_mode):
    # The provider hides both calls behind comments, split off by a lone CR,
    # which the OpenAI SDK reads as a line break.
    with Proxy(policy=POLICY, upstream=provider.url, binary=binary, stream_mode=stream_mode) as proxy:
        client = proxy.openai_client(agent="ops-bot", max_retries=0)
        stream = ask(
            client,
            'On it.\nSMUGGLE db_drop {"database": "production"}\nSMUGGLE db_drop {"database": "staging"}',
            stream=True,
        )
        text, calls = streamed_reply(stream)
        assert text.startswith("On it.")
        assert calls == [("db_drop", {"database": "staging"})]
        [block] = blocked(text)
        assert block.rule == "no-production-db-drop"
        events = [e for e in proxy.audit() if e.get("event") == "tool_call"]
        assert [e["blocked"] for e in events] == [True, False]


def test_an_allowed_streamed_call_arrives_whole(proxy):
    client = proxy.openai_client(agent="ops-bot", max_retries=0)
    stream = ask(client, 'Sure.\nCALL create_ticket {"title": "Disk full"}', stream=True)
    text, calls = streamed_reply(stream)
    assert text == "Sure."
    assert calls == [("create_ticket", {"title": "Disk full"})]


@pytest.mark.parametrize("stream_mode", ["live", "hold"])
def test_a_stream_under_another_label_is_still_checked(binary, provider, stream_mode):
    # The agent asked for a stream, so its client reads the reply as one,
    # whatever the provider labels it.
    with Proxy(policy=POLICY, upstream=provider.url, binary=binary, stream_mode=stream_mode) as proxy:
        client = proxy.openai_client(agent="ops-bot", max_retries=0)
        stream = ask(
            client,
            'LABEL text/plain\nOn it.\nCALL db_drop {"database": "production"}\nCALL db_drop {"database": "staging"}',
            stream=True,
        )
        text, calls = streamed_reply(stream)
        assert text.startswith("On it.")
        assert calls == [("db_drop", {"database": "staging"})]
        [block] = blocked(text)
        assert block.rule == "no-production-db-drop"


def test_a_readable_reply_under_another_label_is_checked(proxy):
    client = proxy.openai_client(agent="ops-bot", max_retries=0)
    completion = ask(
        client,
        'LABEL text/plain\nCALL db_drop {"database": "production"}\nCALL db_drop {"database": "staging"}',
    )
    assert tool_calls(completion) == [("db_drop", {"database": "staging"})]


def test_a_reply_razorwire_cannot_read_is_refused_whatever_its_label(proxy):
    # The SDK would still read it: Python's JSON parser skips the BOM.
    client = proxy.openai_client(agent="ops-bot", max_retries=0)
    with pytest.raises(openai.APIStatusError) as refused:
        ask(client, 'LABEL text/plain\nBOM\nCALL db_drop {"database": "production"}')
    assert refused.value.status_code == 502
    assert refused.value.code == "response_not_inspectable"
    assert any(event.get("event") == "response_refused" for event in proxy.audit())


def test_a_redirect_is_not_passed_on(binary, provider):
    # The SDK follows redirects, so the agent would take its reply from
    # elsewhere, unchecked.
    elsewhere = FakeProvider()
    try:
        with Proxy(policy=POLICY, upstream=provider.url, binary=binary) as proxy:
            client = proxy.openai_client(agent="ops-bot", max_retries=0)
            with pytest.raises(openai.APIStatusError) as refused:
                ask(client, f'REDIRECT {elsewhere.url}/v1/chat/completions\nCALL db_drop {{"database": "production"}}')
            assert refused.value.status_code == 502
        assert elsewhere.requests == []
    finally:
        elsewhere.close()


def test_file_content_passes_as_it_is(proxy):
    client = proxy.openai_client(agent="ops-bot", max_retries=0)
    assert client.files.content("file-1").read() == FakeProvider.CONTENT


def test_a_held_call_approved(proxy):
    client = proxy.openai_client(agent="support-bot", max_retries=0, timeout=60)
    with ThreadPoolExecutor(1) as pool:
        waiting = pool.submit(ask, client, 'CALL stripe_refund {"amount": 750, "order": "A-17"}')
        held = proxy.admin.wait_for_held(tool="stripe_refund", timeout=20)
        assert (held.agent, held.rule, held.arguments) == (
            "support-bot",
            "refund-cap",
            {"amount": 750, "order": "A-17"},
        )
        assert held.expires_ms > held.created_ms
        decision = proxy.admin.approve(held, reason="checked the order")
        assert (decision.decision, decision.by, decision.agent) == ("approved", "admin", "support-bot")
        completion = waiting.result(30)
    assert tool_calls(completion) == [("stripe_refund", {"amount": 750, "order": "A-17"})]
    assert blocked(completion) == []
    assert proxy.admin.approvals().pending == []


def test_a_held_call_denied(proxy):
    client = proxy.openai_client(agent="support-bot", max_retries=0, timeout=60)
    with ThreadPoolExecutor(1) as pool:
        waiting = pool.submit(ask, client, 'CALL stripe_refund {"amount": 900}')
        held = proxy.admin.wait_for_held(timeout=20)
        proxy.admin.deny(held.id, reason="wrong order")
        completion = waiting.result(30)
    assert tool_calls(completion) == []
    [block] = blocked(completion)
    assert (block.outcome, block.by, block.rule) == ("denied", "admin", "refund-cap")
    assert "wrong order" in block.message
    with pytest.raises(RazorwireError) as err:
        proxy.admin.approve(held.id)
    assert err.value.code == "not_pending"


def test_agent_keys(binary, provider):
    with Proxy(policy=POLICY, upstream=provider.url, binary=binary, agents=["support-bot"]) as proxy:
        client = proxy.openai_client(agent="support-bot", max_retries=0)
        ask(client, 'CALL stripe_refund {"amount": 20}')
        [event] = [e for e in proxy.audit() if e.get("event") == "tool_call"]
        assert event["agent"] == "support-bot"
        # Razorwire keys never reach the provider.
        sent = provider.requests[-1]["headers"]
        assert not any(proxy.agent_key("support-bot") in value for value in sent.values())
        # An agent's key cannot use the admin API.
        with pytest.raises(RazorwireError) as err:
            Admin(proxy.url, proxy.agent_key("support-bot")).approvals()
        assert (err.value.status, err.value.code) == (403, "wrong_key_role")
        # Without a key, the proxy refuses the agent.
        anonymous = proxy.openai_client(max_retries=0, api_key="sk-nothing")
        with pytest.raises(Exception) as refused:
            ask(anonymous, "hello")
        assert getattr(refused.value, "status_code", None) == 401


class Executors:
    """An Executor from the SDK, served on a free port."""

    def __init__(self, key):
        self.executor = Executor(key)
        self.calls = []
        for tool in ("stripe_refund", "close_ticket"):
            self.executor.add(tool, self.record)
        self.server = self.executor.server("127.0.0.1", 0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def record(self, job):
        self.calls.append(job)
        return {"done": job.tool, "arguments": job.arguments}

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def executor():
    running = Executors("7c" * 32)
    yield running
    running.close()


def test_a_parked_call_is_carried_out_later(binary, provider, executor):
    with Proxy(
        policy=POLICY,
        upstream=provider.url,
        binary=binary,
        approval_timeout=1,
        executor_url=executor.url,
        executor_key="7c" * 32,
    ) as proxy:
        client = proxy.openai_client(agent="support-bot", max_retries=0, timeout=60)
        completion = ask(client, 'CALL stripe_refund {"amount": 750, "order": "A-17"}')
        [block] = blocked(completion)
        assert block.parked
        [parked] = proxy.admin.approvals().parked
        assert parked.parked and parked.arguments == {"amount": 750, "order": "A-17"}
        decision = proxy.admin.approve(parked, reason="customer called")
        assert decision.parked and decision.ran
        assert decision.output == {"done": "stripe_refund", "arguments": {"amount": 750, "order": "A-17"}}
        [job] = executor.calls
        assert (job.kind, job.id, job.by, job.agent, job.reason) == (
            "call",
            parked.id,
            "admin",
            "support-bot",
            "customer called",
        )
        assert "parked_call_ran" in [e.get("event") for e in proxy.audit()]


def test_rollback_through_the_executor(binary, provider, executor):
    with Proxy(
        policy=POLICY, upstream=provider.url, binary=binary, executor_url=executor.url, executor_key="7c" * 32
    ) as proxy:
        client = proxy.openai_client(agent="ops-bot", max_retries=0)
        request = [{"role": "user", "content": 'CALL create_ticket {"title": "Printer on fire"}'}]
        first = client.chat.completions.create(model=MODEL, tools=TOOLS, messages=request)
        [call] = first.choices[0].message.tool_calls
        # The agent ran the tool and sends its result back.
        client.chat.completions.create(
            model=MODEL,
            tools=TOOLS,
            messages=request
            + [
                first.choices[0].message.model_dump(exclude_none=True),
                {"role": "tool", "tool_call_id": call.id, "content": json.dumps({"id": 812})},
            ],
        )

        plan = proxy.admin.rollback(agent="ops-bot")
        [step] = plan.steps
        assert not plan.run and step.tool == "create_ticket" and step.result == {"id": 812}
        assert step.undo == {"tool": "close_ticket", "arguments": {"id": 812}}
        assert executor.calls == []

        done = proxy.admin.rollback(agent="ops-bot", since="1h", run=True)
        assert done.run and done.undone == 1 and not done.failed
        assert done.steps[0].outcome == "undone"
        [job] = executor.calls
        assert (job.kind, job.tool, job.arguments, job.id) == ("undo", "close_ticket", {"id": 812}, step.id)
        assert job.undoes["tool"] == "create_ticket"

        again = proxy.admin.rollback(ids=[step.id], run=True)
        assert again.steps[0].outcome == "already_undone" and len(executor.calls) == 1


def test_a_signed_alert_verifies(binary, provider):
    alert_key = "9d" * 32
    received = []
    arrived = threading.Event()

    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("content-length") or 0))
            received.append((body, self.headers))
            self.send_response(204)
            self.end_headers()
            arrived.set()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    hook = f"http://127.0.0.1:{server.server_address[1]}/hook"
    try:
        with Proxy(
            policy=POLICY, upstream=provider.url, binary=binary, env={"ALERT_URL": hook, "ALERT_KEY": alert_key}
        ) as proxy:
            client = proxy.openai_client(agent="support-bot", max_retries=0, timeout=60)
            with ThreadPoolExecutor(1) as pool:
                waiting = pool.submit(ask, client, 'CALL stripe_refund {"amount": 900}')
                held = proxy.admin.wait_for_held(timeout=20)
                assert arrived.wait(10)
                proxy.admin.deny(held)
                waiting.result(30)
    finally:
        server.shutdown()
        server.server_close()
    body, headers = received[0]
    verify(alert_key, body, headers)
    alert = json.loads(body)
    assert (alert["kind"], alert["approval_id"], alert["tool"]) == ("held", held.id, "stripe_refund")


def test_a_bad_policy_stops_the_proxy(binary, provider, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nrules: [nonsense\n", encoding="utf-8")
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="stopped at start"):
        Proxy(policy=str(bad), upstream=provider.url, binary=binary).start()
    assert time.monotonic() - started < 15
