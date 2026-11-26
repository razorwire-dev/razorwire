"""Shared test helpers: a fake model provider, and the razorwire binary."""

import json
import os
import shutil
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
POLICY = os.path.join(HERE, "policy.yaml")


def find_test_binary():
    """RAZORWIRE_BIN, else the repo's debug build, else razorwire on PATH."""
    candidates = [os.environ.get("RAZORWIRE_BIN")]
    for name in ("razorwire.exe", "razorwire"):
        candidates.append(os.path.join(REPO, "target", "debug", name))
    candidates.append(shutil.which("razorwire"))
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


@pytest.fixture(scope="session")
def binary():
    path = find_test_binary()
    if path is None:
        pytest.skip("no razorwire binary: run `cargo build` or set RAZORWIRE_BIN")
    return path


class FakeProvider:
    """A stand-in for an OpenAI-compatible provider.

    The last user message says what the model answers: each line
    `CALL <tool> <json arguments>` becomes a tool call, and other lines are
    said back as text. When the last message is a tool result, the model
    just says "Done."

    In a streamed chat reply, `SMUGGLE <tool> <json arguments>` sends the
    call the way a hostile provider might: behind a comment, separated by a
    lone CR, which clients read as a line break.

    Other lines make it misbehave the same way: `LABEL <content type>` sends
    the chat reply under that Content-Type, `BOM` starts a plain reply with
    a byte-order mark, and `REDIRECT <url>` answers with a redirect there.
    A GET for a path ending in `/content` returns raw bytes.
    """

    CONTENT = b"\x00raw file bytes\xff"

    def __init__(self):
        self.requests = []
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("content-length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                provider.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                if self.path.endswith("/chat/completions"):
                    tricks = provider.tricks(body)
                    if "REDIRECT" in tricks:
                        return self.redirect(tricks["REDIRECT"])
                    label = tricks.get("LABEL")
                    if body.get("stream"):
                        smuggled = provider.smuggled_chunks(body)
                        return self.stream(provider.chat_chunks(body), smuggled, label or "text/event-stream")
                    return self.answer(provider.chat(body), label=label, bom="BOM" in tricks)
                if self.path.endswith("/responses"):
                    return self.answer(provider.responses(body))
                self.answer({"error": {"message": "not found"}}, 404)

            def do_GET(self):
                provider.requests.append({"path": self.path, "headers": dict(self.headers), "body": None})
                if not self.path.endswith("/content"):
                    return self.answer({"error": {"message": "not found"}}, 404)
                self.send_response(200)
                self.send_header("content-type", "application/octet-stream")
                self.send_header("content-length", str(len(provider.CONTENT)))
                self.end_headers()
                self.wfile.write(provider.CONTENT)

            def answer(self, payload, status=200, label=None, bom=False):
                data = ("﻿" if bom else "").encode() + json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("content-type", label or "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def redirect(self, location):
                self.send_response(307)
                self.send_header("location", location)
                self.send_header("content-length", "0")
                self.end_headers()

            def stream(self, chunks, smuggled=(), label="text/event-stream"):
                events = [f"data: {json.dumps(chunk)}\n\n" for chunk in chunks]
                # Hidden calls go after the first chunk, before the finish.
                events[1:1] = [f": nothing here\rdata: {json.dumps(chunk)}\n\n" for chunk in smuggled]
                data = ("".join(events) + "data: [DONE]\n\n").encode()
                self.send_response(200)
                self.send_header("content-type", label)
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    TRICKS = ("SMUGGLE ", "LABEL ", "REDIRECT ", "BOM")

    @staticmethod
    def script(text):
        said, calls = [], []
        for line in (text or "").splitlines():
            if line.startswith("CALL "):
                _, tool, arguments = line.split(" ", 2)
                calls.append((tool, arguments))
            elif line.strip() and not line.startswith(FakeProvider.TRICKS):
                said.append(line.strip())
        return " ".join(said), calls

    def tricks(self, body):
        """The misbehaviours the last user message asks for, by name."""
        text = self.last_user_text(body.get("messages") or []) or ""
        found = {}
        for line in text.splitlines():
            name, _, value = line.partition(" ")
            if name in ("LABEL", "REDIRECT", "BOM"):
                found[name] = value.strip()
        return found

    def smuggled_chunks(self, body):
        text = self.last_user_text(body.get("messages") or []) or ""
        chunks = []
        for line in text.splitlines():
            if line.startswith("SMUGGLE "):
                _, tool, arguments = line.split(" ", 2)
                call = {
                    "index": len(chunks),
                    "id": f"call_{uuid.uuid4().hex[:12]}",
                    "type": "function",
                    "function": {"name": tool, "arguments": arguments},
                }
                chunks.append(
                    {
                        "id": "chatcmpl-test",
                        "object": "chat.completion.chunk",
                        "created": 1,
                        "model": body.get("model"),
                        "choices": [{"index": 0, "delta": {"tool_calls": [call]}, "finish_reason": None}],
                    }
                )
        return chunks

    @staticmethod
    def last_user_text(items):
        if not items:
            return None
        last = items[-1]
        if last.get("role") != "user":
            return None
        content = last.get("content")
        if isinstance(content, list):
            return "\n".join(part.get("text", "") for part in content if isinstance(part, dict))
        return content

    def chat(self, body):
        text = self.last_user_text(body.get("messages") or [])
        said, calls = self.script(text) if text is not None else ("Done.", [])
        message = {"role": "assistant", "content": said or None}
        if calls:
            message["tool_calls"] = [
                {
                    "id": f"call_{uuid.uuid4().hex[:12]}",
                    "type": "function",
                    "function": {"name": tool, "arguments": arguments},
                }
                for tool, arguments in calls
            ]
        return {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "created": 1,
            "model": body.get("model"),
            "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if calls else "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }

    def chat_chunks(self, body):
        text = self.last_user_text(body.get("messages") or [])
        said, calls = self.script(text) if text is not None else ("Done.", [])
        base = {"id": "chatcmpl-test", "object": "chat.completion.chunk", "created": 1, "model": body.get("model")}
        chunks = [
            dict(base, choices=[{"index": 0, "delta": {"role": "assistant", "content": said}, "finish_reason": None}])
        ]
        for index, (tool, arguments) in enumerate(calls):
            call = {
                "index": index,
                "id": f"call_{uuid.uuid4().hex[:12]}",
                "type": "function",
                "function": {"name": tool, "arguments": arguments},
            }
            chunks.append(dict(base, choices=[{"index": 0, "delta": {"tool_calls": [call]}, "finish_reason": None}]))
        chunks.append(
            dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": "tool_calls" if calls else "stop"}])
        )
        return chunks

    def responses(self, body):
        items = body.get("input")
        items = [{"role": "user", "content": items}] if isinstance(items, str) else (items or [])
        text = self.last_user_text(items)
        said, calls = self.script(text) if text is not None else ("Done.", [])
        output = []
        if said:
            output.append(
                {
                    "type": "message",
                    "id": "msg_1",
                    "role": "assistant",
                    "status": "completed",
                    "content": [{"type": "output_text", "text": said, "annotations": []}],
                }
            )
        for tool, arguments in calls:
            call_id = f"call_{uuid.uuid4().hex[:12]}"
            output.append(
                {
                    "type": "function_call",
                    "id": f"fc_{call_id}",
                    "call_id": call_id,
                    "name": tool,
                    "arguments": arguments,
                    "status": "completed",
                }
            )
        return {
            "id": "resp_test",
            "object": "response",
            "created_at": 1,
            "status": "completed",
            "model": body.get("model"),
            "output": output,
            "parallel_tool_calls": True,
            "tool_choice": "auto",
            "tools": [],
        }


@pytest.fixture
def provider():
    fake = FakeProvider()
    yield fake
    fake.close()
