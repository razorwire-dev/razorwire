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
    """

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
                    if body.get("stream"):
                        return self.stream(provider.chat_chunks(body))
                    return self.answer(provider.chat(body))
                if self.path.endswith("/responses"):
                    return self.answer(provider.responses(body))
                self.answer({"error": {"message": "not found"}}, 404)

            def answer(self, payload, status=200):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def stream(self, chunks):
                data = "".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks) + "data: [DONE]\n\n"
                data = data.encode()
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
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

    @staticmethod
    def script(text):
        said, calls = [], []
        for line in (text or "").splitlines():
            if line.startswith("CALL "):
                _, tool, arguments = line.split(" ", 2)
                calls.append((tool, arguments))
            elif line.strip():
                said.append(line.strip())
        return " ".join(said), calls

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
