"""Run Razorwire on this machine, for tests and demos.

    from razorwire import Proxy

    with Proxy(policy="policy.yaml", upstream="https://api.groq.com/openai",
               upstream_key=os.environ["GROQ_API_KEY"]) as proxy:
        client = proxy.openai_client(agent="support-bot")
        reply = client.chat.completions.create(...)
        held = proxy.admin.wait_for_held(tool="stripe_refund")
        proxy.admin.deny(held, reason="not in a test")

It starts the `razorwire` binary (from `binary=`, RAZORWIRE_BIN or PATH) on
a free port on 127.0.0.1, in a fresh folder with its own keys file and audit
log, and stops it again on exit. Settings in your environment that
Razorwire reads are not passed on, so a test sees only what it asks for.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, List, Optional

from .admin import Admin
from .agent import openai_client

_KEY = re.compile(r"\b(rw_[0-9a-f]{64})\b")
# Settings Razorwire reads, besides every ALERT_* and RAZORWIRE_* one.
_SETTINGS = {
    "UPSTREAM_URL",
    "UPSTREAM_API_KEY",
    "LISTEN_ADDR",
    "POLICY_FILE",
    "KEYS_FILE",
    "AUDIT_LOG",
    "AUDIT_KEY",
    "APPROVAL_TIMEOUT_SECS",
    "TLS_CERT",
    "TLS_KEY",
    "STREAM_MODE",
    "EXECUTOR_URL",
    "EXECUTOR_KEY",
}


def find_binary(binary: Optional[str] = None) -> str:
    """The razorwire binary: `binary`, else RAZORWIRE_BIN, else razorwire on PATH."""
    path = binary or os.environ.get("RAZORWIRE_BIN") or shutil.which("razorwire")
    if not path or not os.path.isfile(path):
        raise FileNotFoundError(
            "Razorwire is not installed. Install it (see the README), or set RAZORWIRE_BIN to the razorwire binary."
        )
    return path


class Proxy:
    def __init__(
        self,
        *,
        policy: Optional[str] = None,
        upstream: str = "https://api.openai.com",
        upstream_key: Optional[str] = None,
        agents: Iterable[str] = (),
        approval_timeout: Optional[int] = None,
        stream_mode: Optional[str] = None,
        executor_url: Optional[str] = None,
        executor_key: Optional[str] = None,
        signed_log: bool = True,
        env: Optional[Dict[str, str]] = None,
        binary: Optional[str] = None,
        workdir: Optional[str] = None,
        startup_timeout: float = 20.0,
    ):
        """
        policy:       a policy file. None runs in log-only mode.
        upstream:     the provider, such as https://api.groq.com/openai.
        upstream_key: the provider key the proxy sends for every agent.
        agents:       names to give agent keys. With none, any caller may use
                      the proxy and its x-agent-name is trusted.
        signed_log:   sign the audit log with a fresh AUDIT_KEY.
        env:          more settings, such as {"ALERT_URL": ...}.
        workdir:      a folder to keep the keys, log and output in. Default:
                      a temporary one, removed on stop().

        An admin key named "admin" is always made, so `admin` works and
        review rules hold calls for a decision.
        """
        self._binary = find_binary(binary)
        self._policy = os.path.abspath(policy) if policy else None
        self._upstream = upstream
        self._upstream_key = upstream_key
        self._agent_names = list(agents)
        self._approval_timeout = approval_timeout
        self._stream_mode = stream_mode
        self._executor = (executor_url, executor_key)
        self._signed_log = signed_log
        self._extra = dict(env or {})
        self._startup_timeout = startup_timeout
        self._workdir = workdir
        self._temp: Optional[tempfile.TemporaryDirectory[str]] = None
        self._process: Optional[subprocess.Popen[bytes]] = None
        self._output: Any = None
        self._agent_keys: Dict[str, str] = {}
        self._admin: Optional[Admin] = None
        self.url = ""
        """The proxy's address, http://127.0.0.1:<port>."""
        self.audit_key: Optional[str] = None

    def __enter__(self) -> Proxy:
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    @property
    def base_url(self) -> str:
        """The OpenAI-compatible base URL, for any client or framework."""
        return self.url + "/v1"

    @property
    def admin(self) -> Admin:
        """An admin client with the proxy's admin key."""
        if self._admin is None:
            raise RuntimeError("the proxy is not running")
        return self._admin

    @property
    def folder(self) -> str:
        if self._workdir is None:
            raise RuntimeError("the proxy is not running")
        return self._workdir

    @property
    def audit_log(self) -> str:
        return os.path.join(self.folder, "audit.jsonl")

    def agent_key(self, name: str) -> str:
        """The rw_ key made for an agent named in `agents`."""
        try:
            return self._agent_keys[name]
        except KeyError:
            raise KeyError(f"no key was made for {name!r}; name it in agents=") from None

    def openai_client(self, agent: Optional[str] = None, **kwargs: Any) -> Any:
        """An openai.OpenAI client for this proxy, as `agent`.

        With agent keys, it uses that agent's key. Without, it sends the name
        as x-agent-name, and a placeholder API key when none is given (the
        proxy replaces it when upstream_key is set).
        """
        if agent is not None and self._agent_keys:
            kwargs["api_key"] = self.agent_key(agent)
        elif "api_key" not in kwargs:
            kwargs["api_key"] = os.environ.get("OPENAI_API_KEY") or "razorwire-local"
        return openai_client(url=self.url, agent=agent, **kwargs)

    def audit(self) -> List[Dict[str, Any]]:
        """Every event in the audit log so far."""
        if not os.path.exists(self.audit_log):
            return []
        with open(self.audit_log, encoding="utf-8") as log:
            return [json.loads(line) for line in log if line.strip()]

    def output(self) -> str:
        """What the proxy printed so far. Keys are never printed."""
        path = os.path.join(self.folder, "razorwire.out")
        if not os.path.exists(path):
            return ""
        with open(path, encoding="utf-8", errors="replace") as out:
            return out.read()

    def start(self) -> Proxy:
        if self._process is not None:
            return self
        if self._workdir is None:
            self._temp = tempfile.TemporaryDirectory(prefix="razorwire-")
            self._workdir = self._temp.name
        os.makedirs(self._workdir, exist_ok=True)
        keys = os.path.join(self._workdir, "razorwire.keys")
        if os.path.exists(keys):
            os.remove(keys)
        admin_key = self._new_key("admin", "admin", keys)
        self._agent_keys = {name: self._new_key("agent", name, keys) for name in self._agent_names}

        port = _free_port()
        self.url = f"http://127.0.0.1:{port}"
        env = {
            name: value
            for name, value in os.environ.items()
            if name.upper() not in _SETTINGS and not name.upper().startswith(("ALERT_", "RAZORWIRE_"))
        }
        env.update(
            LISTEN_ADDR=f"127.0.0.1:{port}",
            UPSTREAM_URL=self._upstream,
            KEYS_FILE=keys,
            AUDIT_LOG=os.path.join(self._workdir, "audit.jsonl"),
        )
        if self._policy:
            env["POLICY_FILE"] = self._policy
        if self._upstream_key:
            env["UPSTREAM_API_KEY"] = self._upstream_key
        if self._approval_timeout is not None:
            env["APPROVAL_TIMEOUT_SECS"] = str(self._approval_timeout)
        if self._stream_mode:
            env["STREAM_MODE"] = self._stream_mode
        executor_url, executor_key = self._executor
        if executor_url or executor_key:
            env["EXECUTOR_URL"] = executor_url or ""
            env["EXECUTOR_KEY"] = executor_key or ""
        if self._signed_log:
            self.audit_key = secrets.token_hex(32)
            env["AUDIT_KEY"] = self.audit_key
        env.update(self._extra)

        # Kept open while the proxy runs; stop() closes it.
        self._output = open(os.path.join(self._workdir, "razorwire.out"), "w", encoding="utf-8")  # noqa: SIM115
        self._process = subprocess.Popen(
            [self._binary, "serve"],
            env=env,
            cwd=self._workdir,
            stdin=subprocess.DEVNULL,
            stdout=self._output,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + self._startup_timeout
        while True:
            if self._process.poll() is not None:
                output = self.output()
                self.stop()
                raise RuntimeError(f"Razorwire stopped at start:\n{output.strip()}")
            if _healthy(self.url):
                break
            if time.monotonic() > deadline:
                output = self.output()
                self.stop()
                raise RuntimeError(f"Razorwire did not come up in time:\n{output.strip()}")
            time.sleep(0.05)
        self._admin = Admin(self.url, admin_key)
        return self

    def stop(self) -> None:
        process, self._process = self._process, None
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if self._output is not None:
            self._output.close()
            self._output = None
        self._admin = None
        if self._temp is not None:
            self._temp.cleanup()
            self._temp = None
            self._workdir = None

    def _new_key(self, role: str, name: str, keys: str) -> str:
        env = {key: value for key, value in os.environ.items() if not key.upper().startswith("RAZORWIRE_")}
        env["KEYS_FILE"] = keys
        done = subprocess.run(
            [self._binary, "new-key", role, name],
            env=env,
            cwd=self._workdir,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        match = _KEY.search(done.stdout)
        if done.returncode != 0 or match is None:
            raise RuntimeError(f"razorwire new-key {role} {name} failed: {done.stderr.strip()}")
        return match.group(1)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _healthy(url: str) -> bool:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url + "/healthz", timeout=1) as response:
            return bool(response.status == 200)
    except (urllib.error.URLError, OSError):
        return False
