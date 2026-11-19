"""Run the real database demo through the proxy, without and with the policy,
and record every line the agent prints with the time it appeared.

    cargo build --bins --examples
    python docs/demo_capture.py      # writes docs/demo_capture.json
    python docs/demo_render.py       # writes docs/demo.svg

Needs GROQ_API_KEY in the environment or in .env, as the demo agent does.
Never prints the key: the agent reads it itself, and the proxy's output and
audit log go to a temporary folder.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
EXE = ".exe" if os.name == "nt" else ""
PROXY = os.path.join(REPO, "target", "debug", "razorwire" + EXE)
AGENT = os.path.join(REPO, "target", "debug", "examples", "demo_agent" + EXE)
WORK = tempfile.mkdtemp(prefix="razorwire-demo-")
DROP = ("POLICY_FILE", "KEYS_FILE", "AUDIT_KEY", "UPSTREAM_API_KEY", "LISTEN_ADDR", "TLS_CERT",
        "TLS_KEY", "EXECUTOR_URL", "EXECUTOR_KEY", "STREAM_MODE", "AUDIT_LOG")


def clean_env():
    env = {k: v for k, v in os.environ.items()
           if k not in DROP and not k.startswith(("ALERT_", "RAZORWIRE_"))}
    return env


def wait_healthy(port, seconds=20):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as r:
                if r.status == 200:
                    return
        except OSError:
            time.sleep(0.2)
    raise SystemExit(f"proxy on {port} did not come up")


def run(mode, port):
    env = clean_env()
    env["UPSTREAM_URL"] = "https://api.groq.com/openai"
    env["LISTEN_ADDR"] = f"127.0.0.1:{port}"
    env["AUDIT_LOG"] = os.path.join(WORK, f"audit_{mode}.jsonl")
    if mode == "on":
        env["POLICY_FILE"] = os.path.join(REPO, "policy", "example.policy.yaml")
    log = open(os.path.join(WORK, f"proxy_{mode}.log"), "wb")
    proxy = subprocess.Popen([PROXY], cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        wait_healthy(port)
        agent_env = clean_env()
        agent_env["AGENT_BASE_URL"] = f"http://127.0.0.1:{port}/v1"
        start = time.monotonic()
        agent = subprocess.Popen([AGENT], cwd=REPO, env=agent_env, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, encoding="utf-8")
        lines = []
        assert agent.stdout is not None
        for raw in agent.stdout:
            lines.append({"t": round(time.monotonic() - start, 3), "text": raw.rstrip("\n")})
        err = agent.stderr.read() if agent.stderr else ""
        code = agent.wait()
        return {"mode": mode, "exit": code, "stderr": err.strip()[:300], "lines": lines}
    finally:
        proxy.terminate()
        proxy.wait(timeout=10)
        log.close()


def good(result):
    text = "\n".join(line["text"] for line in result["lines"])
    if result["mode"] == "off":
        return "production: DELETED" in text and "staging: DELETED" in text
    return ("production: still there" in text and "staging: DELETED" in text
            and "[razorwire] Blocked tool call" in text)


def main():
    out = {}
    for mode, port in (("off", 18081), ("on", 18082)):
        for attempt in range(1, 4):
            result = run(mode, port)
            result["attempt"] = attempt
            print(f"{mode}: attempt {attempt}, exit {result['exit']}, {len(result['lines'])} lines,"
                  f" {'as expected' if good(result) else 'NOT as expected'}")
            if result["stderr"]:
                print(f"  stderr: {result['stderr']}")
            if good(result):
                break
        out[mode] = result
    with open(os.path.join(HERE, "demo_capture.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    for mode in ("off", "on"):
        print(f"\n== {mode}")
        for line in out[mode]["lines"]:
            print(f"{line['t']:7.2f}  {line['text']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
