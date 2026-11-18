"""Razorwire for Python.

Razorwire is a proxy between an AI agent and its model provider that checks
every tool call against a policy before the agent can run it. This package
helps on both sides of it:

- Agents:   `openai_client()`, `base_url()`, and `blocked()` to see which
            calls were stopped and why.
- Admins:   `Admin`, for held calls, approvals, reloads and rollbacks.
- Executor: `Executor`, the service that carries out rollbacks and approved
            parked calls, with signatures and retries handled.
- Alerts:   `verify()`, to check a signed JSON alert.
- Tests:    `Proxy`, to run Razorwire with a policy inside a test.
"""

from ._version import __version__
from .admin import Admin, Approvals, Decision, HeldCall, RazorwireError, Rollback, RollbackStep
from .agent import async_openai_client, base_url, openai_client
from .executor import Executor, Job
from .notes import BLOCKED_HEADER, NOTE_PREFIX, Block, blocked, blocked_count
from .proxy import Proxy
from .signing import SIGNATURE_HEADER, TIMESTAMP_HEADER, SignatureError, sign, verify

__all__ = [
    "__version__",
    "Admin",
    "Approvals",
    "BLOCKED_HEADER",
    "Block",
    "Decision",
    "Executor",
    "HeldCall",
    "Job",
    "NOTE_PREFIX",
    "Proxy",
    "RazorwireError",
    "Rollback",
    "RollbackStep",
    "SIGNATURE_HEADER",
    "SignatureError",
    "TIMESTAMP_HEADER",
    "async_openai_client",
    "base_url",
    "blocked",
    "blocked_count",
    "openai_client",
    "sign",
    "verify",
]
