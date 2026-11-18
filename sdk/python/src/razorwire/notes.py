"""Read what Razorwire blocked from the reply an agent got.

When Razorwire removes a tool call, it leaves a note in the assistant's
text instead, one line per call:

    [razorwire] Blocked tool call "db_drop": Production is off limits. (rule: no-production-db-drop)

`blocked()` finds these notes and returns them as `Block` objects, so an
agent can tell a blocked call from a model that chose not to call a tool.

The notes are text in the model's reply, so a model could write one itself.
Use them to steer the agent, not as proof. The `x-razorwire-blocked` header,
read by `blocked_count()`, comes from the proxy alone: it drops any
`x-razorwire-` header the provider sends.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, List, Optional

NOTE_PREFIX = "[razorwire] Blocked tool call"
BLOCKED_HEADER = "x-razorwire-blocked"

_NOTE = re.compile(
    r'^\[razorwire\] Blocked tool call "(?P<tool>.*?)": (?P<message>.*) '
    r"\((?:rule: (?P<rule>.*)|default policy)\)$"
)
_DENIED = re.compile(r"Denied by (?P<by>\S+?)(?::|\.)(?: |$)")


@dataclass(frozen=True)
class Block:
    """One tool call Razorwire removed from a reply."""

    tool: str
    """The tool the model asked for, or "unnamed"."""
    message: str
    """Why: the policy's message, and for a held call what happened to it."""
    rule: Optional[str]
    """The rule that decided, or None when the policy's default did."""
    outcome: str
    """"blocked" by a rule, or for a held call "denied", "expired" (nobody
    decided in time) or "parked" (it may still be approved and carried out
    later by the executor, so the agent must not retry it)."""
    by: Optional[str] = None
    """Who denied it, for a denied call."""
    choice: Optional[int] = None
    """Which choice of a Chat Completions reply it was in."""
    text: str = ""
    """The whole note, as it appears in the reply."""

    @property
    def parked(self) -> bool:
        return self.outcome == "parked"


def blocked(response: Any) -> List[Block]:
    """Every block note in a reply, in order.

    `response` can be what the OpenAI SDK returns (a ChatCompletion, a
    Responses API Response, a message), the same as a dict, a list of
    messages, or plain text, such as the text gathered from a stream.
    """
    found: List[Block] = []
    _collect(_as_data(response), None, found)
    return found


def blocked_count(response: Any) -> Optional[int]:
    """The `x-razorwire-blocked` header: how many calls were removed.

    Pass a raw response, from `client.chat.completions.with_raw_response
    .create(...)` for example, or its headers. None when the header is
    missing: nothing was removed, or the reply was a live stream, whose
    headers go out before it is checked. For a stream, read `blocked()` on
    its text instead.
    """
    headers = getattr(response, "headers", response)
    value = _header(headers, BLOCKED_HEADER)
    if value is None:
        return None
    value = value.strip()
    return int(value) if value.isascii() and value.isdigit() else None


def _as_data(value: Any) -> Any:
    if value is None or isinstance(value, (str, dict, list, tuple)):
        return value
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return dump()
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    if hasattr(value, "content"):
        return {"content": value.content}
    raise TypeError(f"cannot read block notes from {type(value).__name__}")


def _collect(data: Any, choice: Optional[int], found: List[Block]) -> None:
    if isinstance(data, str):
        found.extend(_from_text(data, choice))
    elif isinstance(data, (list, tuple)):
        for item in data:
            _collect(_as_data(item), choice, found)
    elif isinstance(data, dict):
        choices = data.get("choices")
        output = data.get("output")
        if isinstance(choices, list):
            for position, item in enumerate(choices):
                if not isinstance(item, dict):
                    continue
                index = item.get("index")
                index = index if isinstance(index, int) else position
                message = item.get("message")
                if isinstance(message, dict):
                    _from_content(message.get("content"), index, found)
        if isinstance(output, list):
            for item in output:
                if isinstance(item, dict) and item.get("type") == "message":
                    _from_content(item.get("content"), None, found)
        if choices is None and output is None and data.get("role", "assistant") == "assistant":
            _from_content(data.get("content"), choice, found)


def _from_content(content: Any, choice: Optional[int], found: List[Block]) -> None:
    if isinstance(content, str):
        found.extend(_from_text(content, choice))
    elif isinstance(content, list):
        for part in content:
            text = part.get("text") if isinstance(part, dict) else None
            if isinstance(text, str):
                found.extend(_from_text(text, choice))


def _from_text(text: str, choice: Optional[int]) -> List[Block]:
    blocks = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(NOTE_PREFIX):
            blocks.append(_parse(line, choice))
    return blocks


def _parse(line: str, choice: Optional[int]) -> Block:
    match = _NOTE.match(line)
    if match is None:
        message = line[len(NOTE_PREFIX) :].strip(' :"')
        return Block("unnamed", message, None, "blocked", None, choice, line)
    tool = match.group("tool") or "unnamed"
    message = match.group("message")
    outcome, by = "blocked", None
    denied = list(_DENIED.finditer(message))
    if "so it is parked" in message:
        outcome = "parked"
    elif denied:
        outcome, by = "denied", denied[-1].group("by")
    elif "No one approved it within" in message or "No decision was made" in message:
        outcome = "expired"
    return Block(tool, message, match.group("rule"), outcome, by, choice, line)


def _header(headers: Any, name: str) -> Optional[str]:
    if headers is None:
        return None
    get = getattr(headers, "get", None)
    if callable(get):
        value = get(name)
        if value is not None:
            return str(value)
    if isinstance(headers, Mapping):
        for key, value in headers.items():
            if isinstance(key, str) and key.lower() == name:
                return str(value)
    return None
