"""Check that a request really came from Razorwire.

Razorwire signs what it sends to an executor, and JSON alerts when
ALERT_KEY is set, in two headers:

    x-razorwire-timestamp: milliseconds since 1970
    x-razorwire-signature: v1=<hex HMAC-SHA256 of "<timestamp>.<body>">

    from razorwire import verify, SignatureError

    try:
        verify(os.environ["ALERT_KEY"], body, request.headers)
    except SignatureError:
        return 401
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Mapping
from typing import Any, Dict, Optional, Union

TIMESTAMP_HEADER = "x-razorwire-timestamp"
SIGNATURE_HEADER = "x-razorwire-signature"
MIN_KEY_BYTES = 32
DEFAULT_MAX_AGE = 300.0

Key = Union[str, bytes]


class SignatureError(Exception):
    """The request is not signed with this key, or the signature is too old."""


def key_bytes(key: Key) -> bytes:
    """A hex key, as `razorwire new-executor-key` and `new-alert-key` print it."""
    if isinstance(key, bytes):
        raw = key
    else:
        try:
            raw = bytes.fromhex(key.strip())
        except ValueError:
            raise ValueError("the key must be hex, as razorwire new-executor-key prints it") from None
    if len(raw) < MIN_KEY_BYTES:
        raise ValueError(f"the key must be at least {MIN_KEY_BYTES} bytes ({MIN_KEY_BYTES * 2} hex characters)")
    return raw


def sign(key: Key, body: Union[bytes, str], timestamp_ms: Optional[int] = None) -> Dict[str, str]:
    """The two headers Razorwire would send with `body`."""
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)
    timestamp = str(int(timestamp_ms))
    return {
        TIMESTAMP_HEADER: timestamp,
        SIGNATURE_HEADER: "v1=" + _mac(key_bytes(key), timestamp, _bytes(body)),
    }


def verify(
    key: Key,
    body: Union[bytes, str],
    headers: Any,
    *,
    max_age: float = DEFAULT_MAX_AGE,
    now_ms: Optional[int] = None,
) -> None:
    """Raise SignatureError unless `body` was signed with `key` in the last `max_age` seconds.

    `body` must be the raw bytes received, before any JSON parsing.
    `headers` is any mapping of the request's headers, in any letter case.
    """
    secret = key_bytes(key)
    timestamp = (_header(headers, TIMESTAMP_HEADER) or "").strip()
    signature = (_header(headers, SIGNATURE_HEADER) or "").strip()
    if not (timestamp.isascii() and timestamp.isdigit()) or len(timestamp) > 20:
        raise SignatureError(f"missing or malformed {TIMESTAMP_HEADER}")
    if not signature.startswith("v1="):
        raise SignatureError(f"missing or malformed {SIGNATURE_HEADER}")
    now = int(time.time() * 1000) if now_ms is None else now_ms
    if abs(now - int(timestamp)) > max_age * 1000:
        raise SignatureError("the signature is too old, or the clocks disagree")
    expected = _mac(secret, timestamp, _bytes(body))
    if not hmac.compare_digest(expected.encode(), signature[3:].encode()):
        raise SignatureError("the signature does not match")


def _mac(key: bytes, timestamp: str, body: bytes) -> str:
    return hmac.new(key, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


def _bytes(body: Union[bytes, str]) -> bytes:
    return body.encode("utf-8") if isinstance(body, str) else bytes(body)


def _header(headers: Any, name: str) -> Optional[str]:
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
