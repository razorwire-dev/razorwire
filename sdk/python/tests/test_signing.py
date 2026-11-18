import hashlib
import hmac
import time

import pytest

from razorwire import SIGNATURE_HEADER, TIMESTAMP_HEADER, SignatureError, sign, verify

KEY = "ab" * 32
BODY = b'{"kind":"undo","id":"und_000000000000000000000000","tool":"close_ticket","arguments":{"id":812}}'


def test_a_signature_razorwire_would_send():
    timestamp = "1763460000000"
    expected = hmac.new(bytes.fromhex(KEY), timestamp.encode() + b"." + BODY, hashlib.sha256).hexdigest()
    headers = sign(KEY, BODY, int(timestamp))
    assert headers == {TIMESTAMP_HEADER: timestamp, SIGNATURE_HEADER: f"v1={expected}"}
    verify(KEY, BODY, headers, now_ms=int(timestamp) + 1000)


def test_headers_in_any_case_and_str_bodies():
    headers = {name.title(): value for name, value in sign(KEY, BODY).items()}
    verify(KEY, BODY.decode(), headers)
    verify(bytes.fromhex(KEY), BODY, headers)


@pytest.mark.parametrize(
    "change",
    [
        lambda h, b: (h, b + b" "),
        lambda h, b: ({**h, SIGNATURE_HEADER: h[SIGNATURE_HEADER][:-1] + "0"}, b),
        lambda h, b: ({**h, SIGNATURE_HEADER: h[SIGNATURE_HEADER][3:]}, b),
        lambda h, b: ({TIMESTAMP_HEADER: h[TIMESTAMP_HEADER]}, b),
        lambda h, b: ({SIGNATURE_HEADER: h[SIGNATURE_HEADER]}, b),
        lambda h, b: ({**h, TIMESTAMP_HEADER: "١٢٣"}, b),
        lambda h, b: ({**h, TIMESTAMP_HEADER: str(int(h[TIMESTAMP_HEADER]) + 1)}, b),
    ],
)
def test_anything_changed_is_refused(change):
    headers, body = change(sign(KEY, BODY), BODY)
    with pytest.raises(SignatureError):
        verify(KEY, body, headers)


def test_another_key_is_refused():
    with pytest.raises(SignatureError):
        verify("cd" * 32, BODY, sign(KEY, BODY))


def test_old_and_future_signatures_are_refused():
    now = int(time.time() * 1000)
    with pytest.raises(SignatureError, match="too old"):
        verify(KEY, BODY, sign(KEY, BODY, now - 301_000))
    with pytest.raises(SignatureError, match="too old"):
        verify(KEY, BODY, sign(KEY, BODY, now + 301_000))
    verify(KEY, BODY, sign(KEY, BODY, now - 3_000_000), max_age=3600)


def test_weak_or_malformed_keys_are_refused():
    with pytest.raises(ValueError):
        sign("ab" * 16, BODY)
    with pytest.raises(ValueError):
        sign("not hex at all", BODY)
