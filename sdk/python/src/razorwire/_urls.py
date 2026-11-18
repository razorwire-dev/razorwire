"""Where the proxy is, and whether a key may be sent there."""

from __future__ import annotations

import ipaddress
import os
from typing import Optional
from urllib.parse import urlsplit

DEFAULT_URL = "http://127.0.0.1:8080"
KEY_PREFIX = "rw_"


def is_loopback_host(host: Optional[str]) -> bool:
    """True for localhost and loopback addresses, the same test the proxy uses."""
    if not host:
        return False
    host = host.strip("[]")
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def proxy_url(url: Optional[str] = None) -> str:
    """The proxy's address: `url`, else RAZORWIRE_URL, else http://127.0.0.1:8080."""
    value = url if url is not None else os.environ.get("RAZORWIRE_URL", "")
    return (value.strip() or DEFAULT_URL).rstrip("/")


def check_url(url: str, setting: str, allow_plain_http: bool = False) -> None:
    """Refuse an address a key should not be sent to.

    Plain http is only allowed to this machine, unless `allow_plain_http`,
    because the key in each request could otherwise be read on the network.
    The URL is never repeated in the error, in case it carries a secret.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"{setting} is not an http or https URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError(f"{setting} must not carry a user name or password")
    if parts.scheme == "http" and not allow_plain_http and not is_loopback_host(parts.hostname):
        raise ValueError(
            f"{setting} must use https unless it points at this machine, or the key would cross the network unencrypted"
        )


def shown_url(url: str) -> str:
    """Scheme, host and port only, for messages."""
    parts = urlsplit(url)
    host = parts.hostname or "?"
    if ":" in host:
        host = f"[{host}]"
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{host}{port}"
