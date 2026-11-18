"""Point an agent at Razorwire.

    import razorwire

    client = razorwire.openai_client()     # an openai.OpenAI that talks to the proxy

The proxy's address comes from RAZORWIRE_URL (default
http://127.0.0.1:8080) and the agent's key from RAZORWIRE_AGENT_KEY. Without
a key, the OpenAI SDK sends OPENAI_API_KEY as usual, which is right when the
proxy has no agent keys set up.

Any framework that takes an OpenAI-compatible base URL works the same way:

    ChatOpenAI(base_url=razorwire.base_url(), api_key=os.environ["RAZORWIRE_AGENT_KEY"])
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

from ._urls import check_url, proxy_url

AGENT_NAME_HEADER = "x-agent-name"


def base_url(url: Optional[str] = None) -> str:
    """The proxy's OpenAI-compatible base URL, such as http://127.0.0.1:8080/v1."""
    return proxy_url(url) + "/v1"


def openai_client(
    *,
    url: Optional[str] = None,
    key: Optional[str] = None,
    agent: Optional[str] = None,
    allow_plain_http: bool = False,
    **kwargs: Any,
) -> Any:
    """An `openai.OpenAI` client that talks to Razorwire.

    url:   the proxy, default RAZORWIRE_URL or http://127.0.0.1:8080
    key:   the agent's rw_ key, default RAZORWIRE_AGENT_KEY. Without one,
           the OpenAI SDK's own api_key or OPENAI_API_KEY is sent.
    agent: the agent's name, sent as x-agent-name. Only used when the proxy
           has no agent keys; with keys, the name comes from the key.
    allow_plain_http: let a key go over plain http to another machine,
           for a private network you trust. Off by default.

    Other keyword arguments go to `openai.OpenAI`.
    """
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("openai_client() needs the openai package: pip install openai") from None
    return OpenAI(**client_arguments(url, key, agent, allow_plain_http, kwargs))


def async_openai_client(
    *,
    url: Optional[str] = None,
    key: Optional[str] = None,
    agent: Optional[str] = None,
    allow_plain_http: bool = False,
    **kwargs: Any,
) -> Any:
    """The same as `openai_client()`, for `openai.AsyncOpenAI`."""
    try:
        from openai import AsyncOpenAI
    except ImportError:
        raise ImportError("async_openai_client() needs the openai package: pip install openai") from None
    return AsyncOpenAI(**client_arguments(url, key, agent, allow_plain_http, kwargs))


def client_arguments(
    url: Optional[str],
    key: Optional[str],
    agent: Optional[str],
    allow_plain_http: bool,
    kwargs: Dict[str, Any],
) -> Dict[str, Any]:
    """The keyword arguments for an OpenAI client that talks to Razorwire."""
    if "base_url" in kwargs:
        raise TypeError("pass the proxy as url=, not base_url=")
    root = proxy_url(url)
    check_url(root, "RAZORWIRE_URL", allow_plain_http)
    arguments = dict(kwargs)
    arguments["base_url"] = root + "/v1"
    if "api_key" in kwargs:
        if key is not None:
            raise TypeError("pass the agent's key as key= or api_key=, not both")
    else:
        if key is None:
            key = os.environ.get("RAZORWIRE_AGENT_KEY")
        if key and key.strip():
            arguments["api_key"] = key.strip()
    if agent:
        headers = dict(arguments.get("default_headers") or {})
        headers[AGENT_NAME_HEADER] = agent
        arguments["default_headers"] = headers
    return arguments
