import pytest

import razorwire
from razorwire.agent import client_arguments

KEY = "rw_" + "b2" * 32


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("RAZORWIRE_URL", "RAZORWIRE_AGENT_KEY"):
        monkeypatch.delenv(name, raising=False)


def test_base_url(monkeypatch):
    assert razorwire.base_url() == "http://127.0.0.1:8080/v1"
    assert razorwire.base_url("https://rw.example.com/") == "https://rw.example.com/v1"
    monkeypatch.setenv("RAZORWIRE_URL", "https://rw.example.com:8443")
    assert razorwire.base_url() == "https://rw.example.com:8443/v1"


def test_client_arguments(monkeypatch):
    assert client_arguments(None, None, None, False, {}) == {"base_url": "http://127.0.0.1:8080/v1"}
    monkeypatch.setenv("RAZORWIRE_AGENT_KEY", KEY + "\n")
    arguments = client_arguments(None, None, "support-bot", False, {"timeout": 30, "default_headers": {"x-team": "a"}})
    assert arguments == {
        "base_url": "http://127.0.0.1:8080/v1",
        "api_key": KEY,
        "timeout": 30,
        "default_headers": {"x-team": "a", "x-agent-name": "support-bot"},
    }
    # An api_key given outright wins over the environment.
    assert client_arguments(None, None, None, False, {"api_key": "sk-x"})["api_key"] == "sk-x"
    with pytest.raises(TypeError):
        client_arguments(None, KEY, None, False, {"api_key": "sk-x"})
    with pytest.raises(TypeError):
        client_arguments(None, None, None, False, {"base_url": "https://api.openai.com/v1"})


def test_keys_are_not_sent_in_the_clear():
    with pytest.raises(ValueError, match="https"):
        client_arguments("http://razorwire:8080", KEY, None, False, {})
    allowed = client_arguments("http://razorwire:8080", KEY, None, True, {})
    assert allowed["base_url"] == "http://razorwire:8080/v1"


def test_openai_clients():
    pytest.importorskip("openai")
    client = razorwire.openai_client(key=KEY, agent="support-bot")
    assert str(client.base_url).rstrip("/") == "http://127.0.0.1:8080/v1"
    assert client.api_key == KEY
    assert client.default_headers["x-agent-name"] == "support-bot"
    async_client = razorwire.async_openai_client(key=KEY)
    assert async_client.api_key == KEY
