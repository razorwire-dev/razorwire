import pytest

from razorwire import Block, blocked, blocked_count

DROP_NOTE = (
    '[razorwire] Blocked tool call "db_drop": Dropping the production database is blocked by policy. '
    "(rule: no-production-db-drop)"
)


def chat(content, tool_calls=None, finish="stop"):
    """A Chat Completions reply shaped as Razorwire leaves it."""
    message = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 1,
        "model": "openai/gpt-oss-120b",
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
    }


def test_a_note_after_the_models_text():
    staging = {
        "id": "call_2",
        "type": "function",
        "function": {"name": "db_drop", "arguments": '{"database": "staging"}'},
    }
    reply = chat(f"Dropping both now.\n\n{DROP_NOTE}", [staging], "tool_calls")
    [block] = blocked(reply)
    assert block == Block(
        tool="db_drop",
        message="Dropping the production database is blocked by policy.",
        rule="no-production-db-drop",
        outcome="blocked",
        choice=0,
        text=DROP_NOTE,
    )
    assert not block.parked


def test_several_notes_and_the_default_policy():
    other = '[razorwire] Blocked tool call "shell": No rule allows this tool. (default policy)'
    blocks = blocked(chat(f"{DROP_NOTE}\n{other}"))
    assert [b.tool for b in blocks] == ["db_drop", "shell"]
    assert blocks[1].rule is None
    assert blocks[1].message == "No rule allows this tool."


def test_held_calls_say_what_happened():
    held = "Refunds above 500 are held for human approval."
    denied = f'[razorwire] Blocked tool call "stripe_refund": {held} Denied by mann: wrong order. (rule: refund-cap)'
    plain_deny = f'[razorwire] Blocked tool call "stripe_refund": {held} Denied by ops.lead. (rule: refund-cap)'
    note = '[razorwire] Blocked tool call "stripe_refund": '
    expired = f"{note}{held} No one approved it within 300 seconds. (rule: refund-cap)"
    parked = (
        f"{note}{held} No one approved it within 300 seconds, so it is parked. If a person approves it "
        "later, Razorwire carries it out itself, so do not try it again. (rule: refund-cap)"
    )
    blocks = blocked(chat("\n".join([denied, plain_deny, expired, parked])))
    assert [(b.outcome, b.by) for b in blocks] == [
        ("denied", "mann"),
        ("denied", "ops.lead"),
        ("expired", None),
        ("parked", None),
    ]
    assert blocks[3].parked
    assert all(b.rule == "refund-cap" for b in blocks)


def test_responses_api_output():
    reply = {
        "id": "resp_1",
        "object": "response",
        "output": [
            {
                "type": "message",
                "id": "msg_1",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "Cleaning up.", "annotations": []}],
            },
            {
                "type": "message",
                "id": "msg_blocked_1",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": DROP_NOTE, "annotations": []}],
            },
            {"type": "function_call", "call_id": "call_2", "name": "db_drop", "arguments": "{}"},
        ],
    }
    [block] = blocked(reply)
    assert block.tool == "db_drop" and block.choice is None


def test_each_choice_is_numbered():
    reply = chat("fine")
    reply["choices"].append(
        {"index": 1, "message": {"role": "assistant", "content": DROP_NOTE}, "finish_reason": "stop"}
    )
    [block] = blocked(reply)
    assert block.choice == 1


def test_plain_text_and_conversations():
    assert blocked(f"streamed text\n\n{DROP_NOTE}")[0].tool == "db_drop"
    history = [
        {"role": "user", "content": DROP_NOTE},
        {"role": "assistant", "content": DROP_NOTE},
        {"role": "assistant", "content": [{"type": "text", "text": DROP_NOTE}]},
    ]
    # A user can paste a note; only the assistant's messages count.
    assert len(blocked(history)) == 2


def test_text_that_only_mentions_razorwire():
    assert blocked(chat("I saw [razorwire] Blocked tool call in the docs.")) == []
    assert blocked(chat(None)) == []
    assert blocked(chat("")) == []


def test_a_note_that_does_not_parse_is_still_reported():
    [block] = blocked('[razorwire] Blocked tool call "weird')
    assert block.tool == "unnamed" and block.outcome == "blocked"


def test_objects_from_the_openai_sdk():
    openai = pytest.importorskip("openai")
    from openai.types.chat import ChatCompletion

    reply = ChatCompletion.model_validate(chat(f"Dropping both now.\n\n{DROP_NOTE}"))
    assert blocked(reply)[0].rule == "no-production-db-drop"
    assert blocked(reply.choices[0].message)[0].tool == "db_drop"
    assert openai


def test_other_objects_are_refused():
    with pytest.raises(TypeError):
        blocked(42)


def test_blocked_count_reads_the_header():
    assert blocked_count({"X-Razorwire-Blocked": "2"}) == 2
    assert blocked_count({"x-razorwire-blocked": " 0 "}) == 0
    assert blocked_count({"content-type": "application/json"}) is None
    assert blocked_count({"x-razorwire-blocked": "lots"}) is None

    class Raw:
        def __init__(self):
            self.headers = {"x-razorwire-blocked": "1"}

    assert blocked_count(Raw()) == 1
