from __future__ import annotations

from typing import Any

from silent_updater.llm.github_models_client import ChatResponse, ToolCall
from silent_updater.llm.tool_loop import ToolDispatcher, run_tool_loop


class FakeClient:
    def __init__(self, scripted: list[ChatResponse]):
        self.scripted = list(scripted)
        self.received_messages: list[list[dict]] = []

    def chat(self, messages: list[dict], tools: list[dict] | None) -> ChatResponse:
        self.received_messages.append([dict(m) for m in messages])
        return self.scripted.pop(0)


def _stop(text: str) -> ChatResponse:
    return ChatResponse(content=text, tool_calls=[], finish_reason="stop", raw={})


def _tool(name: str, args: str, call_id: str = "c1") -> ChatResponse:
    return ChatResponse(
        content="",
        tool_calls=[ToolCall(id=call_id, name=name, arguments=args)],
        finish_reason="tool_calls",
        raw={},
    )


def test_immediate_stop() -> None:
    client = FakeClient([_stop("done")])
    dispatcher = ToolDispatcher(handlers={}, schemas=[])
    result = run_tool_loop(client, "sys", "hello", dispatcher)
    assert result.final_content == "done"
    assert result.iterations == 1


def test_single_tool_then_stop() -> None:
    calls: list[dict] = []

    def my_tool(args: dict) -> dict:
        calls.append(args)
        return {"ok": True, "echo": args.get("x")}

    dispatcher = ToolDispatcher(handlers={"my_tool": my_tool}, schemas=[])
    client = FakeClient([
        _tool("my_tool", '{"x": 42}'),
        _stop("finished"),
    ])
    result = run_tool_loop(client, "sys", "go", dispatcher)
    assert calls == [{"x": 42}]
    assert result.final_content == "finished"
    assert result.iterations == 2


def test_unknown_tool_returns_error() -> None:
    dispatcher = ToolDispatcher(handlers={}, schemas=[])
    client = FakeClient([
        _tool("does_not_exist", "{}"),
        _stop("end"),
    ])
    result = run_tool_loop(client, "sys", "go", dispatcher)
    # The tool message must contain the error
    last_tool_msg = next(m for m in reversed(result.transcript) if m["role"] == "tool")
    assert "unknown tool" in last_tool_msg["content"]


def test_tool_exception_caught() -> None:
    def bad_tool(args: dict) -> dict:
        raise RuntimeError("oops")

    dispatcher = ToolDispatcher(handlers={"bad": bad_tool}, schemas=[])
    client = FakeClient([
        _tool("bad", "{}"),
        _stop("end"),
    ])
    result = run_tool_loop(client, "sys", "go", dispatcher)
    last_tool_msg = next(m for m in reversed(result.transcript) if m["role"] == "tool")
    assert "RuntimeError" in last_tool_msg["content"]


def test_iterations_exceeded() -> None:
    import pytest
    from silent_updater.llm.tool_loop import IterationsExceeded
    client = FakeClient([_tool("noop", "{}") for _ in range(10)])
    def noop(_a): return {"ok": True}
    dispatcher = ToolDispatcher(handlers={"noop": noop}, schemas=[])
    with pytest.raises(IterationsExceeded):
        run_tool_loop(client, "sys", "go", dispatcher, max_iterations=3)
