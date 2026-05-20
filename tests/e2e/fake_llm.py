from __future__ import annotations

import json
from typing import Any, Callable

from silent_updater.llm.github_models_client import ChatResponse, ToolCall


ScriptedStep = Callable[[list[dict]], ChatResponse]


def _stop(content: str = "done") -> ChatResponse:
    return ChatResponse(content=content, tool_calls=[], finish_reason="stop", raw={})


def tool_call(name: str, args: dict[str, Any] | None = None, call_id: str | None = None) -> ChatResponse:
    return ChatResponse(
        content="",
        tool_calls=[ToolCall(
            id=call_id or f"call-{name}",
            name=name,
            arguments=json.dumps(args or {}),
        )],
        finish_reason="tool_calls",
        raw={},
    )


class ScriptedLLM:
    """Returns the next scripted response on each .chat() call.

    Each step can either be a ChatResponse directly or a callable
    (messages) -> ChatResponse for conditional logic.
    """

    def __init__(self, steps: list[ChatResponse | ScriptedStep]):
        self.steps: list[ChatResponse | ScriptedStep] = list(steps)
        self.history: list[list[dict]] = []

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> ChatResponse:
        self.history.append([dict(m) for m in messages])
        if not self.steps:
            return _stop("(unexpected extra call — terminating)")
        step = self.steps.pop(0)
        if callable(step):
            return step(messages)
        return step
