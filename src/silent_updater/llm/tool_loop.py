from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from silent_updater.llm.github_models_client import ChatClient, ToolCall


log = logging.getLogger(__name__)


class IterationsExceeded(RuntimeError):
    pass


class WallClockExceeded(RuntimeError):
    pass


ToolFn = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass
class ToolDispatcher:
    handlers: dict[str, ToolFn]
    schemas: list[dict[str, Any]]

    def invoke(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        fn = self.handlers.get(name)
        if fn is None:
            return {"error": f"unknown tool '{name}'"}
        try:
            return fn(args)
        except Exception as ex:
            log.exception("tool %s raised", name)
            return {"error": f"{type(ex).__name__}: {ex}"}


@dataclass
class LoopResult:
    final_content: str
    iterations: int
    transcript: list[dict[str, Any]]


def run_tool_loop(
    client: ChatClient,
    system_prompt: str,
    initial_user_message: str,
    dispatcher: ToolDispatcher,
    *,
    max_iterations: int = 100,
    wall_clock_seconds: float | None = 7200.0,
    transcript_log: Path | None = None,
) -> LoopResult:
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": initial_user_message},
    ]
    started = time.monotonic()
    log_file = open(transcript_log, "w", encoding="utf-8") if transcript_log else None
    try:
        for iteration in range(1, max_iterations + 1):
            if wall_clock_seconds is not None and time.monotonic() - started > wall_clock_seconds:
                raise WallClockExceeded(f"exceeded {wall_clock_seconds}s wall clock")
            resp = client.chat(messages, tools=dispatcher.schemas)
            _log(log_file, {"iteration": iteration, "assistant": resp.raw})
            assistant_msg: dict[str, Any] = {"role": "assistant", "content": resp.content or None}
            if resp.tool_calls:
                assistant_msg["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.name, "arguments": tc.arguments},
                    }
                    for tc in resp.tool_calls
                ]
            messages.append(assistant_msg)
            if not resp.tool_calls:
                return LoopResult(
                    final_content=resp.content,
                    iterations=iteration,
                    transcript=messages,
                )
            for tc in resp.tool_calls:
                args = _parse_args(tc.arguments)
                result = dispatcher.invoke(tc.name, args)
                tool_msg = {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": tc.name,
                    "content": json.dumps(result, ensure_ascii=False),
                }
                messages.append(tool_msg)
                _log(log_file, {"iteration": iteration, "tool_call": {
                    "name": tc.name, "args": args, "result": result,
                }})
        raise IterationsExceeded(f"exceeded {max_iterations} iterations")
    finally:
        if log_file:
            log_file.close()


def _parse_args(raw: str) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
        return {"_value": parsed}
    except json.JSONDecodeError:
        return {"_raw": raw}


def _log(fh, payload: dict[str, Any]) -> None:
    if fh is None:
        return
    fh.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
    fh.flush()
