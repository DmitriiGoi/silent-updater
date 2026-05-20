from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import httpx


GITHUB_MODELS_URL = "https://models.github.ai/inference/chat/completions"


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: str  # raw JSON string per OpenAI spec


@dataclass(frozen=True)
class ChatResponse:
    content: str
    tool_calls: list[ToolCall]
    finish_reason: str
    raw: dict[str, Any]


class ChatClient(Protocol):
    def chat(self, messages: list[dict], tools: list[dict] | None) -> ChatResponse: ...


class GitHubModelsClient:
    def __init__(
        self,
        token: str,
        model: str = "gpt-4o",
        *,
        endpoint: str = GITHUB_MODELS_URL,
        http: httpx.Client | None = None,
        timeout: float = 120.0,
    ):
        self.token = token
        self.model = model
        self.endpoint = endpoint
        self.http = http or httpx.Client(timeout=timeout)
        self._owns_http = http is None

    def close(self) -> None:
        if self._owns_http:
            self.http.close()

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> ChatResponse:
        body: dict[str, Any] = {"model": self.model, "messages": messages}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        resp = self.http.post(
            self.endpoint,
            json=body,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        if resp.status_code >= 400:
            raise RuntimeError(
                f"GitHub Models API {resp.status_code}: {resp.text[:1500]}"
            )
        data = resp.json()
        choice = data["choices"][0]
        message = choice.get("message") or {}
        finish = choice.get("finish_reason", "stop")
        tool_calls_raw = message.get("tool_calls") or []
        tool_calls = [
            ToolCall(
                id=tc.get("id", ""),
                name=tc.get("function", {}).get("name", ""),
                arguments=tc.get("function", {}).get("arguments", "{}"),
            )
            for tc in tool_calls_raw
        ]
        return ChatResponse(
            content=message.get("content") or "",
            tool_calls=tool_calls,
            finish_reason=finish,
            raw=data,
        )
