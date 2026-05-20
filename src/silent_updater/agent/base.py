from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class AIAgent(ABC):
    """Base class for autonomous agents.

    Holds a workdir, knows how to plan and execute, and produces a run report.
    Concrete subclasses can be LLM-powered (tool-use loop) or deterministic
    pipelines — the abstraction does not assume LLM.
    """

    def __init__(self, workdir: Path):
        self.workdir = Path(workdir)

    @abstractmethod
    def run(self) -> Any:
        """Execute the agent's full workflow and return a report."""
        raise NotImplementedError
