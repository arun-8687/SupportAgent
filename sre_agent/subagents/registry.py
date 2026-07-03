"""
Subagent registry.

The five built-in subagents ship registered (architecture, logs & metrics,
source code, root cause analysis, scanning). Custom subagents extend the
system by subclassing Subagent and registering an instance — the planner
composes any registered subagents for cross-domain investigations.
"""
from typing import Dict, List

from sre_agent.subagents.architecture import ArchitectureSubagent
from sre_agent.subagents.base import Subagent
from sre_agent.subagents.logs_metrics import LogsMetricsSubagent
from sre_agent.subagents.root_cause import RootCauseSubagent
from sre_agent.subagents.scanning import ScanningSubagent
from sre_agent.subagents.source_code import SourceCodeSubagent


class SubagentRegistry:
    """Holds all investigation subagents available to the planner."""

    def __init__(self) -> None:
        self._subagents: Dict[str, Subagent] = {}
        self.root_cause = RootCauseSubagent()
        for subagent in (
            LogsMetricsSubagent(),
            SourceCodeSubagent(),
            ArchitectureSubagent(),
            ScanningSubagent(),
        ):
            self.register(subagent)

    def register(self, subagent: Subagent) -> None:
        self._subagents[subagent.name] = subagent

    def get(self, name: str) -> Subagent:
        if name not in self._subagents:
            raise KeyError(f"Unknown subagent: {name}")
        return self._subagents[name]

    def names(self) -> List[str]:
        return list(self._subagents.keys())

    def descriptions(self) -> str:
        return "\n".join(
            f"- {name}: {agent.description}" for name, agent in self._subagents.items()
        )
