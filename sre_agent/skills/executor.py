"""
Skill executor.

Runs a mitigation action through one of its skill's attached tools. The
skill is activated first (its SKILL.md guidance is loaded/re-read), then
the tool's command template is rendered and executed.

In dry-run mode (default) commands are rendered and logged, not run.
After every execution, PostToolUse hooks fire: a hook returning
{"decision": "block"} marks the action result as blocked.
"""
import asyncio
import logging
import shlex
import time
from typing import Optional

from sre_agent.config import get_settings
from sre_agent.models import ActionResult, HookEvent, MitigationAction
from sre_agent.skills.registry import SkillRegistry, SkillTool

logger = logging.getLogger(__name__)

COMMAND_TIMEOUT_SECONDS = 300


class SkillExecutionError(Exception):
    pass


def render_command(tool: SkillTool, parameters: dict) -> str:
    """Render the tool's command template, quoting parameter values."""
    if not tool.command:
        raise SkillExecutionError(f"Tool {tool.name} has no executable command")
    missing = [p for p in tool.parameters if p not in parameters]
    if missing:
        raise SkillExecutionError(f"Missing parameters for {tool.name}: {missing}")
    safe = {key: shlex.quote(str(value)) for key, value in parameters.items()}
    return tool.command.format(**safe)


class SkillExecutor:
    """Execute mitigation actions via skill tools, with PostToolUse hooks."""

    def __init__(
        self,
        registry: Optional[SkillRegistry] = None,
        dry_run: Optional[bool] = None,
        hooks=None,  # HookEngine; typed loosely to avoid import cycle
    ) -> None:
        self.registry = registry or SkillRegistry()
        settings = get_settings()
        self.dry_run = settings.dry_run if dry_run is None else dry_run
        self.hooks = hooks

    async def execute(self, action: MitigationAction) -> ActionResult:
        started = time.monotonic()

        if action.kind == "manual":
            return ActionResult(
                action_id=action.action_id,
                success=True,
                output=f"Manual step recorded for operator: {action.description}",
                dry_run=True,
            )

        skill = self.registry.get(action.skill_name or "")
        if skill is None:
            return ActionResult(
                action_id=action.action_id,
                success=False,
                error=f"Unknown skill: {action.skill_name}",
                dry_run=self.dry_run,
            )

        # Tools are only available while the skill is active; activating
        # (re-)reads SKILL.md, matching the load/unload lifecycle.
        self.registry.activate(skill.name)

        tool = skill.get_tool(action.tool_name)
        if tool is None:
            return ActionResult(
                action_id=action.action_id,
                success=False,
                error=f"Skill {skill.name} has no tool named {action.tool_name!r}",
                dry_run=self.dry_run,
            )

        try:
            command = render_command(tool, action.parameters)
        except SkillExecutionError as exc:
            return ActionResult(
                action_id=action.action_id,
                success=False,
                error=str(exc),
                dry_run=self.dry_run,
            )

        result = await self._run(action, tool, command, started)
        return await self._post_tool_use(action, tool, command, result)

    # ------------------------------------------------------------------ #

    async def _run(
        self, action: MitigationAction, tool: SkillTool, command: str, started: float
    ) -> ActionResult:
        if self.dry_run:
            logger.info("[dry-run] %s/%s => %s", action.skill_name, tool.name, command)
            return ActionResult(
                action_id=action.action_id,
                success=True,
                output=f"[dry-run] {command}",
                dry_run=True,
                duration_ms=int((time.monotonic() - started) * 1000),
            )

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=COMMAND_TIMEOUT_SECONDS
            )
            success = proc.returncode == 0
            return ActionResult(
                action_id=action.action_id,
                success=success,
                output=stdout.decode(errors="replace")[-4000:],
                error=None if success else stderr.decode(errors="replace")[-2000:],
                dry_run=False,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        except asyncio.TimeoutError:
            return ActionResult(
                action_id=action.action_id,
                success=False,
                error=f"Tool {tool.name} timed out after {COMMAND_TIMEOUT_SECONDS}s",
                dry_run=False,
                duration_ms=int((time.monotonic() - started) * 1000),
            )

    async def _post_tool_use(
        self, action: MitigationAction, tool: SkillTool, command: str, result: ActionResult
    ) -> ActionResult:
        """Fire PostToolUse hooks; a block decision overrides the result."""
        if self.hooks is None:
            return result
        hook_results = await self.hooks.fire(
            HookEvent.POST_TOOL_USE,
            {
                "hook_event_name": "PostToolUse",
                "tool_name": tool.name,
                "tool_input": {"command": command, **action.parameters},
                "tool_result": (result.output or result.error or "")[:2000],
                "tool_succeeded": result.success,
            },
            tool_name=tool.name,
        )
        veto = self.hooks.blocked_by(hook_results)
        if veto:
            reason = (veto.decision or {}).get("reason", "blocked by PostToolUse hook")
            logger.warning("PostToolUse hook '%s' blocked %s: %s", veto.hook, tool.name, reason)
            result.success = False
            result.error = f"Blocked by hook '{veto.hook}': {reason}"
        return result
