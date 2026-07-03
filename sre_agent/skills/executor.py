"""
Skill executor.

Runs an approved mitigation action's underlying skill command. In dry-run
mode (default) it renders and logs the command without executing — the
safe default for demos, CI, and reviewed rollouts. Real execution shells
out (e.g. to the Azure CLI) with a timeout.
"""
import asyncio
import logging
import shlex
import time
from typing import Optional

from sre_agent.config import get_settings
from sre_agent.models import ActionResult, MitigationAction
from sre_agent.skills.registry import SkillDefinition, SkillRegistry

logger = logging.getLogger(__name__)

COMMAND_TIMEOUT_SECONDS = 300


class SkillExecutionError(Exception):
    pass


def render_command(skill: SkillDefinition, parameters: dict) -> str:
    """Render the skill's command template, quoting parameter values."""
    missing = [p for p in skill.parameters if p not in parameters]
    if missing:
        raise SkillExecutionError(f"Missing parameters for {skill.name}: {missing}")
    safe = {key: shlex.quote(str(value)) for key, value in parameters.items()}
    return skill.command.format(**safe)


class SkillExecutor:
    """Execute mitigation actions backed by registered skills."""

    def __init__(self, registry: Optional[SkillRegistry] = None, dry_run: Optional[bool] = None) -> None:
        self.registry = registry or SkillRegistry()
        settings = get_settings()
        self.dry_run = settings.dry_run if dry_run is None else dry_run

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

        try:
            command = render_command(skill, action.parameters)
        except SkillExecutionError as exc:
            return ActionResult(
                action_id=action.action_id,
                success=False,
                error=str(exc),
                dry_run=self.dry_run,
            )

        if self.dry_run:
            logger.info("[dry-run] %s => %s", skill.name, command)
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
                error=f"Skill {skill.name} timed out after {COMMAND_TIMEOUT_SECONDS}s",
                dry_run=False,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
