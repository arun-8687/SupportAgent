"""
Agent hooks — event-triggered automations at workflow lifecycle points.

Two executor types, mirroring the Azure SRE Agent hook model:

  command hooks  -> deterministic CLI operations (notify, emit telemetry)
  prompt hooks   -> LLM-evaluated checks that return structured JSON,
                    e.g. a policy check that can veto a mitigation

Hooks are declared in hooks.yaml and fire at: investigation_started,
before_mitigation, after_resolution, on_escalation. A before_mitigation
prompt hook returning {"allow": false} blocks execution and escalates.
"""
import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field

from sre_agent.config import get_settings
from sre_agent.llm import generate_text
from sre_agent.models import HookEvent, HookResult

logger = logging.getLogger(__name__)

HOOK_TIMEOUT_SECONDS = 60


class HookDefinition(BaseModel):
    """One hook declared in hooks.yaml."""
    name: str
    event: HookEvent
    type: str  # command | prompt
    command: Optional[str] = None      # command hooks
    prompt: Optional[str] = None       # prompt hooks (context appended)
    enabled: bool = True
    env: Dict[str, str] = Field(default_factory=dict)


class HookEngine:
    """Loads hook definitions and runs the ones matching a lifecycle event."""

    def __init__(self, hooks_file: Optional[Path] = None) -> None:
        self.hooks: List[HookDefinition] = self._load(
            hooks_file or get_settings().hooks_file
        )

    @staticmethod
    def _load(path: Path) -> List[HookDefinition]:
        if not path.exists():
            return []
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        hooks = []
        for item in data.get("hooks", []):
            try:
                hooks.append(HookDefinition.model_validate(item))
            except Exception:
                logger.exception("Invalid hook definition: %s", item)
        return hooks

    async def fire(self, event: HookEvent, context: Dict[str, Any]) -> List[HookResult]:
        """Run all enabled hooks registered for `event`."""
        results = []
        for hook in self.hooks:
            if hook.event != event or not hook.enabled:
                continue
            if hook.type == "command":
                results.append(await self._run_command_hook(hook, context))
            elif hook.type == "prompt":
                results.append(await self._run_prompt_hook(hook, context))
        return results

    @staticmethod
    def blocked_by(results: List[HookResult]) -> Optional[HookResult]:
        """Return the first hook result that vetoes the operation, if any."""
        for result in results:
            if result.decision is not None and result.decision.get("allow") is False:
                return result
        return None

    # ------------------------------------------------------------------ #

    async def _run_command_hook(self, hook: HookDefinition, context: Dict[str, Any]) -> HookResult:
        env_json = json.dumps(context, default=str)
        try:
            proc = await asyncio.create_subprocess_shell(
                hook.command or "true",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env={**dict(__import__("os").environ), **hook.env, "SRE_HOOK_CONTEXT": env_json},
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=HOOK_TIMEOUT_SECONDS)
            return HookResult(
                hook=hook.name,
                event=hook.event,
                hook_type="command",
                success=proc.returncode == 0,
                output=stdout.decode(errors="replace")[-2000:],
            )
        except Exception as exc:
            logger.exception("Command hook %s failed", hook.name)
            return HookResult(
                hook=hook.name, event=hook.event, hook_type="command",
                success=False, output=str(exc),
            )

    async def _run_prompt_hook(self, hook: HookDefinition, context: Dict[str, Any]) -> HookResult:
        prompt = (
            f"{hook.prompt}\n\nContext:\n{json.dumps(context, indent=2, default=str)}\n\n"
            'Respond with ONLY a JSON object like {"allow": true/false, "reason": "..."}.'
        )
        raw = await generate_text(
            system_prompt=(
                "You are a policy-evaluation hook inside an SRE automation "
                "workflow. Be conservative; when in doubt, do not allow."
            ),
            user_prompt=prompt,
            # Offline fallback: allow, so hooks don't block local dev runs.
            fallback='{"allow": true, "reason": "no LLM configured; hook defaulted to allow"}',
        )
        decision: Dict[str, Any]
        try:
            start, end = raw.find("{"), raw.rfind("}")
            decision = json.loads(raw[start:end + 1])
        except Exception:
            decision = {"allow": True, "reason": "unparseable hook output; defaulted to allow"}
        return HookResult(
            hook=hook.name,
            event=hook.event,
            hook_type="prompt",
            success=True,
            output=raw[:2000],
            decision=decision,
        )
