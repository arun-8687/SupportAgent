"""
Agent hooks — custom checkpoints that intercept agent behavior.

Core events:
  Stop         -> agent about to finalize a response; a hook can reject it
  PostToolUse  -> a tool finished executing; a hook can audit/block/inject

Lifecycle events (investigation_started, before_mitigation,
after_resolution, on_escalation) are also supported so operators can
automate around workflow milestones.

Executor types:
  prompt   -> an LLM evaluates the prompt (with $ARGUMENTS context
              injection) and returns a JSON decision
  command  -> a shell command or multi-line script runs with the hook
              context as JSON on stdin

Response contract:
  simple:    {"ok": true} / {"ok": false, "reason": "..."}
  expanded:  {"decision": "allow"|"block", "reason": "...",
              "hookSpecificOutput": {"additionalContext": "..."}}
  exit code: 0 without output = allow; 0 with JSON = parse it;
             2 = always block (stderr becomes the reason);
             anything else = failMode ("allow" | "block")

PostToolUse hooks only run when their `matcher` regex (anchored as
^(pattern)$, "*" = all tools) matches the tool name.
"""
import asyncio
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field

from sre_agent.config import get_settings
from sre_agent.llm import generate_text
from sre_agent.models import HookEvent, HookResult

logger = logging.getLogger(__name__)


class HookDefinition(BaseModel):
    """One hook declared in hooks.yaml."""
    name: str
    event: HookEvent
    type: str = "prompt"                 # prompt | command
    prompt: Optional[str] = None         # prompt hooks; $ARGUMENTS injected
    command: Optional[str] = None        # command hooks: inline command
    script: Optional[str] = None         # command hooks: multi-line script
    matcher: Optional[str] = None        # PostToolUse: regex over tool names
    timeout: int = 30
    fail_mode: str = Field(default="allow", alias="failMode")
    max_rejections: int = Field(default=3, alias="maxRejections")
    enabled: bool = True

    model_config = {"populate_by_name": True}

    def matches_tool(self, tool_name: Optional[str]) -> bool:
        """Anchored, case-sensitive matcher; '*' matches all; empty matches none."""
        if self.event != HookEvent.POST_TOOL_USE:
            return True
        if not self.matcher:
            return False
        if self.matcher == "*":
            return True
        if tool_name is None:
            return False
        return re.match(f"^({self.matcher})$", tool_name) is not None


def _parse_decision(raw: str) -> Optional[Dict[str, Any]]:
    """Parse simple/expanded JSON responses into a normalized decision."""
    try:
        start, end = raw.find("{"), raw.rfind("}")
        data = json.loads(raw[start:end + 1])
    except Exception:
        return None
    if "ok" in data:
        return {
            "allow": bool(data["ok"]),
            "reason": data.get("reason", ""),
        }
    if "decision" in data:
        extra = data.get("hookSpecificOutput", {}) or {}
        return {
            "allow": data["decision"] != "block",
            "reason": data.get("reason", ""),
            "additionalContext": extra.get("additionalContext"),
        }
    return None


class HookEngine:
    """Loads hook definitions and runs the ones matching an event."""

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

    async def fire(
        self,
        event: HookEvent,
        context: Dict[str, Any],
        tool_name: Optional[str] = None,
    ) -> List[HookResult]:
        """Run all enabled hooks registered for `event` (matcher-filtered)."""
        results = []
        for hook in self.hooks:
            if hook.event != event or not hook.enabled:
                continue
            if not hook.matches_tool(tool_name):
                continue
            context = {"hook_event_name": event.value, **context}
            if hook.type == "command":
                results.append(await self._run_command_hook(hook, context))
            else:
                results.append(await self._run_prompt_hook(hook, context))
        return results

    @staticmethod
    def blocked_by(results: List[HookResult]) -> Optional[HookResult]:
        """First result that blocks, if any.

        A rejection without a reason is treated as approval (Stop-hook
        semantics: always provide a reason when rejecting).
        """
        for result in results:
            decision = result.decision or {}
            if decision.get("allow") is False and decision.get("reason"):
                return result
        return None

    @staticmethod
    def additional_context(results: List[HookResult]) -> Optional[str]:
        """Last hook-provided additionalContext wins."""
        context = None
        for result in results:
            extra = (result.decision or {}).get("additionalContext")
            if extra:
                context = extra
        return context

    # ------------------------------------------------------------------ #

    async def _run_command_hook(self, hook: HookDefinition, context: Dict[str, Any]) -> HookResult:
        """Command hooks receive the context as JSON on stdin.

        Inline `command` strings run through the shell; multi-line `script`
        blocks are written to a temp file so their shebang (#!/bin/bash or
        #!/usr/bin/env python3) is honored.
        """
        script_path: Optional[Path] = None
        try:
            if hook.script:
                import tempfile

                fd, raw_path = tempfile.mkstemp(prefix=f"hook-{hook.name}-")
                script_path = Path(raw_path)
                script_path.write_text(hook.script, encoding="utf-8")
                os.close(fd)
                script_path.chmod(0o700)
                program = str(script_path)
            else:
                program = hook.command or "true"

            proc = await asyncio.create_subprocess_shell(
                program,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=dict(os.environ),
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=json.dumps(context, default=str).encode()),
                timeout=hook.timeout,
            )
            out = stdout.decode(errors="replace").strip()
            err = stderr.decode(errors="replace").strip()

            if proc.returncode == 2:
                decision = {"allow": False, "reason": err or "blocked by hook (exit 2)"}
            elif proc.returncode == 0:
                decision = _parse_decision(out) if out else {"allow": True, "reason": ""}
                if decision is None:  # exit 0 with non-JSON output = allow
                    decision = {"allow": True, "reason": ""}
            else:
                allow = hook.fail_mode != "block"
                decision = {
                    "allow": allow,
                    "reason": "" if allow else (err or f"hook failed (exit {proc.returncode})"),
                }
            return HookResult(
                hook=hook.name, event=hook.event, hook_type="command",
                success=proc.returncode in (0, 2),
                output=(out or err)[:2000],
                decision=decision,
            )
        except Exception as exc:
            logger.exception("Command hook %s failed", hook.name)
            allow = hook.fail_mode != "block"
            return HookResult(
                hook=hook.name, event=hook.event, hook_type="command",
                success=False, output=str(exc),
                decision={"allow": allow, "reason": "" if allow else str(exc)},
            )
        finally:
            if script_path is not None:
                script_path.unlink(missing_ok=True)

    async def _run_prompt_hook(self, hook: HookDefinition, context: Dict[str, Any]) -> HookResult:
        """Prompt hooks get the context via the $ARGUMENTS placeholder."""
        context_json = json.dumps(context, indent=2, default=str)
        text = hook.prompt or ""
        if "$ARGUMENTS" in text:
            prompt = text.replace("$ARGUMENTS", context_json)
        else:  # context appended automatically when $ARGUMENTS is absent
            prompt = f"{text}\n\nContext:\n{context_json}"
        prompt += (
            '\n\nRespond with ONLY a JSON object: {"ok": true} to allow, '
            'or {"ok": false, "reason": "..."} to reject.'
        )
        raw = await generate_text(
            system_prompt=(
                "You are a policy-evaluation hook inside an SRE automation "
                "workflow. Be conservative; when in doubt, do not allow."
            ),
            user_prompt=prompt,
            # Offline fallback: allow, so hooks don't block local dev runs.
            fallback='{"ok": true, "reason": "no LLM configured; hook defaulted to allow"}',
        )
        decision = _parse_decision(raw) or {
            "allow": True,
            "reason": "unparseable hook output; defaulted to allow",
        }
        return HookResult(
            hook=hook.name,
            event=hook.event,
            hook_type="prompt",
            success=True,
            output=raw[:2000],
            decision=decision,
        )
