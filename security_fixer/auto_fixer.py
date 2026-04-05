"""Automated vulnerability fixer for GHAS alerts."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class FixResult:
    """Outcome of a single auto-fix attempt."""

    alert_type: str  # "code_scanning", "dependabot", "secret_scanning"
    alert_number: int
    file_path: str
    description: str
    fix_applied: str
    success: bool
    error: Optional[str] = None


class AutoFixer:
    """Applies automated fixes for security vulnerabilities."""

    def __init__(self, repo_path: str) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.fixes_applied: List[FixResult] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fix_all(self, alerts: Dict[str, List[dict]]) -> List[FixResult]:
        """Process every alert category and attempt automated fixes."""
        for alert in alerts.get("code_scanning", []):
            self._fix_code_scanning_alert(alert)
        for alert in alerts.get("dependabot", []):
            self._fix_dependabot_alert(alert)
        for alert in alerts.get("secret_scanning", []):
            self._fix_secret_scanning_alert(alert)
        return self.fixes_applied

    # ------------------------------------------------------------------
    # Code scanning fixes
    # ------------------------------------------------------------------

    def _fix_code_scanning_alert(self, alert: dict) -> None:
        rule_id: str = alert.get("rule_id", "")
        instance = alert.get("most_recent_instance", {})
        file_path = instance.get("file_path", "")
        start_line = instance.get("start_line")
        alert_number = alert.get("alert_number", 0)
        description = alert.get("description", "")

        if not file_path:
            return

        full_path = self.repo_path / file_path
        if not full_path.is_file() or ".git" in full_path.parts:
            return

        # Determine the CWE from the rule_id (e.g. "py/sql-injection" or "cwe-89")
        rule_lower = rule_id.lower()

        fixers = [
            (self._is_sql_injection, self._fix_sql_injection),
            (self._is_command_injection, self._fix_command_injection),
            (self._is_unsafe_deserialization, self._fix_unsafe_deserialization),
            (self._is_weak_crypto, self._fix_weak_crypto),
            (self._is_hardcoded_credentials, self._fix_hardcoded_credentials),
            (self._is_debug_mode, self._fix_debug_mode),
            (self._is_ssl_disabled, self._fix_ssl_disabled),
            (self._is_eval_exec, self._fix_eval_exec),
            (self._is_cleartext_logging, self._fix_cleartext_logging),
            (self._is_stack_trace_exposure, self._fix_stack_trace_exposure),
        ]

        for check_fn, fix_fn in fixers:
            if check_fn(rule_lower, description):
                self._apply_code_fix(
                    fix_fn, full_path, file_path, start_line, alert_number, rule_id
                )
                return

        # Unknown rule — record as unfixable
        self.fixes_applied.append(
            FixResult(
                alert_type="code_scanning",
                alert_number=alert_number,
                file_path=file_path,
                description=f"Unknown rule: {rule_id}",
                fix_applied="",
                success=False,
                error="No auto-fix strategy for this rule.",
            )
        )

    def _apply_code_fix(
        self,
        fix_fn: Any,
        full_path: Path,
        file_path: str,
        start_line: Optional[int],
        alert_number: int,
        rule_id: str,
    ) -> None:
        try:
            content = full_path.read_text(encoding="utf-8")
            new_content, fix_desc = fix_fn(content, start_line)
            if new_content != content:
                full_path.write_text(new_content, encoding="utf-8")
                self.fixes_applied.append(
                    FixResult(
                        alert_type="code_scanning",
                        alert_number=alert_number,
                        file_path=file_path,
                        description=f"Rule {rule_id}",
                        fix_applied=fix_desc,
                        success=True,
                    )
                )
            else:
                self.fixes_applied.append(
                    FixResult(
                        alert_type="code_scanning",
                        alert_number=alert_number,
                        file_path=file_path,
                        description=f"Rule {rule_id}",
                        fix_applied="No matching pattern found in source.",
                        success=False,
                        error="Pattern not matched.",
                    )
                )
        except Exception as exc:  # noqa: BLE001
            self.fixes_applied.append(
                FixResult(
                    alert_type="code_scanning",
                    alert_number=alert_number,
                    file_path=file_path,
                    description=f"Rule {rule_id}",
                    fix_applied="",
                    success=False,
                    error=str(exc),
                )
            )

    # --- classification helpers ---

    @staticmethod
    def _is_sql_injection(rule: str, desc: str) -> bool:
        return "sql" in rule and "inject" in rule or "cwe-89" in rule or "cwe-89" in desc.lower()

    @staticmethod
    def _is_command_injection(rule: str, desc: str) -> bool:
        return "command" in rule and "inject" in rule or "cwe-78" in rule or "cwe-78" in desc.lower()

    @staticmethod
    def _is_unsafe_deserialization(rule: str, desc: str) -> bool:
        return "deserialization" in rule or "cwe-502" in rule or "cwe-502" in desc.lower()

    @staticmethod
    def _is_weak_crypto(rule: str, desc: str) -> bool:
        return "crypto" in rule or "hash" in rule or "cwe-327" in rule or "cwe-327" in desc.lower()

    @staticmethod
    def _is_hardcoded_credentials(rule: str, desc: str) -> bool:
        return (
            "hardcoded" in rule
            or "credential" in rule
            or "cwe-798" in rule
            or "cwe-798" in desc.lower()
        )

    @staticmethod
    def _is_debug_mode(rule: str, desc: str) -> bool:
        return "debug" in rule or "cwe-489" in rule or "cwe-489" in desc.lower()

    @staticmethod
    def _is_ssl_disabled(rule: str, desc: str) -> bool:
        return (
            "ssl" in rule
            or "verify" in rule
            or "certificate" in rule
            or "cwe-295" in rule
            or "cwe-295" in desc.lower()
        )

    @staticmethod
    def _is_eval_exec(rule: str, desc: str) -> bool:
        return "eval" in rule or "exec" in rule or "cwe-94" in rule or "cwe-94" in desc.lower()

    @staticmethod
    def _is_cleartext_logging(rule: str, desc: str) -> bool:
        return (
            "clear-text-logging" in rule
            or "cleartext" in rule and "log" in rule
            or "cwe-532" in rule
            or "cwe-532" in desc.lower()
            or "sensitive" in desc.lower() and "log" in desc.lower()
        )

    @staticmethod
    def _is_stack_trace_exposure(rule: str, desc: str) -> bool:
        return (
            "stack-trace" in rule
            or "exception" in desc.lower() and "exposure" in desc.lower()
            or "cwe-209" in rule
            or "cwe-209" in desc.lower()
        )

    # --- fix implementations ---

    def _fix_sql_injection(self, content: str, line: Optional[int]) -> tuple[str, str]:
        """Replace string-formatted SQL with parameterised queries."""
        # f-string pattern: cursor.execute(f"... {var} ...")
        pattern_fstr = re.compile(
            r'(cursor\.execute\()f(["\'])(.*?)\{(\w+)\}(.*?)\2\)',
            re.DOTALL,
        )
        new, n1 = pattern_fstr.subn(
            lambda m: f'{m.group(1)}"{m.group(3)}%s{m.group(5)}", ({m.group(4)},))',
            content,
        )

        # Concatenation pattern: cursor.execute("..." + var)
        pattern_concat = re.compile(
            r'(cursor\.execute\()(["\'])(.*?)\2\s*\+\s*(\w+)\)',
        )
        new, n2 = pattern_concat.subn(
            lambda m: f'{m.group(1)}"{m.group(3)}%s", ({m.group(4)},))',
            new,
        )

        total = n1 + n2
        return new, f"Converted {total} SQL query(ies) to parameterised form."

    def _fix_command_injection(self, content: str, line: Optional[int]) -> tuple[str, str]:
        """Replace os.system/subprocess shell=True with safer alternatives."""
        count = 0

        # os.system(cmd) -> subprocess.run(shlex.split(cmd), check=True)
        pattern_os = re.compile(r'os\.system\((\w+)\)')
        if pattern_os.search(content):
            content = pattern_os.sub(r'subprocess.run(shlex.split(\1), check=True)', content)
            content = _ensure_import(content, "subprocess")
            content = _ensure_import(content, "shlex")
            count += 1

        # subprocess.call(cmd, shell=True) -> subprocess.run(cmd, shell=False, check=True)
        pattern_shell = re.compile(
            r'subprocess\.call\((.+?),\s*shell\s*=\s*True\)'
        )
        if pattern_shell.search(content):
            content = pattern_shell.sub(r'subprocess.run(\1, shell=False, check=True)', content)
            count += 1

        return content, f"Replaced {count} unsafe command execution(s)."

    def _fix_unsafe_deserialization(self, content: str, line: Optional[int]) -> tuple[str, str]:
        """Replace yaml.load with yaml.safe_load; warn on pickle."""
        count = 0
        # yaml.load(data) -> yaml.safe_load(data) (only bare yaml.load without Loader arg)
        pattern_yaml = re.compile(r'yaml\.load\(([^,)]+)\)')
        if pattern_yaml.search(content):
            content = pattern_yaml.sub(r'yaml.safe_load(\1)', content)
            count += 1

        # pickle.loads — add warning comment
        pattern_pickle = re.compile(r'([ \t]*)(pickle\.loads\(.+?\))')
        if pattern_pickle.search(content):
            content = pattern_pickle.sub(
                r'\1# SECURITY: Validate source before deserializing\n'
                r'\1# TODO: Replace pickle with a safer serialisation format\n'
                r'\1\2',
                content,
            )
            count += 1

        return content, f"Fixed {count} unsafe deserialization(s)."

    def _fix_weak_crypto(self, content: str, line: Optional[int]) -> tuple[str, str]:
        """Upgrade MD5/SHA1 to SHA-256."""
        new = content.replace("hashlib.md5(", "hashlib.sha256(")
        new = new.replace("hashlib.sha1(", "hashlib.sha256(")
        changed = new != content
        return new, "Upgraded weak hash to SHA-256." if changed else "No weak hash found."

    def _fix_hardcoded_credentials(self, content: str, line: Optional[int]) -> tuple[str, str]:
        """Move hardcoded passwords / API keys to environment variables."""
        pattern = re.compile(
            r'^([ \t]*)((?:password|passwd|api_key|apikey|secret|token|secret_key)'
            r'\s*=\s*)["\'].+?["\']',
            re.IGNORECASE | re.MULTILINE,
        )
        count = 0

        def _replace(m: re.Match) -> str:
            nonlocal count
            indent = m.group(1)
            var_assign = m.group(2)
            var_name = var_assign.split("=")[0].strip().upper()
            count += 1
            return (
                f'{indent}# SECURITY: Credential moved to environment variable\n'
                f'{indent}{var_assign}os.environ.get("{var_name}", "")'
            )

        new = pattern.sub(_replace, content)
        if count:
            new = _ensure_import(new, "os")
        return new, f"Moved {count} credential(s) to env vars."

    def _fix_debug_mode(self, content: str, line: Optional[int]) -> tuple[str, str]:
        """Replace hardcoded debug=True with env-var toggle."""
        count = 0

        # app.run(debug=True) -> app.run(debug=os.environ.get(...))
        pattern_app = re.compile(r'(app\.run\([^)]*?)debug\s*=\s*True')
        if pattern_app.search(content):
            content = pattern_app.sub(
                r'\1debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true"',
                content,
            )
            content = _ensure_import(content, "os")
            count += 1

        # DEBUG = True -> env-var based
        pattern_const = re.compile(r'^([ \t]*)DEBUG\s*=\s*True', re.MULTILINE)
        if pattern_const.search(content):
            content = pattern_const.sub(
                r'\1DEBUG = os.environ.get("DEBUG", "false").lower() == "true"',
                content,
            )
            content = _ensure_import(content, "os")
            count += 1

        return content, f"Replaced {count} debug toggle(s) with env var."

    def _fix_ssl_disabled(self, content: str, line: Optional[int]) -> tuple[str, str]:
        """Re-enable SSL verification."""
        pattern = re.compile(r'(requests\.\w+\([^)]*?)verify\s*=\s*False')
        new = pattern.sub(r'\1verify=True', content)
        changed = new != content
        if changed:
            # Add advisory comment at top of file
            new = (
                "# SECURITY: SSL verification re-enabled — do not disable in production\n"
                + new
            )
        return new, "Re-enabled SSL verification." if changed else "No disabled SSL found."

    def _fix_eval_exec(self, content: str, line: Optional[int]) -> tuple[str, str]:
        """Add security warning for eval/exec — cannot safely auto-fix."""
        pattern = re.compile(r'^([ \t]*)((?:eval|exec)\(.+?\))', re.MULTILINE)
        count = 0

        def _add_warning(m: re.Match) -> str:
            nonlocal count
            indent = m.group(1)
            code = m.group(2)
            count += 1
            return (
                f"{indent}# SECURITY WARNING: eval()/exec() is dangerous — "
                f"replace with a safe alternative\n"
                f"{indent}# TODO: Manual review required\n"
                f"{indent}{code}"
            )

        new = pattern.sub(_add_warning, content)
        return new, f"Flagged {count} eval/exec call(s) for manual review."

    def _fix_cleartext_logging(self, content: str, line: Optional[int]) -> tuple[str, str]:
        """Fix clear-text logging of sensitive data (CWE-532).

        Strategy: redact sensitive variables in print/log statements near the
        flagged line by masking their values.
        """
        lines = content.splitlines(True)
        if line is None or line < 1 or line > len(lines):
            return content, "No line info — skipped."

        target = lines[line - 1]
        fixed = False

        # Pattern: print(f"...{secret_var}...") or print(f"...{var}...")
        # Replace the interpolated variable with a masked version
        if re.search(r'print\s*\(', target) or re.search(r'log(?:ger)?\.\w+\s*\(', target):
            # Mask f-string interpolations that likely contain sensitive data
            new_line = re.sub(
                r'\{(\w*(?:key|secret|token|password|pwd|api_key|credential|conn)\w*)\}',
                r'{"***REDACTED***"}',
                target,
                flags=re.IGNORECASE,
            )
            # Also mask partial reveals like api_key[-8:]
            new_line = re.sub(
                r'\{[^}]*(?:key|secret|token|password|pwd|credential)\w*\[.*?\][^}]*\}',
                r'{"***REDACTED***"}',
                new_line,
                flags=re.IGNORECASE,
            )
            if new_line != target:
                lines[line - 1] = new_line
                fixed = True
            else:
                # Couldn't identify specific sensitive var — add a warning comment
                indent = re.match(r'^(\s*)', target).group(1)
                lines[line - 1] = (
                    f"{indent}# SECURITY: Sensitive data may be logged below — "
                    f"redact before production (CWE-532)\n" + target
                )
                fixed = True

        if fixed:
            return "".join(lines), "Redacted or flagged sensitive data in log/print statement."
        return content, "Could not identify logging pattern — skipped."

    def _fix_stack_trace_exposure(self, content: str, line: Optional[int]) -> tuple[str, str]:
        """Fix stack trace / exception exposure in HTTP responses (CWE-209).

        Strategy: replace `str(e)` in error responses with a generic message,
        and log the real error server-side instead.
        """
        lines = content.splitlines(True)
        if line is None or line < 1 or line > len(lines):
            return content, "No line info — skipped."

        # Search a small window around the flagged line for the pattern
        window_start = max(0, line - 3)
        window_end = min(len(lines), line + 5)
        window = lines[window_start:window_end]
        joined = "".join(window)

        # Pattern: f"...{str(e)}..." or f"...{e}..." in a response/return
        new_joined = re.sub(
            r'(f["\'].*?)\{str\(\w+\)\}(.*?["\'])',
            r'\1An internal error occurred. Check server logs for details.\2',
            joined,
        )
        if new_joined == joined:
            new_joined = re.sub(
                r'(f["\'].*?)\{(\w+)\}(.*?["\'])',
                lambda m: (
                    f'{m.group(1)}An internal error occurred. Check server logs for details.{m.group(3)}'
                    if m.group(2) in ('e', 'ex', 'exc', 'err', 'error', 'exception')
                    else m.group(0)
                ),
                joined,
            )

        if new_joined != joined:
            lines[window_start:window_end] = [new_joined]
            return "".join(lines), "Replaced exception details in HTTP response with generic message."
        return content, "Could not identify exposure pattern — skipped."

    # ------------------------------------------------------------------
    # Dependabot fixes
    # ------------------------------------------------------------------

    def _fix_dependabot_alert(self, alert: dict) -> None:
        dep_name: str = alert.get("dependency_name", "")
        patched: str = alert.get("patched_version", "")
        ecosystem: str = alert.get("package_ecosystem", "").lower()
        alert_number: int = alert.get("alert_number", 0)
        manifest_path: str = alert.get("manifest_path", "")

        if not dep_name or not patched:
            self.fixes_applied.append(
                FixResult(
                    alert_type="dependabot",
                    alert_number=alert_number,
                    file_path=manifest_path or "unknown",
                    description=f"Upgrade {dep_name}",
                    fix_applied="",
                    success=False,
                    error="Missing dependency name or patched version.",
                )
            )
            return

        if ecosystem == "pip" or manifest_path.endswith((".txt", ".in")):
            self._fix_pip_dependency(dep_name, patched, alert_number, manifest_path)
        elif ecosystem == "npm" or manifest_path.endswith("package.json"):
            self._fix_npm_dependency(dep_name, patched, alert_number, manifest_path)
        else:
            self._fix_pip_dependency(dep_name, patched, alert_number, manifest_path)

    def _fix_pip_dependency(
        self, dep_name: str, patched: str, alert_number: int, manifest_path: str
    ) -> None:
        target = manifest_path or "requirements.txt"
        full_path = self.repo_path / target

        if not full_path.is_file():
            self.fixes_applied.append(
                FixResult(
                    alert_type="dependabot",
                    alert_number=alert_number,
                    file_path=target,
                    description=f"Upgrade {dep_name} to {patched}",
                    fix_applied="",
                    success=False,
                    error=f"{target} not found.",
                )
            )
            return

        try:
            content = full_path.read_text(encoding="utf-8")
            # Match various pinning formats: ==, >=, ~=, <=, !=, or bare name
            pattern = re.compile(
                rf'^({re.escape(dep_name)}\s*(?:==|>=|~=|<=|!=)\s*)[\w.*]+',
                re.IGNORECASE | re.MULTILINE,
            )
            new_content, n = pattern.subn(rf'\g<1>{patched}', content)

            if n == 0:
                # Try bare package name (no pinning)
                bare = re.compile(
                    rf'^{re.escape(dep_name)}\s*$',
                    re.IGNORECASE | re.MULTILINE,
                )
                new_content, n = bare.subn(f'{dep_name}=={patched}', content)

            if n > 0:
                full_path.write_text(new_content, encoding="utf-8")

            self.fixes_applied.append(
                FixResult(
                    alert_type="dependabot",
                    alert_number=alert_number,
                    file_path=target,
                    description=f"Upgrade {dep_name} to {patched}",
                    fix_applied=f"Updated version in {target}" if n else "Version pattern not found.",
                    success=n > 0,
                    error=None if n else "Could not match version pattern.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            self.fixes_applied.append(
                FixResult(
                    alert_type="dependabot",
                    alert_number=alert_number,
                    file_path=target,
                    description=f"Upgrade {dep_name} to {patched}",
                    fix_applied="",
                    success=False,
                    error=str(exc),
                )
            )

    def _fix_npm_dependency(
        self, dep_name: str, patched: str, alert_number: int, manifest_path: str
    ) -> None:
        target = manifest_path or "package.json"
        full_path = self.repo_path / target

        if not full_path.is_file():
            self.fixes_applied.append(
                FixResult(
                    alert_type="dependabot",
                    alert_number=alert_number,
                    file_path=target,
                    description=f"Upgrade {dep_name} to {patched}",
                    fix_applied="",
                    success=False,
                    error=f"{target} not found.",
                )
            )
            return

        try:
            data = json.loads(full_path.read_text(encoding="utf-8"))
            updated = False
            for section in ("dependencies", "devDependencies"):
                deps = data.get(section, {})
                if dep_name in deps:
                    old_ver = deps[dep_name]
                    # Preserve prefix (^, ~) if present
                    prefix = ""
                    if old_ver and old_ver[0] in ("^", "~"):
                        prefix = old_ver[0]
                    deps[dep_name] = f"{prefix}{patched}"
                    updated = True

            if updated:
                full_path.write_text(
                    json.dumps(data, indent=2) + "\n", encoding="utf-8"
                )

            self.fixes_applied.append(
                FixResult(
                    alert_type="dependabot",
                    alert_number=alert_number,
                    file_path=target,
                    description=f"Upgrade {dep_name} to {patched}",
                    fix_applied=f"Updated version in {target}" if updated else "Dep not found in package.json.",
                    success=updated,
                    error=None if updated else "Dependency not found in package.json.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            self.fixes_applied.append(
                FixResult(
                    alert_type="dependabot",
                    alert_number=alert_number,
                    file_path=target,
                    description=f"Upgrade {dep_name} to {patched}",
                    fix_applied="",
                    success=False,
                    error=str(exc),
                )
            )

    # ------------------------------------------------------------------
    # Secret scanning fixes
    # ------------------------------------------------------------------

    def _fix_secret_scanning_alert(self, alert: dict) -> None:
        alert_number: int = alert.get("alert_number", 0)
        secret_type: str = alert.get("secret_type", "")
        display_name: str = alert.get("secret_type_display_name", secret_type)
        locations: list = alert.get("locations", [])

        if not locations:
            self.fixes_applied.append(
                FixResult(
                    alert_type="secret_scanning",
                    alert_number=alert_number,
                    file_path="unknown",
                    description=f"Secret: {display_name}",
                    fix_applied="",
                    success=False,
                    error="No location data in alert.",
                )
            )
            return

        for loc in locations:
            file_path = loc.get("file_path", "")
            if not file_path:
                continue
            full_path = self.repo_path / file_path
            if not full_path.is_file() or ".git" in full_path.parts:
                continue

            try:
                content = full_path.read_text(encoding="utf-8")
                new_content, fix_desc = self._replace_secret(
                    content, file_path, secret_type, display_name
                )
                if new_content != content:
                    full_path.write_text(new_content, encoding="utf-8")
                    self._update_env_example(secret_type, display_name)
                    self.fixes_applied.append(
                        FixResult(
                            alert_type="secret_scanning",
                            alert_number=alert_number,
                            file_path=file_path,
                            description=f"Secret: {display_name}",
                            fix_applied=fix_desc,
                            success=True,
                        )
                    )
                else:
                    self.fixes_applied.append(
                        FixResult(
                            alert_type="secret_scanning",
                            alert_number=alert_number,
                            file_path=file_path,
                            description=f"Secret: {display_name}",
                            fix_applied="Could not locate secret pattern.",
                            success=False,
                            error="Pattern not matched.",
                        )
                    )
            except Exception as exc:  # noqa: BLE001
                self.fixes_applied.append(
                    FixResult(
                        alert_type="secret_scanning",
                        alert_number=alert_number,
                        file_path=file_path,
                        description=f"Secret: {display_name}",
                        fix_applied="",
                        success=False,
                        error=str(exc),
                    )
                )

    def _replace_secret(
        self, content: str, file_path: str, secret_type: str, display_name: str
    ) -> tuple[str, str]:
        """Replace an embedded secret value based on file type."""
        env_var_name = _secret_type_to_env_var(secret_type)
        suffix = Path(file_path).suffix.lower()

        if suffix == ".env":
            # .env file: replace value with placeholder
            pattern = re.compile(
                rf'^(\s*{re.escape(env_var_name)}\s*=\s*).*$',
                re.MULTILINE | re.IGNORECASE,
            )
            new, n = pattern.subn(rf'\1<REPLACE_WITH_ACTUAL_SECRET>', content)
            if n:
                return new, "Replaced secret value with placeholder in .env file."

        if suffix == ".py":
            # Python: VAR = "secret..." -> VAR = os.environ["VAR"]
            pattern = re.compile(
                r'^([ \t]*\w*(?:key|token|secret|password|api_key|apikey)\s*=\s*)["\'].+?["\']',
                re.IGNORECASE | re.MULTILINE,
            )

            def _py_replace(m: re.Match) -> str:
                return f'{m.group(1)}os.environ["{env_var_name}"]'

            new = pattern.sub(_py_replace, content)
            if new != content:
                new = _ensure_import(new, "os")
                return new, f"Replaced secret with os.environ[\"{env_var_name}\"]."

        if suffix in (".yaml", ".yml"):
            # YAML: replace quoted values that look like secrets
            pattern = re.compile(
                r'((?:key|token|secret|password|api_key):\s*)["\']?.+?["\']?\s*$',
                re.IGNORECASE | re.MULTILINE,
            )
            new = pattern.sub(rf'\1${{{env_var_name}}}', content)
            if new != content:
                return new, f"Replaced secret with ${{{env_var_name}}} placeholder."

        if suffix == ".json":
            pattern = re.compile(
                r'("(?:key|token|secret|password|api_key)":\s*)"[^"]+"',
                re.IGNORECASE,
            )
            new = pattern.sub(rf'\1"${{{env_var_name}}}"', content)
            if new != content:
                return new, f"Replaced secret with ${{{env_var_name}}} placeholder."

        # Fallback: generic quoted-string replacement near common var names
        pattern = re.compile(
            r'^([ \t]*\w*(?:key|token|secret|password|apikey)\s*[=:]\s*)["\'].{8,}?["\']',
            re.IGNORECASE | re.MULTILINE,
        )
        new = pattern.sub(rf'\1os.environ.get("{env_var_name}", "")', content)
        if new != content:
            new = _ensure_import(new, "os")
            return new, f"Replaced secret with env-var reference."

        return content, ""

    def _update_env_example(self, secret_type: str, display_name: str) -> None:
        """Add the secret name to ``.env.example`` if it doesn't exist."""
        env_example = self.repo_path / ".env.example"
        env_var = _secret_type_to_env_var(secret_type)
        line = f"{env_var}=<REPLACE_WITH_ACTUAL_SECRET>"

        if env_example.is_file():
            existing = env_example.read_text(encoding="utf-8")
            if env_var in existing:
                return
            env_example.write_text(
                existing.rstrip("\n") + f"\n# {display_name}\n{line}\n",
                encoding="utf-8",
            )
        else:
            env_example.write_text(
                f"# Environment variables for secrets\n# {display_name}\n{line}\n",
                encoding="utf-8",
            )


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------


def _ensure_import(content: str, module: str) -> str:
    """Add ``import <module>`` near the top of the file if missing."""
    if re.search(rf'^import {module}\b', content, re.MULTILINE):
        return content
    if re.search(rf'^from {module} ', content, re.MULTILINE):
        return content

    # Insert after any existing imports, or at top
    match = re.search(r'^(import |from )', content, re.MULTILINE)
    if match:
        pos = match.start()
        return content[:pos] + f"import {module}\n" + content[pos:]
    return f"import {module}\n" + content


def _secret_type_to_env_var(secret_type: str) -> str:
    """Convert a GHAS secret_type slug to an uppercase env var name."""
    name = re.sub(r'[^a-zA-Z0-9]', '_', secret_type).upper()
    return name or "SECRET_VALUE"
