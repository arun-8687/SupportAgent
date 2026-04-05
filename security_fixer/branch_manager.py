"""Git branch management for security fix commits."""

from __future__ import annotations

import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from security_fixer.auto_fixer import FixResult

logger = logging.getLogger(__name__)


class BranchManager:
    """Manages git branches for security fix commits."""

    def __init__(self, repo_path: str) -> None:
        self.repo_path = Path(repo_path).resolve()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        """Run a git command in the repo directory."""
        return subprocess.run(
            ["git", *args],
            cwd=str(self.repo_path),
            capture_output=True,
            text=True,
            timeout=60,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_fix_branch(self, branch_name: Optional[str] = None) -> str:
        """Create and check out a new branch for security fixes.

        Default name: ``security/auto-fix-YYYYMMDD-HHMMSS``
        Returns the branch name.
        """
        if not branch_name:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            branch_name = f"security/auto-fix-{ts}"

        result = self._git("checkout", "-b", branch_name)
        if result.returncode != 0:
            logger.error("Failed to create branch %s: %s", branch_name, result.stderr.strip())
            raise RuntimeError(f"git checkout -b failed: {result.stderr.strip()}")

        logger.info("Created branch: %s", branch_name)
        return branch_name

    def commit_fix(self, fix: FixResult, message: Optional[str] = None) -> str:
        """Stage and commit a single fix. Returns the commit SHA."""
        if not message:
            message = self._build_commit_message(fix)

        # Stage the file
        add = self._git("add", fix.file_path)
        if add.returncode != 0:
            logger.warning("git add failed for %s: %s", fix.file_path, add.stderr.strip())

        # Also stage .env.example if it was created/updated
        env_example = self.repo_path / ".env.example"
        if env_example.is_file():
            self._git("add", ".env.example")

        commit = self._git("commit", "-m", message)
        if commit.returncode != 0:
            stderr = commit.stderr.strip()
            if "nothing to commit" in stderr or "no changes added" in stderr:
                logger.info("Nothing to commit for %s", fix.file_path)
                return ""
            logger.error("git commit failed: %s", stderr)
            raise RuntimeError(f"git commit failed: {stderr}")

        # Extract SHA
        rev = self._git("rev-parse", "HEAD")
        sha = rev.stdout.strip()
        logger.info("Committed %s: %s", sha[:8], message.split("\n")[0])
        return sha

    def commit_all_fixes(self, fixes: List[FixResult]) -> List[str]:
        """Commit all successful fixes. Returns a list of commit SHAs."""
        shas: List[str] = []
        successful = [f for f in fixes if f.success]

        for fix in successful:
            try:
                sha = self.commit_fix(fix)
                if sha:
                    shas.append(sha)
            except RuntimeError as exc:
                logger.error("Failed to commit fix for %s: %s", fix.file_path, exc)

        return shas

    def push_branch(self, branch_name: str) -> bool:
        """Push the branch to origin."""
        result = self._git("push", "-u", "origin", branch_name)
        if result.returncode != 0:
            logger.error("git push failed: %s", result.stderr.strip())
            return False
        logger.info("Pushed branch %s to origin.", branch_name)
        return True

    def create_pull_request(
        self, branch_name: str, title: str, body: str
    ) -> Optional[str]:
        """Create a pull request using ``gh pr create``. Returns the PR URL."""
        try:
            result = subprocess.run(
                [
                    "gh", "pr", "create",
                    "--title", title,
                    "--body", body,
                    "--base", "main",
                    "--head", branch_name,
                ],
                cwd=str(self.repo_path),
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                logger.error("gh pr create failed: %s", result.stderr.strip())
                return None
            pr_url = result.stdout.strip()
            logger.info("Created PR: %s", pr_url)
            return pr_url
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.error("Could not create PR: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_commit_message(fix: FixResult) -> str:
        """Build a descriptive commit message for a fix."""
        type_label = fix.alert_type.replace("_", " ")
        msg = f"fix(security): {fix.description} in {fix.file_path}"
        body = (
            f"\nAlert type: {type_label}\n"
            f"Alert #{fix.alert_number}\n"
            f"Fix: {fix.fix_applied}"
        )
        return msg + body

    @staticmethod
    def build_pr_body(fixes: List[FixResult]) -> str:
        """Generate a markdown PR body with a summary table of fixes."""
        successful = [f for f in fixes if f.success]
        failed = [f for f in fixes if not f.success]

        lines = [
            "## 🔒 Automated Security Fixes\n",
            "This PR was created automatically by **Security Fixer** to resolve "
            "GitHub Advanced Security alerts.\n",
        ]

        if successful:
            lines.append("### ✅ Fixes Applied\n")
            lines.append("| # | Type | File | Description | Fix |")
            lines.append("|---|------|------|-------------|-----|")
            for f in successful:
                lines.append(
                    f"| {f.alert_number} | {f.alert_type} | `{f.file_path}` "
                    f"| {f.description} | {f.fix_applied} |"
                )
            lines.append("")

        if failed:
            lines.append("### ⚠️ Could Not Auto-Fix\n")
            lines.append("| # | Type | File | Reason |")
            lines.append("|---|------|------|--------|")
            for f in failed:
                lines.append(
                    f"| {f.alert_number} | {f.alert_type} | `{f.file_path}` "
                    f"| {f.error or 'Unknown'} |"
                )
            lines.append("")

        lines.append(
            "---\n*Generated by Security Fixer — "
            "automated GHAS remediation engine.*"
        )
        return "\n".join(lines)
