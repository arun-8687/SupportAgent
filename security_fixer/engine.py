"""Orchestrates the full GHAS fetch → fix → commit → PR pipeline."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

import click

from security_fixer.auto_fixer import AutoFixer, FixResult
from security_fixer.branch_manager import BranchManager
from security_fixer.github_fetcher import GHASFetcher

logger = logging.getLogger(__name__)


@dataclass
class RemediationReport:
    """Summary of a remediation run."""

    alerts_fetched: dict
    fixes_attempted: int
    fixes_succeeded: int
    fixes_failed: int
    branch_name: Optional[str]
    pr_url: Optional[str]
    fixes: List[FixResult] = field(default_factory=list)

    def summary(self) -> str:
        """Return a human-readable summary of the run."""
        lines = [
            "",
            click.style("=" * 55, fg="cyan"),
            click.style("  Security Fixer — Remediation Report", fg="cyan", bold=True),
            click.style("=" * 55, fg="cyan"),
            "",
            f"  Alerts fetched:",
        ]
        for kind, count in self.alerts_fetched.items():
            label = kind.replace("_", " ").title()
            lines.append(f"    {label}: {count}")

        lines.append("")
        lines.append(f"  Fixes attempted : {self.fixes_attempted}")
        lines.append(
            click.style(f"  Fixes succeeded : {self.fixes_succeeded}", fg="green")
        )
        if self.fixes_failed:
            lines.append(
                click.style(f"  Fixes failed    : {self.fixes_failed}", fg="red")
            )
        else:
            lines.append(f"  Fixes failed    : 0")

        if self.branch_name:
            lines.append(f"\n  Branch: {self.branch_name}")
        if self.pr_url:
            lines.append(click.style(f"  PR: {self.pr_url}", fg="green", bold=True))

        lines.append(click.style("=" * 55, fg="cyan"))

        if self.fixes:
            lines.append("")
            for f in self.fixes:
                icon = "✅" if f.success else "❌"
                lines.append(f"  {icon} [{f.alert_type}] #{f.alert_number} {f.file_path}")
                lines.append(f"     {f.fix_applied or f.error or ''}")
            lines.append("")

        return "\n".join(lines)


class RemediationEngine:
    """Orchestrates the full GHAS fetch → fix → commit → PR pipeline."""

    def __init__(self, owner: str, repo: str, repo_path: str = ".") -> None:
        self.fetcher = GHASFetcher(owner, repo)
        self.fixer = AutoFixer(repo_path)
        self.branch_mgr = BranchManager(repo_path)
        self.repo_path = repo_path

    def run(
        self,
        dry_run: bool = False,
        create_pr: bool = True,
        branch_name: Optional[str] = None,
    ) -> RemediationReport:
        """Execute the full remediation pipeline.

        1. Fetch all GHAS alerts
        2. Create a fix branch (unless *dry_run*)
        3. Attempt automated fixes for each alert
        4. Commit each successful fix
        5. Push the branch and open a PR

        Args:
            dry_run: Preview fixes without modifying files.
            create_pr: Push and create a PR when done.
            branch_name: Custom branch name (auto-generated if ``None``).

        Returns:
            A :class:`RemediationReport` with the results.
        """
        # 1. Fetch alerts
        click.echo(click.style("\n🔍 Fetching GHAS alerts …", fg="cyan"))
        alerts = self.fetcher.fetch_all_alerts()

        alert_counts = {k: len(v) for k, v in alerts.items()}
        total_alerts = sum(alert_counts.values())
        click.echo(f"   Found {total_alerts} alert(s): {alert_counts}")

        if total_alerts == 0:
            click.echo(click.style("   No alerts — nothing to fix! 🎉", fg="green"))
            return RemediationReport(
                alerts_fetched=alert_counts,
                fixes_attempted=0,
                fixes_succeeded=0,
                fixes_failed=0,
                branch_name=None,
                pr_url=None,
            )

        # 2. Create fix branch
        actual_branch: Optional[str] = None
        if not dry_run:
            click.echo(click.style("\n🌿 Creating fix branch …", fg="cyan"))
            try:
                actual_branch = self.branch_mgr.create_fix_branch(branch_name)
                click.echo(f"   Branch: {actual_branch}")
            except RuntimeError as exc:
                click.echo(click.style(f"   ⚠️  {exc}", fg="yellow"))

        # 3. Apply fixes
        mode = "DRY RUN" if dry_run else "Applying"
        click.echo(click.style(f"\n🔧 {mode} fixes …", fg="cyan"))

        if dry_run:
            # In dry-run mode we still call fix_all so the user can see what
            # *would* happen, but we restore files afterwards.
            from pathlib import Path

            originals: dict[str, str] = {}
            repo = Path(self.repo_path).resolve()
            # Snapshot files that may be modified
            for category in alerts.values():
                for alert in category:
                    for key in ("most_recent_instance", "manifest_path"):
                        fp = ""
                        if isinstance(alert.get(key), dict):
                            fp = alert[key].get("file_path", "")
                        elif isinstance(alert.get(key), str):
                            fp = alert[key]
                        if fp:
                            full = repo / fp
                            if full.is_file() and str(full) not in originals:
                                originals[str(full)] = full.read_text(encoding="utf-8")
                    for loc in alert.get("locations", []):
                        fp = loc.get("file_path", "")
                        if fp:
                            full = repo / fp
                            if full.is_file() and str(full) not in originals:
                                originals[str(full)] = full.read_text(encoding="utf-8")

            fixes = self.fixer.fix_all(alerts)

            # Restore originals
            for path_str, original_content in originals.items():
                Path(path_str).write_text(original_content, encoding="utf-8")
        else:
            fixes = self.fixer.fix_all(alerts)

        succeeded = [f for f in fixes if f.success]
        failed = [f for f in fixes if not f.success]

        for f in fixes:
            icon = "✅" if f.success else "❌"
            click.echo(f"   {icon} [{f.alert_type}] #{f.alert_number} {f.file_path}")

        # 4. Commit fixes
        pr_url: Optional[str] = None
        if not dry_run and succeeded:
            click.echo(click.style("\n📝 Committing fixes …", fg="cyan"))
            shas = self.branch_mgr.commit_all_fixes(fixes)
            click.echo(f"   {len(shas)} commit(s) created.")

            # 5. Push & PR
            if create_pr and actual_branch:
                click.echo(click.style("\n🚀 Pushing branch and creating PR …", fg="cyan"))
                pushed = self.branch_mgr.push_branch(actual_branch)
                if pushed:
                    title = f"fix(security): Auto-fix {len(succeeded)} GHAS alert(s)"
                    body = BranchManager.build_pr_body(fixes)
                    pr_url = self.branch_mgr.create_pull_request(
                        actual_branch, title, body
                    )
                    if pr_url:
                        click.echo(f"   PR created: {pr_url}")
                    else:
                        click.echo(
                            click.style("   ⚠️  Could not create PR.", fg="yellow")
                        )
                else:
                    click.echo(
                        click.style("   ⚠️  Push failed — PR not created.", fg="yellow")
                    )

        return RemediationReport(
            alerts_fetched=alert_counts,
            fixes_attempted=len(fixes),
            fixes_succeeded=len(succeeded),
            fixes_failed=len(failed),
            branch_name=actual_branch,
            pr_url=pr_url,
            fixes=fixes,
        )
