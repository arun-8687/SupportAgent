"""Click-based CLI for Security Fixer."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import click


def _detect_repo_slug(repo_path: str) -> str | None:
    """Auto-detect *owner/repo* from the git remote URL."""
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return None
        url = result.stdout.strip()
        m = re.search(r"github\.com[:/](.+?/.+?)(?:\.git)?$", url)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


@click.group()
@click.version_option(version="0.1.0", prog_name="security-fixer")
def main() -> None:
    """Security Fixer — Fetch GHAS vulnerabilities and auto-fix them."""


@main.command()
@click.argument("repo", required=False)
@click.option(
    "--path",
    "-p",
    "repo_path",
    default=".",
    type=click.Path(exists=True),
    help="Local repo path to apply fixes to.",
)
@click.option("--dry-run", is_flag=True, help="Show what would be fixed without modifying files.")
@click.option("--no-pr", is_flag=True, help="Don't create a pull request.")
@click.option("--branch", "-b", default=None, help="Custom branch name for fixes.")
def fix(
    repo: str | None,
    repo_path: str,
    dry_run: bool,
    no_pr: bool,
    branch: str | None,
) -> None:
    """Fetch GHAS vulnerabilities and auto-fix them.

    REPO should be in owner/repo format (e.g., myorg/myapp).
    If not provided, auto-detects from git remote.
    """
    from security_fixer.engine import RemediationEngine

    # Auto-detect owner/repo if not supplied
    if not repo:
        repo = _detect_repo_slug(repo_path)
        if not repo:
            click.echo(
                click.style(
                    "Error: could not detect owner/repo. "
                    "Pass it explicitly: security-fixer fix owner/repo",
                    fg="red",
                )
            )
            sys.exit(1)

    parts = repo.split("/")
    if len(parts) != 2:
        click.echo(click.style("Error: REPO must be in owner/repo format.", fg="red"))
        sys.exit(1)

    owner, repo_name = parts

    # Banner
    click.echo(
        click.style("🔒 Security Fixer v0.1.0", fg="cyan", bold=True)
    )
    click.echo(f"   Repository : {owner}/{repo_name}")
    click.echo(f"   Local path : {Path(repo_path).resolve()}")
    if dry_run:
        click.echo(click.style("   Mode       : DRY RUN", fg="yellow", bold=True))

    engine = RemediationEngine(owner, repo_name, repo_path)
    report = engine.run(dry_run=dry_run, create_pr=not no_pr, branch_name=branch)

    click.echo(report.summary())

    if report.fixes_failed and not report.fixes_succeeded:
        sys.exit(1)
