"""Fetch security alerts from GitHub Advanced Security APIs."""

from __future__ import annotations

import json
import logging
import os
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class GHASFetcher:
    """Fetch security alerts from GitHub Advanced Security APIs.

    Tries the ``gh`` CLI first (handles auth automatically), then falls back to
    the ``requests`` library with a ``GITHUB_TOKEN`` environment variable.
    """

    def __init__(self, owner: str, repo: str) -> None:
        self.owner = owner
        self.repo = repo
        self.base_url = f"https://api.github.com/repos/{owner}/{repo}"
        self._gh_available: Optional[bool] = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_gh_available(self) -> bool:
        """Return *True* if the ``gh`` CLI is installed and authenticated."""
        if self._gh_available is None:
            try:
                result = subprocess.run(
                    ["gh", "auth", "status"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self._gh_available = result.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                self._gh_available = False
        return self._gh_available

    def _call_gh_api(self, endpoint: str) -> Optional[List[dict]]:
        """Call the GitHub API via ``gh api --paginate``."""
        try:
            result = subprocess.run(
                ["gh", "api", endpoint, "--paginate"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                logger.warning("gh api returned non-zero: %s", result.stderr.strip())
                return None
            return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            logger.warning("gh api call failed: %s", exc)
            return None

    def _call_requests(self, endpoint: str, params: Optional[dict] = None) -> Optional[List[dict]]:
        """Fall back to ``requests`` with ``GITHUB_TOKEN``."""
        try:
            import requests  # noqa: WPS433 (local import intentional)
        except ImportError:
            logger.error("requests library not installed and gh CLI unavailable.")
            return None

        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            logger.error("GITHUB_TOKEN environment variable is not set.")
            return None

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        url = f"{self.base_url}{endpoint}"
        all_results: List[dict] = []
        page = 1
        per_page = 100
        params = dict(params or {})

        while True:
            params.update({"per_page": per_page, "page": page})
            try:
                resp = requests.get(url, headers=headers, params=params, timeout=30)
            except requests.RequestException as exc:
                logger.error("Request failed: %s", exc)
                return None

            # Handle rate limiting
            remaining = resp.headers.get("X-RateLimit-Remaining")
            if remaining is not None and int(remaining) == 0:
                logger.warning("GitHub API rate limit reached.")
                break

            if resp.status_code == 404:
                logger.info(
                    "404 for %s — GHAS may not be enabled for this repo.", url
                )
                return []

            if resp.status_code != 200:
                logger.warning(
                    "GitHub API returned %s: %s", resp.status_code, resp.text[:200]
                )
                return None

            data = resp.json()
            if not data:
                break
            all_results.extend(data)

            # Check for next page via Link header
            link = resp.headers.get("Link", "")
            if 'rel="next"' not in link:
                break
            page += 1

        return all_results

    def _api_get(self, endpoint: str, params: Optional[dict] = None) -> List[dict]:
        """Try ``gh api`` first, then fall back to ``requests``."""
        if self._is_gh_available():
            # Build query string for gh api
            qs = "&".join(f"{k}={v}" for k, v in (params or {}).items())
            full = f"/repos/{self.owner}/{self.repo}{endpoint}"
            if qs:
                full = f"{full}?{qs}"
            data = self._call_gh_api(full)
            if data is not None:
                return data

        # Fallback to requests
        data = self._call_requests(endpoint, params)
        return data if data is not None else []

    # ------------------------------------------------------------------
    # Normalisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_code_scanning(alert: dict) -> Dict[str, Any]:
        rule = alert.get("rule", {})
        tool = alert.get("tool", {})
        instance = alert.get("most_recent_instance", {})
        location = instance.get("location", {})

        return {
            "alert_number": alert.get("number"),
            "rule_id": rule.get("id"),
            "severity": rule.get("security_severity_level") or rule.get("severity", "unknown"),
            "tool_name": tool.get("name"),
            "description": rule.get("description", ""),
            "most_recent_instance": {
                "file_path": location.get("path", ""),
                "start_line": location.get("start_line"),
                "end_line": location.get("end_line"),
                "state": instance.get("state", ""),
            },
            "html_url": alert.get("html_url", ""),
            "created_at": alert.get("created_at", ""),
            "state": alert.get("state", ""),
        }

    @staticmethod
    def _normalize_dependabot(alert: dict) -> Dict[str, Any]:
        dep = alert.get("dependency", {})
        pkg = dep.get("package", {})
        vuln = (alert.get("security_vulnerability") or alert.get("security_advisory", {}))
        first_patched = vuln.get("first_patched_version", {}) or {}
        advisory = alert.get("security_advisory", {})
        identifiers = advisory.get("identifiers", [])

        cve_id = ""
        ghsa_id = ""
        for ident in identifiers:
            if ident.get("type") == "CVE":
                cve_id = ident.get("value", "")
            elif ident.get("type") == "GHSA":
                ghsa_id = ident.get("value", "")

        return {
            "alert_number": alert.get("number"),
            "dependency_name": pkg.get("name", ""),
            "package_ecosystem": pkg.get("ecosystem", ""),
            "vulnerable_version": vuln.get("vulnerable_version_range", ""),
            "patched_version": first_patched.get("identifier", ""),
            "severity": alert.get("severity") or vuln.get("severity", "unknown"),
            "cve_id": cve_id,
            "ghsa_id": ghsa_id,
            "html_url": alert.get("html_url", ""),
            "state": alert.get("state", ""),
            "manifest_path": dep.get("manifest_path", ""),
        }

    @staticmethod
    def _normalize_secret_scanning(alert: dict) -> Dict[str, Any]:
        locations = alert.get("locations", [])
        parsed_locations = []
        for loc in locations:
            details = loc.get("details", {})
            parsed_locations.append({
                "file_path": details.get("path", ""),
                "start_line": details.get("start_line"),
                "end_line": details.get("end_line"),
            })

        return {
            "alert_number": alert.get("number"),
            "secret_type": alert.get("secret_type", ""),
            "secret_type_display_name": alert.get("secret_type_display_name", ""),
            "locations": parsed_locations,
            "state": alert.get("state", ""),
            "html_url": alert.get("html_url", ""),
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch_code_scanning_alerts(self, state: str = "open") -> List[Dict[str, Any]]:
        """Fetch code-scanning alerts. ``GET /repos/{owner}/{repo}/code-scanning/alerts``."""
        raw = self._api_get("/code-scanning/alerts", {"state": state})
        return [self._normalize_code_scanning(a) for a in raw]

    def fetch_dependabot_alerts(self, state: str = "open") -> List[Dict[str, Any]]:
        """Fetch Dependabot alerts. ``GET /repos/{owner}/{repo}/dependabot/alerts``."""
        raw = self._api_get("/dependabot/alerts", {"state": state})
        return [self._normalize_dependabot(a) for a in raw]

    def fetch_secret_scanning_alerts(self, state: str = "open") -> List[Dict[str, Any]]:
        """Fetch secret-scanning alerts. ``GET /repos/{owner}/{repo}/secret-scanning/alerts``."""
        raw = self._api_get("/secret-scanning/alerts", {"state": state})
        return [self._normalize_secret_scanning(a) for a in raw]

    def fetch_all_alerts(self) -> Dict[str, List[Dict[str, Any]]]:
        """Fetch all alert types and return a categorised dict."""
        return {
            "code_scanning": self.fetch_code_scanning_alerts(),
            "dependabot": self.fetch_dependabot_alerts(),
            "secret_scanning": self.fetch_secret_scanning_alerts(),
        }
