"""
Known-error store — pre-approved mitigations for recurring incidents.

A "known error" is a markdown file with YAML frontmatter (the same
authoring format as skills and custom agents): the frontmatter carries the
match criteria and the pre-approved actions, the body carries a free-text
rationale for humans.

    known_errors/ke-payment-oom.md
    ---
    id: ke-payment-oom
    service_name: payment-service      # optional; omit = any service in the app
    error_signature: "memory OOMKilled MemoryWorkingSet heap"
    min_signature_match: 0.5           # fraction of signature tokens found in alert text
    min_rca_confidence: 0.6            # RCA confidence required to use this pre-approval
    approved_actions:
      - skill_name: aks-memory-pressure
        tool_name: restart_aks_deployment
    environments: [prod]
    approved_by: someone@org.com
    expires: 2026-10-01                # date; expired records never match
    enabled: true
    success_count: 0
    ---
    Free-text rationale for humans.

Layout: global records live in `settings.known_errors_dir/*.md`; app-scoped
records live in `settings.apps_dir/<APP_CODE>/known_errors/*.md`. App-scoped
records are searched first and win ties against global records.

Safety rails (all enforced here, not just at the call site):
  - `app_code == "UNMAPPED"` never matches ANY record, global or app-scoped
    (quarantine default — an untagged resource never inherits pre-approval).
  - `covers()` never pre-approves a HIGH risk action, regardless of what a
    record says.
  - `disable()` (the circuit breaker) is meant to be called the moment an
    action pre-approved by a record fails, revoking it for future incidents.
  - `record_candidate()` only ever writes `enabled: false` drafts — nothing
    in this module can enable a record automatically.
"""
import json
import logging
import uuid
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml
from pydantic import BaseModel, Field

from sre_agent.config import get_settings
from sre_agent.frontmatter import parse_frontmatter
from sre_agent.locking import file_lock
from sre_agent.models import MitigationAction, RiskLevel
from sre_agent.textsearch import tokens

logger = logging.getLogger(__name__)

UNMAPPED_APP_CODE = "UNMAPPED"


class ApprovedAction(BaseModel):
    """One skill+tool pair pre-approved by a known-error record."""
    skill_name: str
    tool_name: str


class KnownErrorRecord(BaseModel):
    """A known error loaded from a known_errors/*.md file."""
    id: str
    service_name: Optional[str] = None
    error_signature: str = ""
    min_signature_match: float = 0.5
    min_rca_confidence: float = 0.6
    approved_actions: List[ApprovedAction] = Field(default_factory=list)
    # Explicit opt-in per environment; an empty list matches nothing (safe
    # default — an operator must say prod/staging/dev on purpose).
    environments: List[str] = Field(default_factory=list)
    approved_by: str = ""
    expires: Optional[date] = None
    enabled: bool = True
    success_count: int = 0
    disabled_reason: Optional[str] = None
    body: str = ""
    path: Optional[Path] = None  # source file; set by the loader, not authored


def _read_record(path: Path) -> Optional[KnownErrorRecord]:
    """Parse one known-error markdown file; None (with a warning) if malformed."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        logger.warning("Failed to read known-error file %s", path)
        return None
    meta, body = parse_frontmatter(text)
    if not meta:
        logger.warning("Known-error file %s has no YAML frontmatter; skipping", path)
        return None
    try:
        record = KnownErrorRecord.model_validate({**meta, "body": body.strip()})
    except Exception:
        logger.exception("Failed to parse known-error record %s", path)
        return None
    record.path = path
    return record


class KnownErrorStore:
    """Loads known-error records and matches them against incidents."""

    def __init__(
        self, global_dir: Optional[Path] = None, apps_dir: Optional[Path] = None
    ) -> None:
        settings = get_settings()
        self.global_dir = global_dir or settings.known_errors_dir
        self.apps_dir = apps_dir or settings.apps_dir
        # Candidate counts live alongside whichever data root the caller
        # pointed us at (so tests rooting global_dir/apps_dir under
        # tmp_path stay fully isolated from the real data_dir too).
        if apps_dir is not None:
            base_dir = apps_dir.parent
        elif global_dir is not None:
            base_dir = global_dir.parent
        else:
            base_dir = settings.data_dir
        self.candidates_path = base_dir / "known_error_candidates.jsonl"
        self.promotion_threshold = settings.known_error_promotion_threshold

    # ------------------------------------------------------------------ #
    # Loading
    # ------------------------------------------------------------------ #

    def _app_dir(self, app_code: str) -> Path:
        return self.apps_dir / app_code / "known_errors"

    @staticmethod
    def _load_dir(directory: Path) -> List[KnownErrorRecord]:
        if not directory.exists():
            return []
        records = []
        for path in sorted(directory.glob("*.md")):
            record = _read_record(path)
            if record is not None:
                records.append(record)
        return records

    # ------------------------------------------------------------------ #
    # Matching
    # ------------------------------------------------------------------ #

    def find_match(
        self,
        app_code: str,
        service_name: str,
        alert_text: str,
        environment: str,
        rca_confidence: float,
    ) -> Optional[KnownErrorRecord]:
        """Best matching known-error record, or None.

        Untagged resources (app_code == "UNMAPPED") are quarantined: this
        ALWAYS returns None for them, even if a global record would
        otherwise match — an unmapped resource must never silently inherit
        another app's (or anyone's) pre-approval.
        """
        if not app_code or app_code == UNMAPPED_APP_CODE:
            return None

        alert_tokens = tokens(alert_text)
        today = date.today()

        # rank 0 = app-scoped (wins ties), rank 1 = global.
        candidates: List[Tuple[float, int, KnownErrorRecord]] = []
        for rank, directory in enumerate((self._app_dir(app_code), self.global_dir)):
            for record in self._load_dir(directory):
                score = self._match_score(
                    record, service_name, environment, rca_confidence, alert_tokens, today
                )
                if score is not None:
                    candidates.append((score, rank, record))

        if not candidates:
            return None
        candidates.sort(key=lambda item: (-item[0], item[1]))
        return candidates[0][2]

    @staticmethod
    def _match_score(
        record: KnownErrorRecord,
        service_name: str,
        environment: str,
        rca_confidence: float,
        alert_tokens: Set[str],
        today: date,
    ) -> Optional[float]:
        """Signature score in [0, 1] if the record matches, else None."""
        if not record.enabled:
            return None
        if record.expires is not None and record.expires < today:
            return None
        if environment not in record.environments:
            return None
        if record.service_name and record.service_name != service_name:
            return None
        if rca_confidence < record.min_rca_confidence:
            return None

        signature_tokens = tokens(record.error_signature)
        if not signature_tokens:
            return None
        score = len(signature_tokens & alert_tokens) / len(signature_tokens)
        if score < record.min_signature_match:
            return None
        return score

    @staticmethod
    def covers(record: KnownErrorRecord, action: MitigationAction) -> bool:
        """Whether `record` pre-approves `action`.

        High-risk actions are NEVER pre-approvable, regardless of what the
        record says — this check exists independently of anything an
        operator wrote into a record's approved_actions. Only skill actions
        (with a concrete skill_name/tool_name) are pre-approvable; manual
        steps always still need a human.
        """
        if action.risk == RiskLevel.HIGH:
            return False
        if action.kind != "skill" or not action.skill_name or not action.tool_name:
            return False
        return any(
            approved.skill_name == action.skill_name and approved.tool_name == action.tool_name
            for approved in record.approved_actions
        )

    # ------------------------------------------------------------------ #
    # Lookup by id (used to resolve a gate decision's matched_rule back to
    # the record that produced it).
    # ------------------------------------------------------------------ #

    def get(self, record_id: str) -> Optional[KnownErrorRecord]:
        directories = [self.global_dir]
        if self.apps_dir.exists():
            directories += [
                p / "known_errors" for p in sorted(self.apps_dir.iterdir()) if p.is_dir()
            ]
        for directory in directories:
            for record in self._load_dir(directory):
                if record.id == record_id:
                    return record
        return None

    # ------------------------------------------------------------------ #
    # Mutating a record file in place (success / circuit breaker)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _rewrite(record: KnownErrorRecord, updates: dict) -> None:
        if record.path is None:
            raise ValueError(f"Known-error record {record.id!r} has no source path")
        path = record.path
        with file_lock(path):
            meta, body = parse_frontmatter(path.read_text(encoding="utf-8"))
            meta.update(updates)
            new_text = "---\n" + yaml.safe_dump(meta, sort_keys=False) + "---\n" + body
            path.write_text(new_text, encoding="utf-8")
        for key, value in updates.items():
            setattr(record, key, value)

    def record_success(self, record: KnownErrorRecord) -> None:
        """Increment the record's success_count (audit trail of usage)."""
        self._rewrite(record, {"success_count": record.success_count + 1})

    def disable(self, record: KnownErrorRecord, reason: str) -> None:
        """Circuit breaker: revoke a record's pre-approval after a failure."""
        self._rewrite(record, {"enabled": False, "disabled_reason": reason})
        logger.warning(
            "Known-error record %s disabled (circuit breaker): %s", record.id, reason
        )

    # ------------------------------------------------------------------ #
    # Promotion: recurring mitigations become draft known-error records
    # ------------------------------------------------------------------ #

    def _read_candidates(self) -> Dict[str, int]:
        if not self.candidates_path.exists():
            return {}
        counts: Dict[str, int] = {}
        for line in self.candidates_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                counts[entry["key"]] = entry["count"]
            except (json.JSONDecodeError, KeyError):
                continue
        return counts

    def _write_candidates(self, counts: Dict[str, int]) -> None:
        self.candidates_path.parent.mkdir(parents=True, exist_ok=True)
        self.candidates_path.write_text(
            "".join(json.dumps({"key": key, "count": count}) + "\n" for key, count in counts.items()),
            encoding="utf-8",
        )

    def record_candidate(
        self,
        app_code: str,
        service_name: str,
        alert_title: str,
        actions: List[MitigationAction],
    ) -> Optional[Path]:
        """Track a recurring (app_code, service_name, actions) combination.

        Returns the path of a newly written DRAFT record once the
        combination has recurred `known_error_promotion_threshold` times,
        else None. Drafts are always written with `enabled: false` — this
        method never auto-enables a pre-approval. Untagged incidents
        (app_code == "UNMAPPED") are skipped entirely: there is no app
        directory to draft into, and quarantine should not be gamed via
        promotion either.
        """
        if not app_code or app_code == UNMAPPED_APP_CODE:
            return None

        pairs = sorted(
            {
                (a.skill_name, a.tool_name)
                for a in actions
                if a.kind == "skill" and a.skill_name and a.tool_name
            }
        )
        if not pairs:
            return None

        key = json.dumps([app_code, service_name, pairs], sort_keys=True)
        with file_lock(self.candidates_path):
            counts = self._read_candidates()
            counts[key] = counts.get(key, 0) + 1
            count = counts[key]
            self._write_candidates(counts)

        if count < self.promotion_threshold:
            return None
        return self._write_draft(app_code, service_name, alert_title, pairs)

    def _write_draft(
        self,
        app_code: str,
        service_name: str,
        alert_title: str,
        pairs: List[Tuple[str, str]],
    ) -> Path:
        directory = self._app_dir(app_code)
        directory.mkdir(parents=True, exist_ok=True)
        draft_id = f"ke-draft-{uuid.uuid4().hex[:8]}"
        meta = {
            "id": draft_id,
            "service_name": service_name,
            "error_signature": alert_title,
            "min_signature_match": 0.5,
            "min_rca_confidence": 0.6,
            "approved_actions": [
                {"skill_name": skill_name, "tool_name": tool_name}
                for skill_name, tool_name in pairs
            ],
            "environments": ["prod"],
            "approved_by": "DRAFT - requires human review",
            "enabled": False,
            "success_count": 0,
        }
        body = (
            f"Auto-drafted after {self.promotion_threshold} recurrences of the same "
            f"mitigation for {service_name} ({app_code}). Review the match criteria "
            "and approved actions, then set `enabled: true` and a real `approved_by` "
            "to activate this pre-approval.\n"
        )
        path = directory / f"{draft_id}.md"
        with file_lock(path):
            path.write_text(
                "---\n" + yaml.safe_dump(meta, sort_keys=False) + "---\n" + body,
                encoding="utf-8",
            )
        logger.info("Known-error draft %s written for review at %s", draft_id, path)
        return path
