"""Utilities for respecting .gitignore and exclude patterns during scans."""

from __future__ import annotations

import fnmatch
import logging
from pathlib import Path
from typing import Iterable, List, Optional, Set

logger = logging.getLogger(__name__)

try:
    import pathspec

    _HAS_PATHSPEC = True
except ImportError:
    _HAS_PATHSPEC = False


class FileFilter:
    """Filter files based on .gitignore rules and custom exclude patterns."""

    def __init__(
        self,
        root: Path,
        exclude_paths: Optional[List[str]] = None,
        respect_gitignore: bool = True,
    ) -> None:
        self.root = root.resolve()
        self.exclude_paths = exclude_paths or []
        self._gitignore_spec: Optional[object] = None

        if respect_gitignore:
            self._load_gitignore()

    def _load_gitignore(self) -> None:
        """Load .gitignore patterns from the project root (and parents)."""
        patterns: List[str] = []
        gitignore = self.root / ".gitignore"
        if gitignore.is_file():
            try:
                for line in gitignore.read_text(errors="ignore").splitlines():
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        patterns.append(stripped)
            except OSError:
                pass

        if patterns and _HAS_PATHSPEC:
            self._gitignore_spec = pathspec.PathSpec.from_lines(
                "gitwildmatch", patterns
            )
        elif patterns:
            # Fallback: store raw patterns for fnmatch-based filtering
            self._gitignore_spec = patterns  # type: ignore[assignment]

    def is_excluded(self, filepath: Path) -> bool:
        """Return True if *filepath* should be skipped."""
        try:
            rel = filepath.resolve().relative_to(self.root)
        except ValueError:
            rel = filepath

        rel_posix = rel.as_posix()

        # Check custom exclude_paths (fnmatch-style)
        for pat in self.exclude_paths:
            if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(
                rel_posix, f"**/{pat}"
            ):
                return True
            # Also check if any path component matches the pattern
            for part in rel.parts:
                if fnmatch.fnmatch(part, pat) or fnmatch.fnmatch(part + "/", pat):
                    return True

        # Check .gitignore
        if self._gitignore_spec is not None:
            if _HAS_PATHSPEC:
                if self._gitignore_spec.match_file(rel_posix):  # type: ignore[union-attr]
                    return True
            else:
                # Fallback fnmatch
                for pat in self._gitignore_spec:  # type: ignore[union-attr]
                    if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(
                        filepath.name, pat
                    ):
                        return True

        return False

    def iter_files(
        self,
        pattern: str = "*",
        suffix: Optional[str] = None,
    ) -> Iterable[Path]:
        """Yield files matching *pattern* under root, excluding ignored paths.

        Args:
            pattern: Glob pattern to match (e.g. ``"*.py"``).
            suffix: If given, only yield files whose suffix matches (e.g. ``".py"``).
        """
        for filepath in self.root.rglob(pattern):
            if not filepath.is_file():
                continue
            if suffix and filepath.suffix != suffix:
                continue
            if self.is_excluded(filepath):
                continue
            yield filepath

    def filter_paths(self, paths: Iterable[Path]) -> Iterable[Path]:
        """Filter an existing iterable of paths, removing excluded ones."""
        for p in paths:
            if not self.is_excluded(p):
                yield p
