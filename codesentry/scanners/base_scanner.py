"""Abstract base class for all CodeSentry scanners."""

from __future__ import annotations

import abc
import shutil
from pathlib import Path
from typing import Iterable, Optional

from codesentry.config import ScanConfig
from codesentry.file_filter import FileFilter
from codesentry.models import ScanResult, ScannerType


class BaseScanner(abc.ABC):
    """Abstract base scanner interface.

    Every concrete scanner must set ``scanner_type`` and implement
    :meth:`scan`.
    """

    scanner_type: ScannerType

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self._file_filter: Optional[FileFilter] = None

    # -- helpers available to all scanners --------------------------------

    @abc.abstractmethod
    async def scan(self, path: str, **kwargs) -> ScanResult:
        """Run the scan and return results."""
        ...

    def _create_result(self) -> ScanResult:
        """Return a fresh :class:`ScanResult` pre-stamped with the scanner type."""
        return ScanResult(scanner=self.scanner_type)

    @staticmethod
    def _check_tool_available(tool_name: str) -> bool:
        """Return *True* if *tool_name* is found on ``PATH``."""
        return shutil.which(tool_name) is not None

    def _get_file_filter(self, root: Path) -> FileFilter:
        """Return a FileFilter that respects .gitignore and exclude_paths."""
        if self._file_filter is None:
            self._file_filter = FileFilter(
                root=root,
                exclude_paths=self.config.exclude_paths,
                respect_gitignore=True,
            )
        return self._file_filter

    def _is_excluded(self, file_path: str) -> bool:
        """Return *True* if *file_path* should be skipped."""
        if self._file_filter is not None:
            return self._file_filter.is_excluded(Path(file_path))
        # Fallback to simple pattern matching
        for pattern in self.config.exclude_paths:
            if pattern in file_path:
                return True
        return False

    def _iter_files(self, root: Path, pattern: str = "*") -> Iterable[Path]:
        """Yield files matching *pattern* under *root*, respecting .gitignore."""
        ff = self._get_file_filter(root)
        return ff.iter_files(pattern=pattern)
