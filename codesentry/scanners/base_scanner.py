"""Abstract base class for all CodeSentry scanners."""

from __future__ import annotations

import abc
import shutil
import time
from typing import Optional

from codesentry.config import ScanConfig
from codesentry.models import ScanResult, ScannerType


class BaseScanner(abc.ABC):
    """Abstract base scanner interface.

    Every concrete scanner must set ``scanner_type`` and implement
    :meth:`scan`.
    """

    scanner_type: ScannerType

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()

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

    def _is_excluded(self, file_path: str) -> bool:
        """Return *True* if *file_path* matches any exclude pattern."""
        for pattern in self.config.exclude_paths:
            if pattern in file_path:
                return True
        return False
