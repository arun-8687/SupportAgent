"""
Cross-process file locking for the file-backed stores.

Multiple workers (Functions instances sharing an Azure Files mount, or
listener replicas) append to the same JSONL/markdown files; an advisory
lock serializes those writes.

Caveat: fcntl advisory locks are reliable on local/ext4 and NFS-mounted
Azure Files, but NOT on SMB mounts. If you mount Azure Files over SMB,
prefer the Postgres-backed stores (set SRE_AGENT_DATABASE_URL) for
anything with concurrent writers.
"""
import os
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows dev boxes
    fcntl = None


@contextmanager
def file_lock(target: Path):
    """Exclusive advisory lock scoped to `target` (via a .lock sidecar)."""
    lock_path = target.with_suffix(target.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
