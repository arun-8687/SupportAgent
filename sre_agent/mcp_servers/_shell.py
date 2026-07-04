"""
Shared read-only shell execution helper for the first-party MCP servers.

Every tool in kubectl_readonly.py and azure_readonly.py routes through
run_readonly() so the safety rules live in one place: subcommand
allowlisting, identifier validation, shell-quoting, and a hard timeout.
These servers are diagnostic-only by design — there is no write/mutate
tool in either, so there is no permission-gate or approval step to bypass.
"""
import asyncio
import re
import shlex

# Kubernetes/Azure resource name charset: alphanumerics, hyphens, dots,
# underscores, forward slashes (for resource IDs). Rejects shell
# metacharacters even though shlex.quote already neutralizes them —
# defense in depth, and a clear error beats a quoted-but-nonsensical arg.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._/-]+$")

COMMAND_TIMEOUT_SECONDS = 30


class UnsafeArgumentError(ValueError):
    """An argument failed identifier validation before reaching the shell."""


def validate_identifier(value: str, field_name: str) -> str:
    if not value or not _IDENTIFIER_RE.match(value):
        raise UnsafeArgumentError(
            f"{field_name}={value!r} is not a valid identifier "
            "(letters, digits, '.', '_', '-', '/' only)"
        )
    return value


async def run_readonly(binary: str, allowlisted_subcommands: set, args: list) -> str:
    """
    Run `binary <args>` after checking args[0] (the subcommand) against
    allowlisted_subcommands. Returns combined stdout+stderr, truncated.
    Raises UnsafeArgumentError if the subcommand isn't allowlisted.
    """
    if not args or args[0] not in allowlisted_subcommands:
        raise UnsafeArgumentError(
            f"Subcommand {args[0] if args else '<empty>'!r} is not in the "
            f"read-only allowlist {sorted(allowlisted_subcommands)}"
        )
    command = " ".join([binary, *(shlex.quote(a) for a in args)])
    proc = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await asyncio.wait_for(
            proc.communicate(), timeout=COMMAND_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError:
        proc.kill()
        return f"[timed out after {COMMAND_TIMEOUT_SECONDS}s] {command}"
    return stdout.decode(errors="replace")[-6000:]
