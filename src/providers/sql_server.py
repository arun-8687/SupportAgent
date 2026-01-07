"""
SQL Server Provider Implementation.

Provides SQL Server-specific functionality for:
- Connecting to SQL Server / Azure SQL
- Diagnosing deadlocks, blocking, and other issues
- Executing remediation actions (retry, kill session, etc.)
- Verifying fixes
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..providers.base import (
    BaseProvider,
    DiagnosticInfo,
    ProviderCapabilities,
    ProviderRegistry,
    RemediationResult,
    VerificationResult,
)

logger = logging.getLogger(__name__)


# SQL queries for diagnostics
DEADLOCK_GRAPH_QUERY = """
SELECT TOP 1
    xed.value('@timestamp', 'datetime2') AS deadlock_time,
    xed.query('.') AS deadlock_graph
FROM (
    SELECT CAST(target_data AS XML) AS target_data
    FROM sys.dm_xe_session_targets st
    JOIN sys.dm_xe_sessions s ON s.address = st.event_session_address
    WHERE s.name = 'system_health' AND st.target_name = 'ring_buffer'
) AS data
CROSS APPLY target_data.nodes('RingBufferTarget/event[@name="xml_deadlock_report"]') AS xdr(xed)
ORDER BY xed.value('@timestamp', 'datetime2') DESC;
"""

BLOCKING_SESSIONS_QUERY = """
SELECT
    r.session_id AS blocked_session,
    r.blocking_session_id,
    r.wait_type,
    r.wait_time / 1000.0 AS wait_seconds,
    r.status,
    st.text AS blocked_query,
    bs.text AS blocking_query,
    r.database_id,
    DB_NAME(r.database_id) AS database_name
FROM sys.dm_exec_requests r
LEFT JOIN sys.dm_exec_requests br ON r.blocking_session_id = br.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) st
OUTER APPLY sys.dm_exec_sql_text(br.sql_handle) bs
WHERE r.blocking_session_id > 0
ORDER BY r.wait_time DESC;
"""

SESSION_INFO_QUERY = """
SELECT
    s.session_id,
    s.login_name,
    s.host_name,
    s.program_name,
    s.status,
    s.login_time,
    r.command,
    r.wait_type,
    r.wait_time,
    r.cpu_time,
    r.total_elapsed_time,
    t.text AS current_query
FROM sys.dm_exec_sessions s
LEFT JOIN sys.dm_exec_requests r ON s.session_id = r.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t
WHERE s.session_id = @session_id;
"""

PROCEDURE_STATUS_QUERY = """
SELECT TOP 1
    object_name(object_id) AS procedure_name,
    last_execution_time,
    execution_count,
    total_elapsed_time / execution_count AS avg_elapsed_time_us,
    total_worker_time / execution_count AS avg_cpu_time_us,
    cached_time
FROM sys.dm_exec_procedure_stats
WHERE object_name(object_id) = @procedure_name
  AND database_id = DB_ID();
"""

KILL_SESSION_QUERY = "KILL @session_id;"


@ProviderRegistry.register_with_name('sql_server')
class SQLServerProvider(BaseProvider):
    """
    Provider for SQL Server and Azure SQL.

    Implements diagnostic and remediation capabilities for SQL Server databases.
    """

    def __init__(self):
        self._connection = None
        self._config: Dict[str, Any] = {}
        self._connected = False

    @property
    def name(self) -> str:
        return "sql_server"

    @property
    def display_name(self) -> str:
        return "SQL Server / Azure SQL"

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            can_restart_job=False,
            can_kill_process=True,
            can_scale_resources=False,
            can_clear_cache=True,
            can_retry_operation=True,
            can_get_logs=True,
            can_get_metrics=True,
            can_execute_query=True,
            can_modify_config=False,
            custom_capabilities=[
                "get_deadlock_graph",
                "get_blocking_sessions",
                "kill_session",
                "retry_procedure",
                "clear_plan_cache",
                "get_session_info"
            ]
        )

    async def connect(self, config: Dict[str, Any]) -> bool:
        """
        Connect to SQL Server.

        Config should include:
        - connection_string: Full connection string, OR
        - server: Server hostname
        - database: Database name
        - username: Login username (optional for Windows auth)
        - password: Login password (optional for Windows auth)
        - driver: ODBC driver (default: ODBC Driver 18 for SQL Server)
        """
        self._config = config

        try:
            # Try to import pyodbc
            import pyodbc

            if 'connection_string' in config:
                conn_str = config['connection_string']
            else:
                driver = config.get('driver', 'ODBC Driver 18 for SQL Server')
                server = config['server']
                database = config['database']

                conn_str = f"DRIVER={{{driver}}};SERVER={server};DATABASE={database};"

                if 'username' in config and 'password' in config:
                    conn_str += f"UID={config['username']};PWD={config['password']};"
                else:
                    conn_str += "Trusted_Connection=yes;"

                # Azure SQL often needs encryption
                if config.get('encrypt', True):
                    conn_str += "Encrypt=yes;TrustServerCertificate=no;"

            # Connect in a thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            self._connection = await loop.run_in_executor(
                None, lambda: pyodbc.connect(conn_str, timeout=30)
            )
            self._connected = True
            logger.info(f"Connected to SQL Server: {config.get('server', 'unknown')}")
            return True

        except ImportError:
            logger.error("pyodbc not installed. Install with: pip install pyodbc")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to SQL Server: {e}")
            self._connected = False
            return False

    async def disconnect(self) -> None:
        """Close the SQL Server connection."""
        if self._connection:
            try:
                self._connection.close()
            except Exception as e:
                logger.warning(f"Error closing connection: {e}")
            finally:
                self._connection = None
                self._connected = False

    async def health_check(self) -> bool:
        """Check if connection is healthy."""
        if not self._connection:
            return False

        try:
            loop = asyncio.get_event_loop()
            cursor = await loop.run_in_executor(
                None, self._connection.cursor
            )
            await loop.run_in_executor(
                None, lambda: cursor.execute("SELECT 1")
            )
            cursor.close()
            return True
        except Exception:
            return False

    async def _execute_query(
        self,
        query: str,
        params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Execute a query and return results as list of dicts."""
        if not self._connection:
            raise RuntimeError("Not connected to SQL Server")

        loop = asyncio.get_event_loop()

        def run_query():
            cursor = self._connection.cursor()
            try:
                if params:
                    # Replace @param with ? for pyodbc
                    processed_query = query
                    param_values = []
                    for key, value in params.items():
                        processed_query = processed_query.replace(f"@{key}", "?")
                        param_values.append(value)
                    cursor.execute(processed_query, param_values)
                else:
                    cursor.execute(query)

                # Check if query returns results
                if cursor.description:
                    columns = [col[0] for col in cursor.description]
                    rows = cursor.fetchall()
                    return [dict(zip(columns, row)) for row in rows]
                return []
            finally:
                cursor.close()

        return await loop.run_in_executor(None, run_query)

    async def diagnose(
        self,
        job_name: str,
        error_message: str,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> DiagnosticInfo:
        """
        Diagnose a SQL Server issue.

        For deadlocks and blocking, gathers:
        - Deadlock graph (if available)
        - Current blocking sessions
        - Session information
        """
        details: Dict[str, Any] = {
            "procedure_name": job_name,
            "error_message": error_message,
            "error_code": error_code
        }
        recommendations: List[str] = []
        logs: Optional[str] = None

        try:
            # Check for deadlock
            if error_code == "1205" or "deadlock" in error_message.lower():
                # Get deadlock graph
                deadlock_results = await self._execute_query(DEADLOCK_GRAPH_QUERY)
                if deadlock_results:
                    details["deadlock_graph"] = str(deadlock_results[0].get("deadlock_graph", ""))
                    details["deadlock_time"] = str(deadlock_results[0].get("deadlock_time", ""))
                    logs = f"Deadlock occurred at {details['deadlock_time']}"
                    recommendations.append("Retry the transaction - deadlocks are transient")
                    recommendations.append("Review the deadlock graph to identify conflicting resources")
                    recommendations.append("Consider adding NOLOCK hints or adjusting isolation level")

                # Get current blocking info
                blocking = await self._execute_query(BLOCKING_SESSIONS_QUERY)
                if blocking:
                    details["current_blocking"] = blocking
                    recommendations.append("Check if there are still blocking sessions")

                return DiagnosticInfo(
                    platform="sql_server",
                    status="deadlock_detected",
                    details=details,
                    logs=logs,
                    recommendations=recommendations
                )

            # Check for lock timeout
            elif error_code == "1222" or "lock" in error_message.lower():
                blocking = await self._execute_query(BLOCKING_SESSIONS_QUERY)
                if blocking:
                    details["blocking_sessions"] = blocking
                    for session in blocking[:3]:
                        recommendations.append(
                            f"Consider killing blocking session {session['blocking_session_id']} "
                            f"(waiting {session['wait_seconds']:.1f}s)"
                        )

                return DiagnosticInfo(
                    platform="sql_server",
                    status="lock_timeout",
                    details=details,
                    recommendations=recommendations
                )

            # General diagnosis - check procedure stats
            else:
                proc_stats = await self._execute_query(
                    PROCEDURE_STATUS_QUERY,
                    {"procedure_name": job_name}
                )
                if proc_stats:
                    details["procedure_stats"] = proc_stats[0]

                return DiagnosticInfo(
                    platform="sql_server",
                    status="diagnosed",
                    details=details,
                    recommendations=["Review error message and procedure logic"]
                )

        except Exception as e:
            logger.error(f"Diagnosis failed: {e}")
            return DiagnosticInfo(
                platform="sql_server",
                status="diagnosis_failed",
                details=details,
                error=str(e)
            )

    async def execute_remediation(
        self,
        action: str,
        params: Dict[str, Any]
    ) -> RemediationResult:
        """
        Execute a remediation action.

        Supported actions:
        - retry_procedure: Re-execute a stored procedure
        - kill_session: Kill a blocking session
        - clear_plan_cache: Clear the plan cache for a procedure
        """
        try:
            if action == "retry_procedure":
                return await self._retry_procedure(params)
            elif action == "kill_session":
                return await self._kill_session(params)
            elif action == "clear_plan_cache":
                return await self._clear_plan_cache(params)
            else:
                return RemediationResult(
                    success=False,
                    action=action,
                    error=f"Unknown action: {action}"
                )

        except Exception as e:
            logger.error(f"Remediation failed: {e}")
            return RemediationResult(
                success=False,
                action=action,
                error=str(e)
            )

    async def _retry_procedure(self, params: Dict[str, Any]) -> RemediationResult:
        """Retry a stored procedure."""
        procedure_name = params.get("procedure_name")
        proc_params = params.get("params", {})
        max_retries = params.get("max_retries", 3)
        retry_delay = params.get("retry_delay_seconds", 1)

        if not procedure_name:
            return RemediationResult(
                success=False,
                action="retry_procedure",
                error="procedure_name is required"
            )

        # Build the EXEC statement
        param_str = ", ".join(
            f"@{k}={repr(v)}" for k, v in proc_params.items()
        ) if proc_params else ""
        exec_sql = f"EXEC {procedure_name} {param_str}"

        last_error = None
        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Retry attempt {attempt}/{max_retries} for {procedure_name}")
                await self._execute_query(exec_sql)
                return RemediationResult(
                    success=True,
                    action="retry_procedure",
                    details={
                        "procedure_name": procedure_name,
                        "attempts": attempt
                    }
                )
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Attempt {attempt} failed: {e}")
                if attempt < max_retries:
                    await asyncio.sleep(retry_delay)

        return RemediationResult(
            success=False,
            action="retry_procedure",
            details={"attempts": max_retries},
            error=f"All {max_retries} attempts failed. Last error: {last_error}"
        )

    async def _kill_session(self, params: Dict[str, Any]) -> RemediationResult:
        """Kill a database session."""
        session_id = params.get("session_id")

        if not session_id:
            return RemediationResult(
                success=False,
                action="kill_session",
                error="session_id is required"
            )

        try:
            # Get session info first for logging
            session_info = await self._execute_query(
                SESSION_INFO_QUERY,
                {"session_id": session_id}
            )

            # Kill the session
            await self._execute_query(f"KILL {session_id}")

            return RemediationResult(
                success=True,
                action="kill_session",
                details={
                    "session_id": session_id,
                    "session_info": session_info[0] if session_info else {}
                }
            )

        except Exception as e:
            return RemediationResult(
                success=False,
                action="kill_session",
                details={"session_id": session_id},
                error=str(e)
            )

    async def _clear_plan_cache(self, params: Dict[str, Any]) -> RemediationResult:
        """Clear the plan cache."""
        procedure_name = params.get("procedure_name")

        try:
            if procedure_name:
                # Clear plan for specific procedure
                await self._execute_query(
                    f"DBCC FREEPROCCACHE (SELECT plan_handle FROM sys.dm_exec_procedure_stats "
                    f"WHERE object_name(object_id) = '{procedure_name}')"
                )
            else:
                # Clear entire cache (use with caution)
                await self._execute_query("DBCC FREEPROCCACHE")

            return RemediationResult(
                success=True,
                action="clear_plan_cache",
                details={"procedure_name": procedure_name or "ALL"}
            )

        except Exception as e:
            return RemediationResult(
                success=False,
                action="clear_plan_cache",
                error=str(e)
            )

    async def verify_fix(
        self,
        job_name: str,
        expected_state: str,
        context: Optional[Dict[str, Any]] = None
    ) -> VerificationResult:
        """
        Verify that a fix was successful.

        For SQL procedures, checks:
        - No active blocking for the procedure
        - Procedure executed successfully (if retried)
        """
        checks_passed = []
        checks_failed = []
        evidence: Dict[str, Any] = {}

        try:
            # Check for blocking
            blocking = await self._execute_query(BLOCKING_SESSIONS_QUERY)
            if not blocking:
                checks_passed.append("no_blocking")
                evidence["blocking_sessions"] = 0
            else:
                # Check if any blocking relates to our procedure
                related_blocking = [
                    b for b in blocking
                    if job_name.lower() in str(b.get("blocked_query", "")).lower()
                ]
                if not related_blocking:
                    checks_passed.append("no_related_blocking")
                    evidence["blocking_sessions"] = len(blocking)
                else:
                    checks_failed.append("still_blocking")
                    evidence["related_blocking"] = related_blocking

            # Check procedure stats for recent execution
            proc_stats = await self._execute_query(
                PROCEDURE_STATUS_QUERY,
                {"procedure_name": job_name}
            )
            if proc_stats:
                last_exec = proc_stats[0].get("last_execution_time")
                if last_exec:
                    # Check if executed recently (within last minute)
                    if (datetime.now(timezone.utc) - last_exec).total_seconds() < 60:
                        checks_passed.append("recent_execution")
                        evidence["last_execution"] = str(last_exec)
                    else:
                        checks_failed.append("no_recent_execution")

            success = len(checks_failed) == 0 and len(checks_passed) > 0
            confidence = len(checks_passed) / (len(checks_passed) + len(checks_failed)) if checks_passed or checks_failed else 0.5

            return VerificationResult(
                success=success,
                checks_passed=checks_passed,
                checks_failed=checks_failed,
                evidence=evidence,
                confidence=confidence
            )

        except Exception as e:
            return VerificationResult(
                success=False,
                checks_failed=["verification_error"],
                evidence={"error": str(e)},
                confidence=0.0
            )

    def get_error_patterns(self) -> List[Dict[str, Any]]:
        """Get SQL Server error patterns."""
        return [
            {
                "pattern": r"deadlock victim|Error 1205",
                "category": "data_pipeline",
                "issue_type": "deadlock",
                "severity": "P2",
                "remediation_hint": "retry_procedure",
                "auto_remediable": True
            },
            {
                "pattern": r"lock request time out|Error 1222",
                "category": "data_pipeline",
                "issue_type": "lock_timeout",
                "severity": "P2",
                "remediation_hint": "kill_blocking_session",
                "auto_remediable": True
            },
            {
                "pattern": r"transaction log.*full|Error 9002",
                "category": "infrastructure",
                "issue_type": "log_full",
                "severity": "P1",
                "remediation_hint": "backup_transaction_log",
                "auto_remediable": False
            },
            {
                "pattern": r"cannot open database|Error 4060",
                "category": "integration",
                "issue_type": "database_unavailable",
                "severity": "P1",
                "remediation_hint": "check_database_status",
                "auto_remediable": False
            }
        ]

    def get_available_actions(self) -> List[Dict[str, Any]]:
        """Get available remediation actions."""
        return [
            {
                "name": "retry_procedure",
                "display_name": "Retry Stored Procedure",
                "description": "Re-execute the failed stored procedure with retries",
                "params": ["procedure_name", "max_retries", "retry_delay_seconds"],
                "risk_level": "low"
            },
            {
                "name": "kill_session",
                "display_name": "Kill Blocking Session",
                "description": "Terminate a blocking database session",
                "params": ["session_id"],
                "risk_level": "medium"
            },
            {
                "name": "clear_plan_cache",
                "display_name": "Clear Plan Cache",
                "description": "Clear cached query plans",
                "params": ["procedure_name"],
                "risk_level": "low"
            }
        ]


# Also register as azure_sql (same implementation)
ProviderRegistry._providers['azure_sql'] = SQLServerProvider
