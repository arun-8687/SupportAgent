"""
Error Classification for intelligent remediation decisions.

A senior SRE perspective: Not all errors are equal.
- Transient: Retry will likely work
- Deterministic: Same input = same failure, don't waste time retrying
- Resource: Might work with more resources, but ask WHY first
- Code: Needs human intervention, don't auto-fix
"""
import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple


class ErrorCategory(Enum):
    """Primary error classification."""
    TRANSIENT = "transient"           # Retry likely helps
    RESOURCE = "resource"             # Might need more resources
    DETERMINISTIC = "deterministic"   # Same input = same failure
    CODE = "code"                     # Bug in job logic
    DATA = "data"                     # Bad input data
    INFRASTRUCTURE = "infrastructure" # Platform issue
    UNKNOWN = "unknown"


class RemediationStrategy(Enum):
    """What action to take."""
    RETRY_IMMEDIATE = "retry_immediate"     # Just retry now
    RETRY_WITH_BACKOFF = "retry_backoff"    # Retry after delay
    SCALE_AND_RETRY = "scale_and_retry"     # Increase resources, then retry
    INVESTIGATE_FIRST = "investigate"       # Gather more info before acting
    ESCALATE_HUMAN = "escalate"             # Human needs to look at this
    WAIT_DEPENDENCY = "wait_dependency"     # Upstream issue, wait for it


@dataclass
class ErrorClassification:
    """Result of error analysis."""
    category: ErrorCategory
    strategy: RemediationStrategy
    confidence: float
    reasoning: str

    # For resource errors
    resource_type: Optional[str] = None  # memory, cpu, disk, network
    estimated_need: Optional[str] = None # "16GB", "2x current"

    # For transient errors
    suggested_wait_seconds: int = 0
    max_retries: int = 0

    # Is this a workaround or real fix?
    is_workaround: bool = False
    follow_up_required: bool = False
    follow_up_reason: Optional[str] = None


class ErrorClassifier:
    """
    Classifies errors to determine appropriate remediation strategy.

    Philosophy:
    1. Don't retry deterministic failures (waste of time)
    2. Don't auto-scale without understanding why (waste of money)
    3. Distinguish between "fixed" and "worked around"
    4. Know when to stop and call a human
    """

    # Patterns that indicate transient issues - RETRY THESE
    TRANSIENT_PATTERNS = [
        # Network/connectivity
        (r"Connection reset|Connection refused", "Network glitch"),
        (r"timeout|timed out|TimeoutException", "Timeout - may recover"),
        (r"Could not connect to", "Connectivity issue"),
        (r"SSLHandshakeException", "TLS negotiation failed"),

        # Cluster/infrastructure transient
        (r"ClusterTerminatedException", "Cluster died - spot instance or preemption"),
        (r"RESOURCE_DOES_NOT_EXIST", "Resource timing issue"),
        (r"Cluster is not in RUNNING state", "Cluster not ready yet"),
        (r"temporarily unavailable", "Service temporarily down"),

        # Rate limiting
        (r"429|Too Many Requests|rate limit", "Rate limited - backoff"),
        (r"throttl", "Throttled"),

        # Transient Spark issues
        (r"FetchFailedException", "Shuffle fetch failed - executor died"),
        (r"Stage cancelled because SparkContext was shut down", "Context died"),
    ]

    # Patterns that indicate resource exhaustion - MAYBE SCALE
    RESOURCE_PATTERNS = [
        # Memory
        (r"OutOfMemoryError.*heap", "memory", "Driver/executor heap exhausted"),
        (r"Container killed by YARN for exceeding memory", "memory", "Container OOM"),
        (r"GC overhead limit exceeded", "memory", "GC thrashing - needs more heap"),
        (r"Unable to acquire memory", "memory", "Spark memory pressure"),
        (r"java.lang.OutOfMemoryError: Metaspace", "metaspace", "Class loading exhausted"),

        # Disk
        (r"No space left on device", "disk", "Disk full"),
        (r"IOException.*Disk", "disk", "Disk I/O issue"),
        (r"shuffle.*spill", "disk", "Heavy shuffle spill"),

        # Slots/parallelism
        (r"Could not allocate executor", "executors", "Not enough cluster capacity"),
    ]

    # Patterns that indicate code/logic bugs - DON'T AUTO-FIX
    CODE_PATTERNS = [
        (r"AnalysisException", "SQL/Schema error in code"),
        (r"ClassNotFoundException|NoClassDefFoundError", "Missing dependency"),
        (r"NoSuchMethodError|NoSuchFieldError", "Version mismatch"),
        (r"NullPointerException", "Code bug - null handling"),
        (r"ArrayIndexOutOfBoundsException", "Code bug - array access"),
        (r"IllegalArgumentException", "Invalid argument in code"),
        (r"UnsupportedOperationException", "Operation not supported"),
        (r"AssertionError", "Assertion failed"),
        (r"SyntaxError|ParseException", "Syntax error in code"),
    ]

    # Patterns that indicate data issues - INVESTIGATE SOURCE
    DATA_PATTERNS = [
        (r"FileNotFoundException|Path does not exist", "Missing input file"),
        (r"CorruptRecordException", "Corrupt data"),
        (r"MalformedInputException", "Malformed input"),
        (r"Schema mismatch|column.*not found", "Schema changed"),
        (r"NumberFormatException", "Invalid data format"),
        (r"DateTimeParseException", "Invalid date format"),
        (r"JsonParseException|JSONDecodeError", "Invalid JSON"),
    ]

    def classify(
        self,
        error_message: str,
        stack_trace: Optional[str] = None,
        retry_count: int = 0,
        recent_data_volume_change: Optional[float] = None,
        recent_code_change: bool = False
    ) -> ErrorClassification:
        """
        Classify an error and recommend remediation strategy.

        Args:
            error_message: The error message
            stack_trace: Optional stack trace for deeper analysis
            retry_count: How many times we've already retried
            recent_data_volume_change: % change in data volume (e.g., 3.0 = 3x increase)
            recent_code_change: Whether there was a recent code deployment
        """
        full_text = f"{error_message}\n{stack_trace or ''}"

        # Check patterns in order of specificity

        # 1. Code bugs - never auto-fix
        for pattern, reason in self.CODE_PATTERNS:
            if re.search(pattern, full_text, re.IGNORECASE):
                return ErrorClassification(
                    category=ErrorCategory.CODE,
                    strategy=RemediationStrategy.ESCALATE_HUMAN,
                    confidence=0.9,
                    reasoning=f"Code issue detected: {reason}",
                    is_workaround=False,
                    follow_up_required=False  # Human will handle
                )

        # 2. Data issues - investigate before acting
        for pattern, reason in self.DATA_PATTERNS:
            if re.search(pattern, full_text, re.IGNORECASE):
                return ErrorClassification(
                    category=ErrorCategory.DATA,
                    strategy=RemediationStrategy.INVESTIGATE_FIRST,
                    confidence=0.85,
                    reasoning=f"Data issue: {reason}. Check upstream data source.",
                    is_workaround=False,
                    follow_up_required=True,
                    follow_up_reason="Investigate data source for root cause"
                )

        # 3. Resource exhaustion - careful here
        for pattern, resource_type, reason in self.RESOURCE_PATTERNS:
            if re.search(pattern, full_text, re.IGNORECASE):
                return self._classify_resource_error(
                    resource_type=resource_type,
                    reason=reason,
                    retry_count=retry_count,
                    data_volume_change=recent_data_volume_change,
                    recent_code_change=recent_code_change,
                    full_text=full_text
                )

        # 4. Transient errors - retry with appropriate strategy
        for pattern, reason in self.TRANSIENT_PATTERNS:
            if re.search(pattern, full_text, re.IGNORECASE):
                return self._classify_transient_error(
                    reason=reason,
                    retry_count=retry_count
                )

        # 5. Unknown - be conservative
        return ErrorClassification(
            category=ErrorCategory.UNKNOWN,
            strategy=RemediationStrategy.INVESTIGATE_FIRST if retry_count == 0
                     else RemediationStrategy.ESCALATE_HUMAN,
            confidence=0.5,
            reasoning="Unknown error pattern. Investigating before action.",
            max_retries=1,
            follow_up_required=True,
            follow_up_reason="Unknown error pattern - add to classification rules"
        )

    def _classify_resource_error(
        self,
        resource_type: str,
        reason: str,
        retry_count: int,
        data_volume_change: Optional[float],
        recent_code_change: bool,
        full_text: str
    ) -> ErrorClassification:
        """
        Classify resource exhaustion errors with nuance.

        Key insight: Just because we CAN scale doesn't mean we SHOULD.
        """
        # If there was a recent code change, the code might be the problem
        if recent_code_change:
            return ErrorClassification(
                category=ErrorCategory.RESOURCE,
                strategy=RemediationStrategy.INVESTIGATE_FIRST,
                confidence=0.8,
                reasoning=f"{reason}. Recent code change detected - investigate if code is inefficient.",
                resource_type=resource_type,
                is_workaround=True,
                follow_up_required=True,
                follow_up_reason="Recent code change may have introduced inefficiency"
            )

        # If data volume increased significantly, scaling might be appropriate
        if data_volume_change and data_volume_change > 1.5:
            # Data grew 50%+ - scaling is reasonable
            return ErrorClassification(
                category=ErrorCategory.RESOURCE,
                strategy=RemediationStrategy.SCALE_AND_RETRY,
                confidence=0.75,
                reasoning=f"{reason}. Data volume increased {data_volume_change:.1f}x - scaling is justified.",
                resource_type=resource_type,
                estimated_need=self._estimate_resource_need(resource_type, data_volume_change),
                is_workaround=False,  # This is legitimate growth
                follow_up_required=True,
                follow_up_reason="Monitor if resource needs continue growing - may need architecture review"
            )

        # Check for patterns that suggest bad code vs legitimate need
        bad_patterns = [
            (r"collect\(\)|\.collect\s*\(", "collect() pulling data to driver"),
            (r"toPandas\(\)", "toPandas() pulling all data to driver"),
            (r"broadcast.*join", "Broadcasting large dataset"),
            (r"crossJoin|cross join", "Cross join causing explosion"),
        ]

        for pattern, code_issue in bad_patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                return ErrorClassification(
                    category=ErrorCategory.CODE,
                    strategy=RemediationStrategy.ESCALATE_HUMAN,
                    confidence=0.85,
                    reasoning=f"{reason}. Likely caused by: {code_issue}. Scaling won't fix the pattern.",
                    resource_type=resource_type,
                    is_workaround=True,
                    follow_up_required=True,
                    follow_up_reason=f"Code review needed: {code_issue}"
                )

        # No clear cause - be conservative
        if retry_count == 0:
            return ErrorClassification(
                category=ErrorCategory.RESOURCE,
                strategy=RemediationStrategy.INVESTIGATE_FIRST,
                confidence=0.6,
                reasoning=f"{reason}. No clear cause (no data growth, no code change). Investigate before scaling.",
                resource_type=resource_type,
                is_workaround=True,
                follow_up_required=True,
                follow_up_reason="Unclear why resource exhaustion occurred"
            )
        else:
            # Already investigated/retried - escalate
            return ErrorClassification(
                category=ErrorCategory.RESOURCE,
                strategy=RemediationStrategy.ESCALATE_HUMAN,
                confidence=0.7,
                reasoning=f"{reason}. Already retried {retry_count}x without success. Human review needed.",
                resource_type=resource_type,
                is_workaround=True,
                follow_up_required=True,
                follow_up_reason="Repeated resource exhaustion - architecture review needed"
            )

    def _classify_transient_error(
        self,
        reason: str,
        retry_count: int
    ) -> ErrorClassification:
        """Classify transient errors with exponential backoff logic."""

        max_retries = 3

        if retry_count >= max_retries:
            # Exceeded retries - not actually transient
            return ErrorClassification(
                category=ErrorCategory.TRANSIENT,
                strategy=RemediationStrategy.ESCALATE_HUMAN,
                confidence=0.8,
                reasoning=f"{reason}. Retried {retry_count}x - not recovering. May be persistent issue.",
                max_retries=0,
                follow_up_required=True,
                follow_up_reason="Transient error persisted - investigate infrastructure"
            )

        # Calculate backoff: 30s, 60s, 120s
        wait_seconds = 30 * (2 ** retry_count)

        return ErrorClassification(
            category=ErrorCategory.TRANSIENT,
            strategy=RemediationStrategy.RETRY_WITH_BACKOFF if retry_count > 0
                     else RemediationStrategy.RETRY_IMMEDIATE,
            confidence=0.85 - (retry_count * 0.1),  # Less confident with each retry
            reasoning=f"{reason}. Retry {retry_count + 1}/{max_retries}.",
            suggested_wait_seconds=wait_seconds,
            max_retries=max_retries - retry_count,
            is_workaround=False,
            follow_up_required=False
        )

    def _estimate_resource_need(
        self,
        resource_type: str,
        data_growth: float
    ) -> str:
        """Estimate how much more resource is needed."""
        if resource_type == "memory":
            # Don't just match growth - add buffer
            multiplier = min(data_growth * 1.2, 4.0)  # Cap at 4x
            return f"{multiplier:.1f}x current"
        elif resource_type == "disk":
            return f"{data_growth * 1.5:.1f}x current"
        elif resource_type == "executors":
            return f"{data_growth:.1f}x current"
        return "unknown"
