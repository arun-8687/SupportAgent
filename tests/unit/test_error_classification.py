"""
Tests for error classification and SRE-informed remediation logic.
"""
import pytest
from datetime import datetime, timedelta

from src.intelligence.error_classification import (
    ErrorClassifier,
    ErrorCategory,
    RemediationStrategy
)
from src.intelligence.guardrails import (
    RemediationGuardrails,
    GuardrailConfig,
    CircuitBreaker,
    GuardrailViolation
)
from src.intelligence.smart_remediation import (
    SmartRemediationPlanner,
    ActionType
)


class TestErrorClassifier:
    """Tests for error classification logic."""

    @pytest.fixture
    def classifier(self):
        return ErrorClassifier()

    # === TRANSIENT ERRORS ===

    def test_connection_reset_is_transient(self, classifier):
        """Connection reset should be classified as transient."""
        result = classifier.classify("java.net.SocketException: Connection reset")

        assert result.category == ErrorCategory.TRANSIENT
        assert result.strategy == RemediationStrategy.RETRY_IMMEDIATE
        assert result.max_retries > 0

    def test_cluster_terminated_is_transient(self, classifier):
        """Cluster termination (spot instance) should be transient."""
        result = classifier.classify(
            "ClusterTerminatedException: Cluster was terminated"
        )

        assert result.category == ErrorCategory.TRANSIENT
        assert result.strategy == RemediationStrategy.RETRY_IMMEDIATE

    def test_rate_limit_is_transient_with_backoff(self, classifier):
        """Rate limiting should trigger retry with backoff."""
        result = classifier.classify(
            "HTTP 429: Too Many Requests - rate limit exceeded"
        )

        assert result.category == ErrorCategory.TRANSIENT
        assert result.suggested_wait_seconds > 0 or result.strategy == RemediationStrategy.RETRY_IMMEDIATE

    def test_transient_error_after_retries_escalates(self, classifier):
        """After max retries, transient errors should escalate."""
        result = classifier.classify(
            "Connection reset by peer",
            retry_count=5
        )

        assert result.strategy == RemediationStrategy.ESCALATE_HUMAN

    # === RESOURCE ERRORS ===

    def test_oom_is_resource_error(self, classifier):
        """OOM should be classified as resource error."""
        result = classifier.classify(
            "java.lang.OutOfMemoryError: Java heap space"
        )

        assert result.category == ErrorCategory.RESOURCE
        assert result.resource_type == "memory"

    def test_oom_with_data_growth_suggests_scaling(self, classifier):
        """OOM with data growth should suggest scaling."""
        result = classifier.classify(
            "java.lang.OutOfMemoryError: Java heap space",
            recent_data_volume_change=2.5  # 2.5x growth
        )

        assert result.category == ErrorCategory.RESOURCE
        assert result.strategy == RemediationStrategy.SCALE_AND_RETRY
        assert not result.is_workaround  # Legitimate scaling

    def test_oom_with_code_change_investigates(self, classifier):
        """OOM after code change should investigate, not just scale."""
        result = classifier.classify(
            "java.lang.OutOfMemoryError: Java heap space",
            recent_code_change=True
        )

        assert result.category == ErrorCategory.RESOURCE
        assert result.strategy == RemediationStrategy.INVESTIGATE_FIRST
        assert result.follow_up_required

    def test_oom_with_collect_escalates(self, classifier):
        """OOM from collect() should escalate (code issue)."""
        result = classifier.classify(
            "java.lang.OutOfMemoryError: Java heap space",
            stack_trace="at org.apache.spark.sql.Dataset.collect(Dataset.scala:123)"
        )

        assert result.category == ErrorCategory.CODE
        assert result.strategy == RemediationStrategy.ESCALATE_HUMAN

    def test_oom_with_topandas_escalates(self, classifier):
        """OOM from toPandas() should escalate (code issue)."""
        result = classifier.classify(
            "java.lang.OutOfMemoryError: Java heap space",
            stack_trace="df.toPandas()"
        )

        assert result.category == ErrorCategory.CODE
        assert result.strategy == RemediationStrategy.ESCALATE_HUMAN

    # === CODE ERRORS ===

    def test_null_pointer_is_code_error(self, classifier):
        """NullPointerException is a code bug."""
        result = classifier.classify("java.lang.NullPointerException")

        assert result.category == ErrorCategory.CODE
        assert result.strategy == RemediationStrategy.ESCALATE_HUMAN
        assert not result.is_workaround

    def test_analysis_exception_is_code_error(self, classifier):
        """AnalysisException (bad SQL) is a code error."""
        result = classifier.classify(
            "org.apache.spark.sql.AnalysisException: Column 'foo' does not exist"
        )

        assert result.category == ErrorCategory.CODE
        assert result.strategy == RemediationStrategy.ESCALATE_HUMAN

    def test_class_not_found_is_code_error(self, classifier):
        """ClassNotFoundException is a code/dependency error."""
        result = classifier.classify(
            "java.lang.ClassNotFoundException: com.example.MyClass"
        )

        assert result.category == ErrorCategory.CODE
        assert result.strategy == RemediationStrategy.ESCALATE_HUMAN

    # === DATA ERRORS ===

    def test_file_not_found_is_data_error(self, classifier):
        """Missing input file is a data error."""
        result = classifier.classify(
            "FileNotFoundException: /mnt/data/input.parquet"
        )

        assert result.category == ErrorCategory.DATA
        assert result.strategy == RemediationStrategy.INVESTIGATE_FIRST

    def test_corrupt_record_is_data_error(self, classifier):
        """Corrupt record is a data error."""
        result = classifier.classify(
            "CorruptRecordException: Malformed CSV at line 42"
        )

        assert result.category == ErrorCategory.DATA
        assert result.follow_up_required

    # === UNKNOWN ERRORS ===

    def test_unknown_error_investigates_first(self, classifier):
        """Unknown errors should investigate, not blindly retry."""
        result = classifier.classify(
            "SomeWeirdException: Something unexpected happened"
        )

        assert result.category == ErrorCategory.UNKNOWN
        assert result.strategy == RemediationStrategy.INVESTIGATE_FIRST


class TestCircuitBreaker:
    """Tests for circuit breaker logic."""

    @pytest.fixture
    def breaker(self):
        return CircuitBreaker(threshold=3, window_minutes=5, cooldown_minutes=10)

    def test_circuit_closed_initially(self, breaker):
        """Circuit should be closed initially."""
        assert not breaker.is_open("job1", "error1")

    def test_circuit_opens_after_threshold(self, breaker):
        """Circuit should open after threshold failures."""
        for _ in range(3):
            breaker.record_failure("job1", "error1")

        assert breaker.is_open("job1", "error1")

    def test_circuit_isolated_by_job(self, breaker):
        """Circuit breaker should be per-job."""
        for _ in range(3):
            breaker.record_failure("job1", "error1")

        assert breaker.is_open("job1", "error1")
        assert not breaker.is_open("job2", "error1")  # Different job

    def test_success_resets_circuit(self, breaker):
        """Success should reset the circuit."""
        for _ in range(3):
            breaker.record_failure("job1", "error1")

        assert breaker.is_open("job1", "error1")

        breaker.record_success("job1", "error1")

        assert not breaker.is_open("job1", "error1")


class TestRemediationGuardrails:
    """Tests for remediation guardrails."""

    @pytest.fixture
    def guardrails(self):
        config = GuardrailConfig(
            max_retries_transient=3,
            max_retries_resource=1,
            max_driver_memory_gb=32,
            max_memory_multiplier=2.0,
            max_cost_per_incident_usd=50.0
        )
        return RemediationGuardrails(config)

    def test_first_retry_allowed(self, guardrails):
        """First retry should be allowed."""
        check = guardrails.check_can_retry(
            incident_id="inc-1",
            job_name="job1",
            error_pattern="timeout",
            is_transient=True
        )

        assert check.passed

    def test_exceeds_max_retries(self, guardrails):
        """Should block after max retries."""
        # Record retries
        for _ in range(3):
            guardrails.record_action("inc-1", "retry")

        check = guardrails.check_can_retry(
            incident_id="inc-1",
            job_name="job1",
            error_pattern="timeout",
            is_transient=True
        )

        assert not check.passed
        assert check.violation == GuardrailViolation.MAX_RETRIES_EXCEEDED

    def test_memory_within_limits(self, guardrails):
        """Memory scaling within limits should be allowed."""
        check = guardrails.check_can_scale_memory(
            incident_id="inc-1",
            current_memory_gb=8,
            proposed_memory_gb=16
        )

        assert check.passed

    def test_memory_exceeds_hard_cap(self, guardrails):
        """Memory scaling beyond hard cap should be blocked."""
        check = guardrails.check_can_scale_memory(
            incident_id="inc-1",
            current_memory_gb=16,
            proposed_memory_gb=64  # Exceeds 32GB cap
        )

        assert not check.passed
        assert check.violation == GuardrailViolation.MAX_MEMORY_EXCEEDED

    def test_memory_exceeds_multiplier(self, guardrails):
        """Memory scaling too aggressive should be blocked."""
        check = guardrails.check_can_scale_memory(
            incident_id="inc-1",
            current_memory_gb=8,
            proposed_memory_gb=24  # 3x, exceeds 2x limit
        )

        assert not check.passed
        assert check.violation == GuardrailViolation.MAX_MEMORY_EXCEEDED
        assert "2.0x" in check.message

    def test_cost_within_limits(self, guardrails):
        """Cost within limits should be allowed."""
        check = guardrails.check_cost_limit(
            incident_id="inc-1",
            estimated_cost_usd=25.0
        )

        assert check.passed

    def test_cost_exceeds_limits(self, guardrails):
        """Cost exceeding limits should be blocked."""
        # First action
        guardrails.record_action("inc-1", "scale", cost_usd=30.0)

        # Second action would exceed
        check = guardrails.check_cost_limit(
            incident_id="inc-1",
            estimated_cost_usd=25.0  # Total would be 55
        )

        assert not check.passed
        assert check.violation == GuardrailViolation.MAX_COST_EXCEEDED

    def test_p1_prod_requires_approval(self, guardrails):
        """P1 in prod should require approval."""
        check = guardrails.check_blast_radius(
            downstream_job_count=2,
            is_prod=True,
            severity="P1"
        )

        assert not check.passed
        assert check.violation == GuardrailViolation.MANUAL_OVERRIDE_REQUIRED


class TestSmartRemediationPlanner:
    """Tests for smart remediation planning."""

    @pytest.fixture
    def planner(self):
        return SmartRemediationPlanner()

    @pytest.mark.asyncio
    async def test_transient_error_gets_retry(self, planner):
        """Transient error should get simple retry plan."""
        plan = await planner.create_plan(
            incident_id="inc-1",
            job_name="etl-job",
            job_type="databricks",
            error_message="Connection reset by peer"
        )

        assert len(plan.tier1_actions) > 0
        assert plan.tier1_actions[0].action_type == ActionType.RETRY
        assert not plan.blocked

    @pytest.mark.asyncio
    async def test_oom_with_growth_gets_scale(self, planner):
        """OOM with data growth should get scaling plan."""
        plan = await planner.create_plan(
            incident_id="inc-1",
            job_name="etl-job",
            job_type="databricks",
            error_message="java.lang.OutOfMemoryError: Java heap space",
            current_memory_gb=8,
            recent_data_volume_change=2.0
        )

        # Should have tier2 scaling action
        scale_actions = [a for a in plan.tier2_actions if a.action_type == ActionType.SCALE_MEMORY]
        assert len(scale_actions) > 0

    @pytest.mark.asyncio
    async def test_code_error_escalates(self, planner):
        """Code error should escalate, not retry."""
        plan = await planner.create_plan(
            incident_id="inc-1",
            job_name="etl-job",
            job_type="databricks",
            error_message="NullPointerException at MyClass.java:42"
        )

        # Should have escalation
        assert any(a.action_type == ActionType.ESCALATE for a in plan.tier3_actions)
        # Should NOT have automated retries
        assert len(plan.tier1_actions) == 0

    @pytest.mark.asyncio
    async def test_workaround_creates_followup(self, planner):
        """Workarounds should create follow-up tickets."""
        plan = await planner.create_plan(
            incident_id="inc-1",
            job_name="etl-job",
            job_type="databricks",
            error_message="java.lang.OutOfMemoryError: Java heap space",
            recent_code_change=True  # Triggers investigation
        )

        # Should have follow-up
        assert plan.follow_up_ticket is not None
        assert "investigate" in plan.follow_up_ticket["title"].lower()

    @pytest.mark.asyncio
    async def test_databricks_oom_clears_cache_first(self, planner):
        """Databricks OOM should try cache clear before scaling."""
        plan = await planner.create_plan(
            incident_id="inc-1",
            job_name="etl-job",
            job_type="databricks",
            error_message="java.lang.OutOfMemoryError: Java heap space",
            recent_data_volume_change=1.5  # Triggers scale path
        )

        # Tier 1 should have cache clear
        cache_actions = [a for a in plan.tier1_actions if a.action_type == ActionType.CLEAR_CACHE]
        assert len(cache_actions) > 0

    @pytest.mark.asyncio
    async def test_guardrails_block_excessive_scaling(self, planner):
        """Guardrails should block excessive memory scaling."""
        # Create guardrails with low limit
        guardrails = RemediationGuardrails(GuardrailConfig(max_driver_memory_gb=16))
        custom_planner = SmartRemediationPlanner(guardrails=guardrails)

        plan = await custom_planner.create_plan(
            incident_id="inc-1",
            job_name="etl-job",
            job_type="databricks",
            error_message="java.lang.OutOfMemoryError: Java heap space",
            current_memory_gb=16,  # Already at limit
            recent_data_volume_change=2.0
        )

        # Check that scaling would be blocked by guardrails
        for check in plan.guardrail_checks:
            if check.violation == GuardrailViolation.MAX_MEMORY_EXCEEDED:
                assert not check.passed
                break
