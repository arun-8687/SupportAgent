# Support Agent - Pilot Implementation User Stories

## Overview

This document defines the features and user stories for the pilot implementation of the AI-powered Support Agent. The pilot focuses on **SQL Server stored procedure failures** as the initial use case, with architecture designed for expansion to other platforms.

---

## Personas

| Persona | Description |
|---------|-------------|
| **Support Engineer** | First responder to incidents, monitors dashboards, handles escalations |
| **On-Call Engineer** | Receives after-hours alerts, needs quick resolution paths |
| **Team Lead** | Oversees incident resolution, reviews metrics, approves risky actions |
| **Platform Admin** | Configures the system, manages integrations, defines runbooks |
| **Developer** | Owns the failing code/procedure, receives escalations for code fixes |

---

## Epics

| Epic | Description | Priority |
|------|-------------|----------|
| **E1** | Incident Intake & Classification | P0 - MVP |
| **E2** | Automated Diagnosis | P0 - MVP |
| **E3** | Auto-Remediation | P0 - MVP |
| **E4** | Human-in-the-Loop Approval | P0 - MVP |
| **E5** | Observability & Dashboard | P1 - Pilot |
| **E6** | Knowledge Base Management | P1 - Pilot |
| **E7** | Escalation & Notifications | P1 - Pilot |
| **E8** | Reporting & Analytics | P2 - Post-Pilot |
| **E9** | Multi-Platform Expansion | P2 - Post-Pilot |

---

## Epic 1: Incident Intake & Classification (P0 - MVP)

### US-1.1: Receive Incident via API
**As a** monitoring system
**I want to** submit incidents to the Support Agent via REST API
**So that** failures are automatically processed without manual intervention

**Acceptance Criteria:**
- [ ] POST `/api/v1/incidents` accepts incident payload
- [ ] Required fields validated: job_name, job_type, error_message, environment
- [ ] Returns incident_id and initial status
- [ ] Supports SQL Server job type
- [ ] API secured with API key authentication
- [ ] Rate limiting prevents abuse (100 req/min)

**Example Payload:**
```json
{
  "job_name": "usp_ProcessDailyOrders",
  "job_type": "sql_server",
  "source_system": "Azure-SQL-EastUS",
  "environment": "prod",
  "error_message": "Transaction was deadlocked on lock resources",
  "error_code": "1205",
  "priority_hint": "P2"
}
```

---

### US-1.2: Classify Error Type
**As a** Support Agent
**I want to** automatically classify the error type from the error message
**So that** I can route to the appropriate remediation path

**Acceptance Criteria:**
- [ ] Recognizes SQL Server error codes (1205, 1222, 9002, 18456, etc.)
- [ ] Categorizes as: transient, resource, data, configuration, code, unknown
- [ ] Determines if error is auto-remediable
- [ ] Assigns initial severity (P1-P4) based on error type and environment
- [ ] Classification completes in < 2 seconds

**Error Classification Matrix:**
| Error Code | Type | Category | Auto-Remediable |
|------------|------|----------|-----------------|
| 1205 | Deadlock | Transient | Yes |
| 1222 | Lock Timeout | Transient | Yes |
| 9002 | Log Full | Resource | Partial |
| 18456 | Auth Failed | Config | No |

---

### US-1.3: Deduplicate Incidents
**As a** Support Agent
**I want to** detect duplicate and related incidents
**So that** I don't create redundant work and can identify incident storms

**Acceptance Criteria:**
- [ ] Detects exact duplicates (same job, same error, within 15 min)
- [ ] Identifies related incidents (same job family, similar error)
- [ ] Detects event storms (>10 similar incidents in 5 min)
- [ ] Links child incidents to parent
- [ ] Suppresses duplicate processing with reason logged

---

### US-1.4: Correlate with Recent Changes
**As a** Support Agent
**I want to** check for recent changes that might have caused the failure
**So that** I can identify root cause faster

**Acceptance Criteria:**
- [ ] Queries for deployments in last 24 hours affecting the job
- [ ] Checks for schema changes on affected tables
- [ ] Identifies upstream job failures
- [ ] Flags if failure started after a specific change
- [ ] Correlation confidence score provided

---

## Epic 2: Automated Diagnosis (P0 - MVP)

### US-2.1: Gather SQL Server Diagnostics
**As a** Support Agent
**I want to** automatically gather diagnostic information from SQL Server
**So that** I can understand the root cause

**Acceptance Criteria:**
- [ ] Retrieves deadlock graph for Error 1205
- [ ] Gets blocking session information for lock issues
- [ ] Queries procedure execution statistics
- [ ] Captures current session states
- [ ] Diagnostic gathering completes in < 10 seconds
- [ ] Errors handled gracefully if SQL connection fails

---

### US-2.2: Match Known Errors
**As a** Support Agent
**I want to** check if this error matches a known issue with documented resolution
**So that** I can apply proven fixes quickly

**Acceptance Criteria:**
- [ ] Searches knowledge base using error message similarity
- [ ] Returns matching known errors with confidence score
- [ ] Includes documented resolution steps
- [ ] Links to relevant runbooks
- [ ] Match threshold configurable (default: 85%)

---

### US-2.3: Analyze Root Cause with AI
**As a** Support Agent
**I want to** use AI to analyze complex errors without known patterns
**So that** I can diagnose novel issues

**Acceptance Criteria:**
- [ ] Sends error context to Azure OpenAI for analysis
- [ ] Generates root cause hypothesis with confidence
- [ ] Suggests investigation steps
- [ ] Explains reasoning chain
- [ ] AI analysis completes in < 15 seconds

---

### US-2.4: Generate Diagnosis Summary
**As a** Support Engineer
**I want to** see a clear summary of the diagnosis
**So that** I understand what was found and what's recommended

**Acceptance Criteria:**
- [ ] Summary includes: error type, root cause, affected resources
- [ ] Lists evidence gathered
- [ ] Provides confidence level
- [ ] Recommends next action: auto-fix, manual review, or escalate
- [ ] Summary available via API and dashboard

---

## Epic 3: Auto-Remediation (P0 - MVP)

### US-3.1: Retry Failed Stored Procedure
**As a** Support Agent
**I want to** automatically retry a procedure that failed due to a transient error
**So that** temporary issues resolve without human intervention

**Acceptance Criteria:**
- [ ] Retries procedure with configurable attempts (default: 3)
- [ ] Exponential backoff between retries (1s, 2s, 4s)
- [ ] Logs each retry attempt with result
- [ ] Stops retrying after success
- [ ] Escalates after max retries exhausted

---

### US-3.2: Kill Blocking Session
**As a** Support Agent
**I want to** kill a blocking session causing lock timeouts
**So that** blocked queries can proceed

**Acceptance Criteria:**
- [ ] Identifies the blocking session ID
- [ ] Logs session info before killing (user, query, duration)
- [ ] Executes KILL command
- [ ] Verifies session terminated
- [ ] Requires approval for sessions > 5 minutes old
- [ ] Never kills system sessions (SPID < 50)

---

### US-3.3: Clear Procedure Plan Cache
**As a** Support Agent
**I want to** clear the cached query plan for a poorly performing procedure
**So that** SQL Server generates a fresh, optimized plan

**Acceptance Criteria:**
- [ ] Clears plan cache for specific procedure only
- [ ] Logs cache clear action
- [ ] Verifies new plan generated on next execution
- [ ] Low-risk action, no approval required

---

### US-3.4: Propose Remediation Plan
**As a** Support Agent
**I want to** generate a remediation plan with steps and risk assessment
**So that** humans can review before execution

**Acceptance Criteria:**
- [ ] Plan includes ordered list of steps
- [ ] Each step has: action, parameters, risk level
- [ ] Overall risk assessment (low/medium/high)
- [ ] Estimated success probability
- [ ] Rollback plan if applicable
- [ ] Plan stored for audit trail

---

### US-3.5: Execute Remediation with Rollback
**As a** Support Agent
**I want to** execute remediation steps with rollback capability
**So that** I can recover if something goes wrong

**Acceptance Criteria:**
- [ ] Executes steps in order
- [ ] Records state before each step (for rollback)
- [ ] Stops on first failure
- [ ] Triggers rollback on critical failures
- [ ] Logs execution time for each step
- [ ] Reports final status

---

## Epic 4: Human-in-the-Loop Approval (P0 - MVP)

### US-4.1: Request Approval for Risky Actions
**As a** Support Agent
**I want to** request human approval for high-risk remediation actions
**So that** humans maintain control over dangerous operations

**Acceptance Criteria:**
- [ ] Approval required for: P1 incidents, production changes, kill sessions
- [ ] Approval request includes: action details, risk assessment, impact
- [ ] Request sent via configured channel (API, Teams, email)
- [ ] Timeout after 30 minutes with escalation
- [ ] Tracks who approved and when

---

### US-4.2: Approve/Reject via API
**As a** Team Lead
**I want to** approve or reject remediation proposals via API
**So that** I can authorize actions quickly

**Acceptance Criteria:**
- [ ] POST `/api/v1/approvals/{id}/approve` approves action
- [ ] POST `/api/v1/approvals/{id}/reject` rejects with reason
- [ ] Only authorized users can approve
- [ ] Approval immediately triggers execution
- [ ] Rejection escalates incident to human queue

---

### US-4.3: Auto-Approve Low-Risk Actions
**As a** Platform Admin
**I want to** configure auto-approval for low-risk actions
**So that** simple fixes proceed without delay

**Acceptance Criteria:**
- [ ] Configurable auto-approval rules by:
  - Risk level (low only)
  - Environment (non-prod)
  - Action type (retry, cache clear)
  - Confidence threshold (>90%)
- [ ] Auto-approved actions logged with reason
- [ ] Override available for specific jobs

---

### US-4.4: View Pending Approvals
**As a** Team Lead
**I want to** see all pending approval requests
**So that** I don't miss time-sensitive actions

**Acceptance Criteria:**
- [ ] GET `/api/v1/approvals/pending` returns pending list
- [ ] Sorted by urgency (P1 first, oldest first)
- [ ] Shows time remaining before timeout
- [ ] Filterable by environment, job type
- [ ] Dashboard widget for pending approvals

---

## Epic 5: Observability & Dashboard (P1 - Pilot)

### US-5.1: View Active Incidents
**As a** Support Engineer
**I want to** see all active incidents in a dashboard
**So that** I have visibility into current issues

**Acceptance Criteria:**
- [ ] Dashboard shows incidents in progress
- [ ] Displays: job name, error type, status, duration, assigned action
- [ ] Real-time updates (refresh < 5s)
- [ ] Filterable by: severity, environment, status
- [ ] Click-through to incident details

---

### US-5.2: View Incident Timeline
**As a** Support Engineer
**I want to** see the complete timeline of an incident
**So that** I understand what actions were taken

**Acceptance Criteria:**
- [ ] Timeline shows all events chronologically
- [ ] Events include: intake, classification, diagnosis, remediation, verification
- [ ] Each event shows timestamp and duration
- [ ] Tool calls and their results displayed
- [ ] AI reasoning visible for diagnosis steps

---

### US-5.3: Monitor System Health
**As a** Platform Admin
**I want to** monitor the Support Agent's health and performance
**So that** I can ensure it's operating correctly

**Acceptance Criteria:**
- [ ] Health endpoints: `/health/live`, `/health/ready`
- [ ] Prometheus metrics exposed at `/metrics`
- [ ] Key metrics: incidents/hour, MTTR, success rate, AI latency
- [ ] Alerting on: high error rate, slow processing, connection failures
- [ ] Grafana dashboard template provided

---

### US-5.4: View Resolution Metrics
**As a** Team Lead
**I want to** see resolution metrics and trends
**So that** I can measure the system's effectiveness

**Acceptance Criteria:**
- [ ] Metrics dashboard shows:
  - Incidents by severity over time
  - Auto-resolution rate
  - Mean time to resolution (MTTR)
  - Top error types
  - Escalation rate
- [ ] Filterable by date range, environment
- [ ] Export to CSV

---

## Epic 6: Knowledge Base Management (P1 - Pilot)

### US-6.1: Add Known Error
**As a** Platform Admin
**I want to** add known errors with resolutions to the knowledge base
**So that** the system can match and resolve similar issues

**Acceptance Criteria:**
- [ ] POST `/api/v1/knowledge/errors` creates known error
- [ ] Fields: title, error_pattern, root_cause, resolution, runbook_link
- [ ] Error pattern supports regex
- [ ] Generates embedding for similarity search
- [ ] Versioning for updates

**Example:**
```json
{
  "title": "SQL Server Deadlock on Orders Table",
  "error_pattern": "deadlock.*Orders.*OrderItems",
  "root_cause": "Concurrent updates to Orders and OrderItems with different lock order",
  "resolution": "Retry transaction, consider adding NOLOCK hints",
  "auto_remediation": "retry_procedure",
  "tags": ["sql_server", "deadlock", "transient"]
}
```

---

### US-6.2: Learn from Resolved Incidents
**As a** Support Agent
**I want to** learn from successfully resolved incidents
**So that** I can handle similar issues faster next time

**Acceptance Criteria:**
- [ ] After successful resolution, prompt to add to knowledge base
- [ ] Extracts error pattern from incident
- [ ] Records resolution steps taken
- [ ] Links to incident for context
- [ ] Requires human review before adding

---

### US-6.3: Search Knowledge Base
**As a** Support Engineer
**I want to** search the knowledge base manually
**So that** I can find resolutions for issues I'm investigating

**Acceptance Criteria:**
- [ ] GET `/api/v1/knowledge/search?q=...` searches knowledge base
- [ ] Hybrid search: keyword + semantic similarity
- [ ] Returns ranked results with relevance score
- [ ] Filterable by category, tags, platform
- [ ] Results include resolution steps

---

## Epic 7: Escalation & Notifications (P1 - Pilot)

### US-7.1: Escalate to Human Queue
**As a** Support Agent
**I want to** escalate incidents I cannot resolve automatically
**So that** humans can take over

**Acceptance Criteria:**
- [ ] Escalation triggered when:
  - Max retries exhausted
  - Confidence below threshold
  - Unknown error type
  - Human review required flag set
- [ ] Escalated incident marked with reason
- [ ] Assigned to human queue with priority
- [ ] All diagnostic info preserved

---

### US-7.2: Send Notifications
**As a** On-Call Engineer
**I want to** receive notifications for escalated incidents
**So that** I'm aware of issues needing attention

**Acceptance Criteria:**
- [ ] Notification channels: Teams webhook, email, PagerDuty
- [ ] Configurable per severity level
- [ ] Notification includes: summary, severity, link to dashboard
- [ ] P1 incidents trigger immediate notification
- [ ] Batching for lower priority (every 15 min digest)

---

### US-7.3: Escalate to Developer
**As a** Support Agent
**I want to** escalate code-related issues to the responsible developer
**So that** bugs get fixed at the source

**Acceptance Criteria:**
- [ ] Identifies code owner from job metadata or config
- [ ] Creates ticket in configured system (Jira, Azure DevOps)
- [ ] Ticket includes: error details, diagnosis, suggested fix
- [ ] Links incident to ticket
- [ ] Tracks ticket status

---

## Epic 8: Reporting & Analytics (P2 - Post-Pilot)

### US-8.1: Generate Incident Report
**As a** Team Lead
**I want to** generate incident reports for management
**So that** I can communicate system health and improvements

**Acceptance Criteria:**
- [ ] Weekly/monthly report generation
- [ ] Includes: incident counts, MTTR trends, top errors, resolution rates
- [ ] Comparison with previous period
- [ ] Exportable as PDF/Excel

---

### US-8.2: Identify Recurring Issues
**As a** Platform Admin
**I want to** identify recurring issues that need permanent fixes
**So that** I can prioritize technical debt

**Acceptance Criteria:**
- [ ] Report shows jobs with >3 incidents in 30 days
- [ ] Groups by error type and root cause
- [ ] Estimates time spent on recurring issues
- [ ] Suggests permanent fix actions

---

## Epic 9: Multi-Platform Expansion (P2 - Post-Pilot)

### US-9.1: Add Databricks Provider
**As a** Platform Admin
**I want to** add support for Databricks job failures
**So that** Spark jobs are also auto-remediated

**Acceptance Criteria:**
- [ ] Databricks provider implemented
- [ ] Actions: restart job, scale cluster, clear cache
- [ ] Error patterns: OOM, cluster terminated, schema mismatch
- [ ] Integration with Databricks REST API

---

### US-9.2: Add Azure Data Factory Provider
**As a** Platform Admin
**I want to** add support for ADF pipeline failures
**So that** ETL pipelines are also covered

**Acceptance Criteria:**
- [ ] ADF provider implemented
- [ ] Actions: rerun pipeline, restart IR
- [ ] Error patterns: IR unavailable, source timeout
- [ ] Integration with ADF REST API

---

### US-9.3: Add Custom Provider via Plugin
**As a** Developer
**I want to** add custom providers without modifying core code
**So that** I can support internal platforms

**Acceptance Criteria:**
- [ ] Plugin interface documented
- [ ] Example plugin provided
- [ ] Hot-reload of plugins supported
- [ ] Plugin validation on load

---

## Pilot Success Criteria

### Quantitative Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Auto-resolution rate | >60% of transient errors | Incidents resolved without human intervention |
| MTTR improvement | >50% reduction | Compared to manual resolution baseline |
| False positive rate | <5% | Incorrect diagnoses or failed remediations |
| System availability | >99% | Support Agent uptime |
| Processing latency | <30s to proposal | Time from intake to remediation proposal |

### Qualitative Criteria

- [ ] Support engineers report reduced toil
- [ ] On-call burden measurably decreased
- [ ] No critical incidents caused by auto-remediation
- [ ] Knowledge base actively used and growing
- [ ] Positive feedback from pilot users

---

## Pilot Timeline

| Phase | Duration | Focus |
|-------|----------|-------|
| **Phase 1** | Week 1-2 | E1 (Intake) + E2 (Diagnosis) |
| **Phase 2** | Week 3-4 | E3 (Remediation) + E4 (Approval) |
| **Phase 3** | Week 5-6 | E5 (Dashboard) + E6 (Knowledge Base) |
| **Phase 4** | Week 7-8 | E7 (Escalation) + Testing + Refinement |
| **Pilot Run** | Week 9-12 | Production pilot with real incidents |

---

## Out of Scope for Pilot

- Multi-tenant support
- Custom workflow designer
- Mobile app
- Integration with all ITSM platforms
- Predictive incident prevention
- Cost optimization recommendations
