// Types mirror the FastAPI payloads (sre_agent/webapi). Keep in sync with
// serializers.py and incident_index.py / step_events.py.

export interface Me {
  identity: string;
  provider: string;
  roles: string[];
  can_approve: boolean;
  verified: boolean;
}

export interface IncidentRow {
  incident_id: string;
  app_code: string;
  service_name: string;
  severity: string;
  environment: string;
  title: string;
  status: string;
  awaiting_approval: boolean;
  ticket_id: string | null;
  resolution_summary: string | null;
  created_at: number;
  updated_at: number;
}

export interface IncidentList {
  items: IncidentRow[];
  total: number;
  limit: number;
  offset: number;
}

export interface StepEvent {
  seq: number;
  incident_id: string;
  step: string;
  status: string;
  duration_ms: number | null;
  fields: Record<string, unknown>;
  ts: number;
}

// The full investigation state is intentionally loose: it is the serialized
// LangGraph state (redacted). We read known slices defensively.
export interface IncidentDetail {
  index: IncidentRow | null;
  state: IncidentState | null;
  awaiting_approval: boolean;
}

export interface MitigationAction {
  action_id: string;
  skill?: string;
  description?: string;
  risk?: string;
  [k: string]: unknown;
}

export interface GateDecision {
  action_id: string;
  outcome: string;
  matched_rule?: string;
  reason?: string;
}

export interface IncidentState {
  incident?: {
    incident_id: string;
    service_name: string;
    app_code: string;
    severity: string;
    environment: string;
    alert?: { title?: string; description?: string; raw?: unknown };
  };
  status?: string;
  triage?: { severity?: string; category?: string; summary?: string };
  root_cause?: {
    hypothesis?: string;
    confidence?: number;
    correlated_change?: string | null;
  };
  mitigation_plan?: { actions?: MitigationAction[]; summary?: string; risk?: string };
  gate_decisions?: GateDecision[];
  approval?: { approved?: boolean; approver?: string; reason?: string } | null;
  execution?: { success?: boolean; summary?: string } | null;
  verification?: { resolved?: boolean; summary?: string } | null;
  ticket?: { ticket_id?: string; url?: string | null } | null;
  resolution_summary?: string | null;
  [k: string]: unknown;
}

export interface PendingApproval {
  incident_id: string;
  created_at: number;
  incident: IncidentRow | null;
}

export interface MetricsSummary {
  total: number;
  by_status: Record<string, number>;
  awaiting_approval: number;
  mttr_seconds: number | null;
}

export interface ApprovalResult {
  incident_id: string;
  status: string;
  resolution_summary?: string | null;
  [k: string]: unknown;
}
