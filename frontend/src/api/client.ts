// Typed fetch client for the SRE Agent API. Same-origin in production;
// Vite proxies /api in dev. Throws ApiError on non-2xx so React Query can
// surface error states.
import type {
  ApprovalResult,
  IncidentDetail,
  IncidentList,
  Me,
  MetricsSummary,
  PendingApproval,
  StepEvent,
} from './types';

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    headers: { 'content-type': 'application/json' },
    ...init,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.error || body.detail || detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export interface IncidentQuery {
  status?: string;
  app_code?: string;
  severity?: string;
  service_name?: string;
  awaiting_approval?: boolean;
  sort?: string;
  descending?: boolean;
  limit?: number;
  offset?: number;
}

function qs(params: Record<string, unknown>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : '';
}

export const api = {
  me: () => request<Me>('/me'),
  incidents: (q: IncidentQuery = {}) =>
    request<IncidentList>(`/incidents${qs(q as Record<string, unknown>)}`),
  incident: (id: string) => request<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`),
  timeline: (id: string) =>
    request<{ items: StepEvent[] }>(`/incidents/${encodeURIComponent(id)}/timeline`),
  pendingApprovals: () => request<{ items: PendingApproval[] }>('/approvals/pending'),
  metrics: () => request<MetricsSummary>('/metrics/summary'),
  approve: (id: string, approved: boolean, reason: string) =>
    request<ApprovalResult>(`/incidents/${encodeURIComponent(id)}/approval`, {
      method: 'POST',
      body: JSON.stringify({ approved, reason }),
    }),
};

// SSE URL helpers (EventSource can't set headers; auth rides the session
// cookie set by Easy Auth, same-origin).
export const sseUrls = {
  incident: (id: string) => `/api/incidents/${encodeURIComponent(id)}/events`,
  global: () => '/api/events',
};
