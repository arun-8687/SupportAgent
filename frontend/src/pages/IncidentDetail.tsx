import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import { api, sseUrls } from '../api/client';
import type { CorrelatedChange, StepEvent } from '../api/types';
import { SeverityBadge, StatusBadge } from '../components/Badges';
import { ApprovalPanel } from '../components/ApprovalPanel';
import { ErrorState, LiveDot, Loading } from '../components/States';
import { Timeline } from '../components/Timeline';
import { useLiveEvents } from '../hooks/useLiveEvents';

export function IncidentDetailPage() {
  const { id = '' } = useParams();
  const queryClient = useQueryClient();

  const me = useQuery({ queryKey: ['me'], queryFn: api.me });
  const detail = useQuery({
    queryKey: ['incident', id],
    queryFn: () => api.incident(id),
  });
  const timeline = useQuery({
    queryKey: ['timeline', id],
    queryFn: () => api.timeline(id),
  });

  // Merge the persisted timeline with live SSE steps (dedup by seq).
  const [liveSteps, setLiveSteps] = useState<StepEvent[]>([]);
  useEffect(() => setLiveSteps([]), [id]);
  const onEvent = useCallback((event: StepEvent) => {
    setLiveSteps((prev) => (prev.some((e) => e.seq === event.seq) ? prev : [...prev, event]));
  }, []);
  const live = useLiveEvents(sseUrls.incident(id), onEvent);

  const approve = useMutation({
    mutationFn: ({ approved, reason }: { approved: boolean; reason: string }) =>
      api.approve(id, approved, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incident', id] });
      queryClient.invalidateQueries({ queryKey: ['timeline', id] });
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
    },
  });

  if (detail.isLoading) return <Loading />;
  if (detail.isError) return <ErrorState error={detail.error} />;

  const d = detail.data!;
  const state = d.state ?? {};
  const row = d.index;
  const merged = mergeTimeline(timeline.data?.items ?? [], liveSteps);

  return (
    <>
      <p>
        <Link to="/">← Dashboard</Link>
      </p>

      <div className="section" style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        <h1 style={{ margin: 0, fontSize: 20 }}>{row?.title || state.incident?.alert?.title || id}</h1>
        {row && <SeverityBadge severity={row.severity} />}
        {row && <StatusBadge status={row.status} />}
      </div>

      <div className="detail-grid">
        <div>
          {approve.isError && <ErrorState error={approve.error} />}
          {approve.isSuccess && (
            <div className="banner warn">Decision submitted: {approve.data.status}</div>
          )}

          {d.awaiting_approval && (
            <ApprovalPanel
              actions={state.mitigation_plan?.actions ?? []}
              decisions={state.gate_decisions ?? []}
              canApprove={me.data?.can_approve ?? false}
              pending={approve.isPending}
              onDecision={(approved, reason) => approve.mutate({ approved, reason })}
            />
          )}

          <Section title="Incident">
            <dl className="kv">
              <dt>ID</dt>
              <dd>{state.incident?.incident_id || id}</dd>
              <dt>Service</dt>
              <dd>{state.incident?.service_name || row?.service_name || '—'}</dd>
              <dt>App</dt>
              <dd>{state.incident?.app_code || row?.app_code || '—'}</dd>
              <dt>Environment</dt>
              <dd>{state.incident?.environment || row?.environment || '—'}</dd>
              <dt>Alert</dt>
              <dd>{state.incident?.alert?.description || '—'}</dd>
            </dl>
          </Section>

          {state.triage && (
            <Section title="Triage">
              <dl className="kv">
                <dt>Category</dt>
                <dd>{state.triage.category || '—'}</dd>
                <dt>Summary</dt>
                <dd>{state.triage.summary || '—'}</dd>
              </dl>
            </Section>
          )}

          {state.root_cause && (
            <Section title="Root cause">
              <dl className="kv">
                <dt>Hypothesis</dt>
                <dd>{state.root_cause.hypothesis || '—'}</dd>
                <dt>Confidence</dt>
                <dd>
                  {state.root_cause.confidence != null
                    ? `${Math.round(state.root_cause.confidence * 100)}%`
                    : '—'}
                </dd>
                {state.root_cause.correlated_change && (
                  <>
                    <dt>Correlated change</dt>
                    <dd>{formatCorrelatedChange(state.root_cause.correlated_change)}</dd>
                  </>
                )}
              </dl>
            </Section>
          )}

          {state.mitigation_plan && (
            <Section title="Mitigation plan">
              {state.mitigation_plan.summary && <p>{state.mitigation_plan.summary}</p>}
              {(state.mitigation_plan.actions ?? []).map((a) => (
                <div key={a.action_id} className="action-item">
                  <div className="step">{a.skill || a.action_id}</div>
                  {a.description && <div className="meta">{a.description}</div>}
                  {a.risk && <span className="badge warn">risk: {a.risk}</span>}
                </div>
              ))}
            </Section>
          )}

          {state.execution && (
            <Section title="Execution">
              <p>{state.execution.summary || (state.execution.success ? 'Succeeded' : 'Ran')}</p>
            </Section>
          )}

          {state.verification && (
            <Section title="Verification">
              <p>
                {state.verification.summary ||
                  (state.verification.resolved ? 'Resolved' : 'Not resolved')}
              </p>
            </Section>
          )}

          {(state.resolution_summary || row?.resolution_summary) && (
            <Section title="Resolution">
              <p>{state.resolution_summary || row?.resolution_summary}</p>
              {state.ticket?.ticket_id && (
                <p className="meta">Ticket: {state.ticket.ticket_id}</p>
              )}
            </Section>
          )}
        </div>

        <aside>
          <div className="card section" style={{ padding: 16 }}>
            <h2 style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              Run timeline <LiveDot status={live} />
            </h2>
            <Timeline events={merged} />
          </div>
        </aside>
      </div>
    </>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="card section" style={{ padding: 16 }}>
      <h2>{title}</h2>
      {children}
    </div>
  );
}

function mergeTimeline(persisted: StepEvent[], live: StepEvent[]): StepEvent[] {
  const bySeq = new Map<number, StepEvent>();
  for (const e of persisted) bySeq.set(e.seq, e);
  for (const e of live) bySeq.set(e.seq, e);
  return Array.from(bySeq.values()).sort((a, b) => a.seq - b.seq);
}

function formatCorrelatedChange(change: CorrelatedChange): string {
  const parts = [change.identifier, change.description].filter(Boolean);
  const label = parts.join(' — ') || change.kind;
  return change.author ? `${label} (${change.author})` : label;
}
