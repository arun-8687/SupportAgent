import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback, useState } from 'react';
import { Link } from 'react-router-dom';

import { api } from '../api/client';
import type { StepEvent } from '../api/types';
import { ErrorState, LiveDot, Loading } from '../components/States';
import { IncidentTable } from '../components/IncidentTable';
import { formatDuration } from '../lib/format';
import { sseUrls } from '../api/client';
import { useLiveEvents } from '../hooks/useLiveEvents';

const STATUS_OPTIONS = [
  '',
  'received',
  'investigating',
  'awaiting_approval',
  'resolved',
  'escalated',
];
const SEVERITY_OPTIONS = ['', 'sev1', 'sev2', 'sev3', 'sev4'];
const PAGE_SIZE = 25;

export function Dashboard() {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState('');
  const [severity, setSeverity] = useState('');
  const [sort, setSort] = useState('updated_at');
  const [descending, setDescending] = useState(true);
  const [page, setPage] = useState(0);

  const query = {
    status: status || undefined,
    severity: severity || undefined,
    sort,
    descending,
    limit: PAGE_SIZE,
    offset: page * PAGE_SIZE,
  };

  const incidents = useQuery({
    queryKey: ['incidents', query],
    queryFn: () => api.incidents(query),
  });
  const metrics = useQuery({ queryKey: ['metrics'], queryFn: api.metrics });

  // Live: any new step event means the dashboard is stale — refetch (debounced
  // by React Query's dedup). Cheap and robust vs. patching rows in place.
  const onEvent = useCallback(
    (_: StepEvent) => {
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
      queryClient.invalidateQueries({ queryKey: ['metrics'] });
    },
    [queryClient],
  );
  const live = useLiveEvents(sseUrls.global(), onEvent);

  const onSort = (column: string) => {
    if (column === sort) setDescending((d) => !d);
    else {
      setSort(column);
      setDescending(true);
    }
    setPage(0);
  };

  const total = incidents.data?.total ?? 0;
  const maxPage = Math.max(0, Math.ceil(total / PAGE_SIZE) - 1);

  return (
    <>
      <div className="metrics-strip">
        <Metric label="Total incidents" value={metrics.data?.total ?? '—'} />
        <Metric
          label="Awaiting approval"
          value={metrics.data?.awaiting_approval ?? '—'}
          highlight={(metrics.data?.awaiting_approval ?? 0) > 0}
        />
        <Metric
          label="Open"
          value={openCount(metrics.data?.by_status)}
        />
        <Metric label="MTTR" value={formatDuration(metrics.data?.mttr_seconds ?? null)} />
      </div>

      {(metrics.data?.awaiting_approval ?? 0) > 0 && (
        <div className="banner warn">
          {metrics.data!.awaiting_approval} incident(s) awaiting approval —{' '}
          <Link to="/approvals">review the queue</Link>.
        </div>
      )}

      <div className="toolbar">
        <label>
          Status{' '}
          <select
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPage(0);
            }}
          >
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {s || 'all'}
              </option>
            ))}
          </select>
        </label>
        <label>
          Severity{' '}
          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value);
              setPage(0);
            }}
          >
            {SEVERITY_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {s || 'all'}
              </option>
            ))}
          </select>
        </label>
        <div className="header-spacer" />
        <span className="identity">
          <LiveDot status={live} /> live
        </span>
      </div>

      {incidents.isLoading ? (
        <Loading />
      ) : incidents.isError ? (
        <ErrorState error={incidents.error} />
      ) : total === 0 ? (
        <div className="card empty">No incidents match these filters.</div>
      ) : (
        <>
          <IncidentTable
            rows={incidents.data!.items}
            sort={sort}
            descending={descending}
            onSort={onSort}
          />
          <div className="pagination">
            <span>
              {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of {total}
            </span>
            <button className="btn" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
              Prev
            </button>
            <button
              className="btn"
              disabled={page >= maxPage}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </div>
        </>
      )}
    </>
  );
}

function Metric({
  label,
  value,
  highlight,
}: {
  label: string;
  value: number | string;
  highlight?: boolean;
}) {
  return (
    <div className="card metric">
      <div className="value" style={highlight ? { color: 'var(--warn)' } : undefined}>
        {value}
      </div>
      <div className="label">{label}</div>
    </div>
  );
}

function openCount(byStatus?: Record<string, number>): number | string {
  if (!byStatus) return '—';
  const terminal = new Set(['resolved', 'verified', 'mitigated', 'escalated']);
  return Object.entries(byStatus)
    .filter(([k]) => !terminal.has(k))
    .reduce((sum, [, n]) => sum + n, 0);
}
