import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useCallback } from 'react';
import { Link } from 'react-router-dom';

import { api, sseUrls } from '../api/client';
import type { StepEvent } from '../api/types';
import { SeverityBadge } from '../components/Badges';
import { ErrorState, LiveDot, Loading } from '../components/States';
import { relativeTime } from '../lib/format';
import { useLiveEvents } from '../hooks/useLiveEvents';

export function Approvals() {
  const queryClient = useQueryClient();
  const pending = useQuery({ queryKey: ['approvals'], queryFn: api.pendingApprovals });

  const onEvent = useCallback(
    (_: StepEvent) => queryClient.invalidateQueries({ queryKey: ['approvals'] }),
    [queryClient],
  );
  const live = useLiveEvents(sseUrls.global(), onEvent);

  return (
    <>
      <div className="section" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <h1 style={{ margin: 0, fontSize: 20 }}>Approval queue</h1>
        <span className="identity">
          <LiveDot status={live} /> live
        </span>
      </div>

      {pending.isLoading ? (
        <Loading />
      ) : pending.isError ? (
        <ErrorState error={pending.error} />
      ) : pending.data!.items.length === 0 ? (
        <div className="card empty">Nothing awaiting approval. 🎉</div>
      ) : (
        <div className="card table-wrap">
          <table>
            <thead>
              <tr>
                <th>Sev</th>
                <th>Incident</th>
                <th>Service</th>
                <th>Waiting</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {pending.data!.items.map((p) => (
                <tr key={p.incident_id}>
                  <td>{p.incident ? <SeverityBadge severity={p.incident.severity} /> : '—'}</td>
                  <td className="wrap">
                    <Link to={`/incidents/${encodeURIComponent(p.incident_id)}`}>
                      {p.incident?.title || p.incident_id}
                    </Link>
                  </td>
                  <td>{p.incident?.service_name || '—'}</td>
                  <td>{relativeTime(p.created_at)}</td>
                  <td>
                    <Link className="btn" to={`/incidents/${encodeURIComponent(p.incident_id)}`}>
                      Review
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
