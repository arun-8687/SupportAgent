// Vertical step timeline for an incident's run. Ordered by seq; a live SSE
// feed appends new steps in the detail page.
import type { StepEvent } from '../api/types';
import { relativeTime } from '../lib/format';

function toneClass(status: string): string {
  const s = status?.toLowerCase();
  if (s === 'failed' || s === 'error') return 'failed';
  if (s === 'completed' || s === 'ok' || s === 'resolved') return 'completed';
  return '';
}

export function Timeline({ events }: { events: StepEvent[] }) {
  if (events.length === 0) {
    return <div className="empty">No steps recorded yet.</div>;
  }
  return (
    <ul className="timeline">
      {events.map((e) => (
        <li key={e.seq} className={toneClass(e.status)}>
          <div className="step">
            {e.step} <span className="badge muted">{e.status}</span>
          </div>
          <div className="meta">
            {relativeTime(e.ts)}
            {e.duration_ms != null ? ` · ${e.duration_ms}ms` : ''}
            {renderFields(e.fields)}
          </div>
        </li>
      ))}
    </ul>
  );
}

function renderFields(fields: Record<string, unknown>): string {
  const keys = Object.keys(fields || {}).filter((k) => k !== 'incident_id');
  if (keys.length === 0) return '';
  return ' · ' + keys.map((k) => `${k}=${String(fields[k])}`).join(' ');
}
