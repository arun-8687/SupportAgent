import { Link } from 'react-router-dom';

import type { IncidentRow } from '../api/types';
import { relativeTime } from '../lib/format';
import { SeverityBadge, StatusBadge } from './Badges';

interface Props {
  rows: IncidentRow[];
  sort: string;
  descending: boolean;
  onSort: (column: string) => void;
}

const COLUMNS: [string, string, boolean][] = [
  ['severity', 'Sev', true],
  ['title', 'Incident', false],
  ['service_name', 'Service', true],
  ['app_code', 'App', true],
  ['status', 'Status', true],
  ['updated_at', 'Updated', true],
];

export function IncidentTable({ rows, sort, descending, onSort }: Props) {
  return (
    <div className="card table-wrap">
      <table>
        <thead>
          <tr>
            {COLUMNS.map(([key, label, sortable]) => (
              <th
                key={key}
                onClick={sortable ? () => onSort(key) : undefined}
                style={{ cursor: sortable ? 'pointer' : 'default' }}
              >
                {label}
                {sort === key ? (descending ? ' ↓' : ' ↑') : ''}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.incident_id}>
              <td>
                <SeverityBadge severity={r.severity} />
              </td>
              <td className="wrap">
                <Link to={`/incidents/${encodeURIComponent(r.incident_id)}`}>
                  {r.title || r.incident_id}
                </Link>
              </td>
              <td>{r.service_name}</td>
              <td>{r.app_code}</td>
              <td>
                <StatusBadge status={r.status} />
              </td>
              <td title={String(r.updated_at)}>{relativeTime(r.updated_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
