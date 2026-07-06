// Status & severity badges with a stable color mapping.

const STATUS_TONE: Record<string, string> = {
  resolved: 'ok',
  verified: 'ok',
  mitigated: 'ok',
  awaiting_approval: 'warn',
  escalated: 'danger',
  failed: 'danger',
  error: 'danger',
  received: 'info',
  triaging: 'info',
  investigating: 'info',
  analyzing: 'info',
};

const SEVERITY_TONE: Record<string, string> = {
  sev1: 'danger',
  sev2: 'danger',
  sev3: 'warn',
  sev4: 'muted',
  sev5: 'muted',
};

export function StatusBadge({ status }: { status: string }) {
  const tone = STATUS_TONE[status?.toLowerCase()] ?? 'muted';
  return <span className={`badge ${tone}`}>{humanize(status)}</span>;
}

export function SeverityBadge({ severity }: { severity: string }) {
  const tone = SEVERITY_TONE[severity?.toLowerCase()] ?? 'muted';
  return <span className={`badge ${tone}`}>{(severity || '—').toUpperCase()}</span>;
}

function humanize(value: string): string {
  if (!value) return '—';
  return value.replace(/_/g, ' ');
}
