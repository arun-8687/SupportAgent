// Approve / reject a paused mitigation. Renders the gated actions, requires a
// reason on reject, and gates the buttons on the SRE.Approver role.
import { useState } from 'react';

import type { GateDecision, MitigationAction } from '../api/types';

interface Props {
  actions: MitigationAction[];
  decisions: GateDecision[];
  canApprove: boolean;
  pending: boolean;
  onDecision: (approved: boolean, reason: string) => void;
}

export function ApprovalPanel({ actions, decisions, canApprove, pending, onDecision }: Props) {
  const [reason, setReason] = useState('');
  const requireApprovalIds = new Set(
    decisions.filter((d) => d.outcome === 'require_approval').map((d) => d.action_id),
  );
  const gated = actions.filter(
    (a) => requireApprovalIds.size === 0 || requireApprovalIds.has(a.action_id),
  );

  return (
    <div className="card section" style={{ padding: 16 }}>
      <h2>Approval required</h2>
      {gated.length === 0 ? (
        <p className="meta">No specific actions listed; review the mitigation plan above.</p>
      ) : (
        gated.map((a) => (
          <div key={a.action_id} className="action-item">
            <div className="step">{a.skill || a.action_id}</div>
            {a.description && <div className="meta">{a.description}</div>}
            {a.risk && <span className="badge warn">risk: {a.risk}</span>}
          </div>
        ))
      )}

      <textarea
        rows={3}
        placeholder="Reason (required to reject)"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        disabled={!canApprove || pending}
        style={{ marginTop: 12 }}
      />

      {!canApprove && (
        <div className="banner warn" style={{ marginTop: 12 }}>
          You have read-only access. The <strong>SRE.Approver</strong> role is required to act.
        </div>
      )}

      <div style={{ display: 'flex', gap: 10, marginTop: 12 }}>
        <button
          className="btn primary"
          disabled={!canApprove || pending}
          onClick={() => onDecision(true, reason)}
        >
          {pending ? 'Submitting…' : 'Approve'}
        </button>
        <button
          className="btn danger"
          disabled={!canApprove || pending || reason.trim() === ''}
          title={reason.trim() === '' ? 'A reason is required to reject' : undefined}
          onClick={() => onDecision(false, reason)}
        >
          Reject
        </button>
      </div>
    </div>
  );
}
