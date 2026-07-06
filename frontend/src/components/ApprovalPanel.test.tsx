import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { ApprovalPanel } from './ApprovalPanel';
import type { GateDecision, MitigationAction } from '../api/types';

const actions: MitigationAction[] = [
  { action_id: 'a1', skill: 'restart_pod', description: 'Roll the deployment', risk: 'medium' },
];
const decisions: GateDecision[] = [{ action_id: 'a1', outcome: 'require_approval' }];

describe('ApprovalPanel', () => {
  it('disables the action buttons for a viewer', () => {
    render(
      <ApprovalPanel
        actions={actions}
        decisions={decisions}
        canApprove={false}
        pending={false}
        onDecision={() => {}}
      />,
    );
    expect(screen.getByRole('button', { name: /approve/i })).toBeDisabled();
    expect(screen.getByText(/read-only access/i)).toBeInTheDocument();
  });

  it('requires a reason before reject is enabled', async () => {
    const onDecision = vi.fn();
    render(
      <ApprovalPanel
        actions={actions}
        decisions={decisions}
        canApprove={true}
        pending={false}
        onDecision={onDecision}
      />,
    );
    const reject = screen.getByRole('button', { name: /reject/i });
    expect(reject).toBeDisabled();

    await userEvent.type(screen.getByPlaceholderText(/reason/i), 'not safe right now');
    expect(reject).toBeEnabled();
    await userEvent.click(reject);
    expect(onDecision).toHaveBeenCalledWith(false, 'not safe right now');
  });

  it('approves without a reason', async () => {
    const onDecision = vi.fn();
    render(
      <ApprovalPanel
        actions={actions}
        decisions={decisions}
        canApprove={true}
        pending={false}
        onDecision={onDecision}
      />,
    );
    await userEvent.click(screen.getByRole('button', { name: /approve/i }));
    expect(onDecision).toHaveBeenCalledWith(true, '');
  });

  it('renders the gated action detail', () => {
    render(
      <ApprovalPanel
        actions={actions}
        decisions={decisions}
        canApprove={true}
        pending={false}
        onDecision={() => {}}
      />,
    );
    expect(screen.getByText('restart_pod')).toBeInTheDocument();
    expect(screen.getByText(/risk: medium/i)).toBeInTheDocument();
  });
});
