import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { SeverityBadge, StatusBadge } from './Badges';

describe('badges', () => {
  it('maps resolved status to the ok tone', () => {
    const { container } = render(<StatusBadge status="resolved" />);
    expect(container.querySelector('.badge.ok')).toBeInTheDocument();
    expect(screen.getByText('resolved')).toBeInTheDocument();
  });

  it('humanizes underscored statuses', () => {
    render(<StatusBadge status="awaiting_approval" />);
    expect(screen.getByText('awaiting approval')).toBeInTheDocument();
  });

  it('maps sev1 to the danger tone', () => {
    const { container } = render(<SeverityBadge severity="sev1" />);
    expect(container.querySelector('.badge.danger')).toBeInTheDocument();
    expect(screen.getByText('SEV1')).toBeInTheDocument();
  });

  it('falls back to muted for unknown values', () => {
    const { container } = render(<StatusBadge status="weird" />);
    expect(container.querySelector('.badge.muted')).toBeInTheDocument();
  });
});
