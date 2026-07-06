import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { Timeline } from './Timeline';
import type { StepEvent } from '../api/types';

function ev(seq: number, step: string, status: string): StepEvent {
  return { seq, incident_id: 'i1', step, status, duration_ms: 5, fields: {}, ts: Date.now() / 1000 };
}

describe('Timeline', () => {
  it('shows an empty message with no events', () => {
    render(<Timeline events={[]} />);
    expect(screen.getByText(/no steps recorded/i)).toBeInTheDocument();
  });

  it('renders steps with their status', () => {
    render(<Timeline events={[ev(1, 'triage', 'completed'), ev(2, 'verify', 'failed')]} />);
    expect(screen.getByText('triage')).toBeInTheDocument();
    expect(screen.getByText('verify')).toBeInTheDocument();
  });
});
