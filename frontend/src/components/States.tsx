// Loading / empty / error primitives so every page handles all three.
import type { ReactNode } from 'react';

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return <div className="loading">{label}</div>;
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function ErrorState({ error }: { error: unknown }) {
  const message =
    error instanceof Error ? error.message : typeof error === 'string' ? error : 'Request failed';
  return <div className="error">⚠ {message}</div>;
}

export function LiveDot({ status }: { status: string }) {
  return <span className={`live-dot ${status}`} title={`live: ${status}`} />;
}
