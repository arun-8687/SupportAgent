import { useEffect, useRef, useState } from 'react';

import type { StepEvent } from '../api/types';

type Status = 'connecting' | 'open' | 'closed';

// Subscribe to an SSE endpoint of step events. EventSource auto-reconnects
// and replays from Last-Event-ID (the server tails by seq), so we just
// accumulate `step` frames. Returns the live status for a connection badge.
export function useLiveEvents(
  url: string,
  onEvent: (event: StepEvent) => void,
  enabled = true,
): Status {
  const [status, setStatus] = useState<Status>('connecting');
  const handlerRef = useRef(onEvent);
  handlerRef.current = onEvent;

  useEffect(() => {
    if (!enabled) return;
    const source = new EventSource(url, { withCredentials: true });
    setStatus('connecting');
    source.onopen = () => setStatus('open');
    source.onerror = () => setStatus('connecting'); // browser retries
    source.addEventListener('step', (e) => {
      try {
        handlerRef.current(JSON.parse((e as MessageEvent).data) as StepEvent);
      } catch {
        /* ignore malformed frame */
      }
    });
    return () => {
      source.close();
      setStatus('closed');
    };
  }, [url, enabled]);

  return status;
}
