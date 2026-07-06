import '@testing-library/jest-dom/vitest';

// jsdom has no EventSource; stub it so components using useLiveEvents mount.
class MockEventSource {
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(public url: string) {}
  addEventListener() {}
  close() {}
}
// @ts-expect-error assign test double
globalThis.EventSource = MockEventSource;
