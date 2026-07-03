# App Service restart procedure

Use when an App Service shows symptoms of a wedged worker process: rising
memory with flat traffic, thread-pool exhaustion, or 5xx bursts that don't
correlate with dependencies.

## Procedure

1. Verify current state with `check_app_state` (read-only) before acting.
2. Check whether the app runs on multiple instances — a restart is rolling
   across instances only when "always on" and multiple workers are configured.
3. Restart with `restart_app_service`. Expect 30–90 seconds of cold start.
4. After restart, verify: state should be `Running` and 5xx rate should drop
   within 5 minutes.

## When NOT to restart

- During an active deployment slot swap (wait for it to finish).
- If the cause is a downstream dependency (restart won't help; fix the
  dependency or fail over instead).
