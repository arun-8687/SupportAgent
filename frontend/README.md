# SRE Agent Console (frontend)

React + Vite + TypeScript SPA for monitoring agent runs and approving/rejecting
paused mitigations. Served same-origin by the FastAPI app (`sre_agent/webapi`)
in production; talks to a relative `/api` and streams live updates over SSE.

## Develop

```bash
npm install
# In another terminal, run the API against the same data dir:
#   SRE_AGENT_PERSIST_STEP_EVENTS=true python -m sre_agent.webapi
npm run dev        # http://localhost:5173  (proxies /api -> :8080)
```

Drive a sample incident so the dashboard has data:

```bash
python -m sre_agent.main simulate sre_agent/samples/azure_monitor_alert.json
```

## Scripts

| Command | What |
| --- | --- |
| `npm run dev` | Vite dev server with `/api` proxy |
| `npm run build` | `tsc --noEmit` + production build → `dist/` |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run lint` | ESLint (zero warnings) |
| `npm run test` | Vitest component tests |

## Production

`npm run build` emits `dist/`; point the API at it with
`SRE_AGENT_WEBAPI_SPA_DIST_DIR=frontend/dist` and it is mounted at `/` with
history fallback. See `sre_agent/deploy/README.md` §13.

## Layout

- `src/api/` — typed client + payload types (mirror the pydantic models)
- `src/hooks/useLiveEvents.ts` — SSE subscription (Last-Event-ID resume)
- `src/components/` — badges, table, timeline, approval panel, state primitives
- `src/pages/` — Dashboard, IncidentDetail, Approvals
