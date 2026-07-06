"""Production monitoring & action web API for the SRE Agent.

A standalone async FastAPI service (App Service, Always On) that reads the
shared Postgres state the worker writes — the incident index, the
checkpointer, and the durable step-event timeline — and exposes the one
write action in scope: approve/reject a paused mitigation. It serves the
built React SPA and streams live updates over SSE.
"""
