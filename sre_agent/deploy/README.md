# Deploying the SRE Agent on Azure Functions

Use **Flex Consumption or Elastic Premium** — classic Consumption's 5–10
minute execution cap is too short for LLM-driven investigations.

## Required app settings

| Setting | Value | Why |
| --- | --- | --- |
| `SRE_AGENT_ENVIRONMENT` | `production` | Enables strict mode: no mock telemetry, durable checkpointer required, verified approver identity required |
| `SRE_AGENT_DATABASE_URL` | Postgres connection string | Checkpointer + alert ledger + pending approvals; approvals must resume on any instance |
| `SRE_AGENT_DATA_DIR` | e.g. `/mounts/sre-data` | Azure Files mount for knowledge/memory markdown files — instance-local disk is ephemeral and per-instance |
| `SRE_AGENT_SERVICEBUS_CONNECTION_STRING` | Service Bus connection (or identity-based) | Topic trigger |
| `SRE_AGENT_SERVICEBUS_TOPIC` / `_SUBSCRIPTION` | `sre-incidents` / `sre-agent` | Trigger bindings resolve these via `%...%` |
| `SRE_AGENT_AZURE_OPENAI_*` | endpoint/key/deployment | In production a missing LLM fails loudly instead of degrading to heuristics |
| `SRE_AGENT_EXECUTION_MODE` | `dispatch` (recommended on Functions) | The Functions sandbox lacks az/kubectl + credentials; dispatch publishes approved actions to the outbound topic for a privileged runner |

## host.json

Copy `host.json` from this directory to the function project root:

- `functionTimeout: 00:30:00` — investigations exceed default timeouts.
- `maxAutoLockRenewalDuration: 00:30:00` — keeps the Service Bus lock
  renewed for the worst-case investigation (the default renewal window is
  5 minutes; past it the message unlocks and redelivers mid-run — the
  alert ledger dedupes that, but avoid it anyway).
- `maxConcurrentCalls: 4` — bounds parallel investigations per instance,
  which together with `SRE_AGENT_LLM_MAX_CONCURRENCY` caps LLM spend
  during alert storms.

## Identity & approvals

Enable **App Service Authentication (Easy Auth) with Entra ID** on the
Function App. The approval endpoint takes the approver from the verified
`X-MS-CLIENT-PRINCIPAL` header; in production, requests without it get
401 and body-supplied approver names are never trusted.

Approvals via Service Bus (`event_type=approval` messages) treat topic
send rights as the credential — restrict senders with Service Bus RBAC.

## Storage mount

Mount an Azure Files share and point `SRE_AGENT_DATA_DIR` at it. Prefer
NFS shares — the file locks used by the markdown knowledge stores are
advisory fcntl locks, which are unreliable over SMB. With
`SRE_AGENT_DATABASE_URL` set, the high-contention stores (alert ledger,
pending approvals) use Postgres and don't depend on file locking at all.

## Maintenance

The `ApprovalSweep` timer (every 5 minutes) escalates approvals that
exceeded `SRE_AGENT_APPROVAL_TIMEOUT_SECONDS` and prunes checkpoints
older than `SRE_AGENT_CHECKPOINT_RETENTION_DAYS` (default 14).
