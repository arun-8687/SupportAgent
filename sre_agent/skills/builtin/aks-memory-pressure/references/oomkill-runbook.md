# OOMKill runbook (supporting reference)

Quick reference for interpreting OOMKilled events:

| Signal | Meaning |
| --- | --- |
| `OOMKilled`, exit code 137 | Container exceeded its memory limit |
| `Evicted` | Node-level memory pressure, not container limit |
| Restart count climbing with OOMKilled | Leak or undersized limit |
| Single OOMKilled after deploy | Likely regression in the new version |

Escalation: if OOMKills continue after a rolling restart AND no deployment
correlates, page the service owner — this may be a data-shape change upstream.
