---
name: aks-memory-pressure
description: Investigates AKS/Kubernetes memory pressure, OOMKilled pods, and crashlooping deployments, and mitigates via rolling restarts. Use when pods restart with OOMKilled, memory metrics trend upward, or a deployment crashloops.
compatibility: Requires kubectl with access to the affected cluster
metadata:
  author: sre-agent
  version: "1.0"
category: compute
applies_to:
  - memory
  - oomkilled
  - crashloop
  - aks
  - kubernetes
files:
  - SKILL.md
  - references/oomkill-runbook.md
tools:
  - name: restart_aks_deployment
    type: shell
    description: Rolling restart of an AKS deployment to recycle unhealthy pods
    command: "kubectl rollout restart deployment/{deployment} -n {namespace}"
    parameters: [namespace, deployment]
    risk: medium
  - name: get_pod_memory
    type: shell
    description: Read-only snapshot of pod memory usage in the namespace
    command: "kubectl top pods -n {namespace} --sort-by=memory"
    parameters: [namespace]
    risk: low
---
# AKS memory pressure troubleshooting

Follow this procedure when a service on AKS shows memory growth, OOMKilled
restarts, or crashlooping pods.

## Investigation steps

1. Confirm the trend: check `MemoryWorkingSet` for the affected workload over
   the last 90 minutes. A steady climb (not a spike) suggests a leak or a
   changed workload profile; a step change suggests a deployment.
2. Check pod events for `OOMKilled` — run the `get_pod_memory` tool to see
   which pods are near their limits.
3. Correlate with deployments: a memory regression almost always follows a
   code or config change. Check what shipped in the 6 hours before onset.
4. Check whether the HPA is at `maxReplicas` — if the service can't scale
   out, per-pod memory pressure compounds.

## Mitigation guidance

- **First line**: rolling restart (`restart_aks_deployment` tool) clears leaked
  memory and buys time. Safe because it's rolling; do NOT delete pods directly.
- **If HPA is saturated**: raise `maxReplicas` (see the `hpa-scaling` skill).
- **If a deployment correlates**: propose rollback of that deployment as a
  manual action for the on-call engineer — never roll back automatically.

## Pitfalls

- Restarting without checking the deployment correlation hides the root cause;
  the leak will return within hours.
- Raising memory limits without evidence just delays the next OOMKill.
