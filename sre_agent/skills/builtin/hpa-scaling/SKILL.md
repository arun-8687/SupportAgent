---
name: hpa-scaling
description: Raises Horizontal Pod Autoscaler headroom for saturated Kubernetes services. Use when a workload is pinned at maxReplicas while CPU or memory pressure keeps climbing.
compatibility: Requires kubectl with access to the affected cluster
metadata:
  author: sre-agent
  version: "1.0"
category: scaling
applies_to:
  - memory
  - scaling
  - hpa
  - saturation
  - kubernetes
tools:
  - name: adjust_hpa_max_replicas
    type: shell
    description: Raise the HPA max replica count so the service can scale out under pressure
    command: "kubectl patch hpa {hpa_name} -n {namespace} --patch '{{\"spec\":{{\"maxReplicas\":{max_replicas}}}}}'"
    parameters: [namespace, hpa_name, max_replicas]
    risk: medium
    supports_rollback: true
    rollback_command: "kubectl patch hpa {hpa_name} -n {namespace} --patch '{{\"spec\":{{\"maxReplicas\":{previous_max_replicas}}}}}'"
  - name: get_hpa_status
    type: shell
    description: Read-only HPA status (current/desired replicas, utilization)
    command: "kubectl get hpa {hpa_name} -n {namespace} -o wide"
    parameters: [namespace, hpa_name]
    risk: low
---
# HPA scaling headroom

Use when a workload is pinned at its HPA `maxReplicas` while resource
pressure continues to climb.

## Procedure

1. Check saturation with `get_hpa_status`: if `current == max` and CPU/memory
   utilization is above target, the HPA is the bottleneck.
2. Confirm cluster capacity first — scaling a Deployment beyond available
   node capacity just creates Pending pods.
3. Raise `maxReplicas` conservatively (≤ 2× current) with
   `adjust_hpa_max_replicas`. Record the previous value for rollback.
4. Watch for 10 minutes: replicas should grow and per-pod pressure fall.

## Pitfalls

- Raising maxReplicas masks a memory leak instead of fixing it; pair this with
  the `aks-memory-pressure` investigation.
- Quota limits: some services can't scale past subscription quotas — check
  before promising headroom.
