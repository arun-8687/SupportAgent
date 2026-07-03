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
