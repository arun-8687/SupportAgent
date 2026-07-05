# Incident response plan

Instructions for how the agent handles incidents in this environment.
Edit this file to encode your team's procedures — its content is injected
into the planner and mitigation prompts.

## Principles

1. Correlate telemetry with recent changes before proposing any mitigation —
   most production incidents follow a deployment.
2. Prefer the smallest reversible action first (rolling restart before
   scaling, scaling before config changes).
3. Never propose destructive operations; propose a manual review step for
   anything involving data.
4. Production changes always go through the permission gate for human
   approval. Non-prod restarts may auto-approve per gate policy.

## Escalation

- If root-cause confidence is below 0.4, escalate rather than mitigate.
- Include the full investigation summary and blast radius in the ticket so
  the on-call engineer can act from a single thread.
