"""
Source-code subagent.

Correlates the incident window with recent deployments and commits from
connected repositories — the "correlates the trend with a deployment event
from your GitHub repository two hours earlier" part of the investigation.
"""
from typing import List

from sre_agent.models import Evidence, Incident, SubagentFinding
from sre_agent.subagents.base import Subagent
from sre_agent.tools.deployments import DeploymentClient


class SourceCodeSubagent(Subagent):
    name = "source_code"
    description = (
        "You correlate incidents with recent code changes: deployments, "
        "commits, and config changes in the hours before the alert."
    )

    def __init__(self, client: DeploymentClient | None = None) -> None:
        self.client = client or DeploymentClient()

    async def collect(self, incident: Incident) -> List[Evidence]:
        evidence: List[Evidence] = []
        deployments = await self.client.recent_deployments(incident.service_name)
        for deploy in deployments:
            evidence.append(
                Evidence(
                    source="deployments",
                    observation=(
                        f"Deployment {deploy['id']} ({deploy.get('sha', '')[:7]}) to "
                        f"{deploy.get('environment', '?')} at {deploy.get('created_at', '?')}: "
                        f"{deploy.get('description', '')}"
                    ),
                    data=deploy,
                )
            )
        commits = await self.client.recent_commits(incident.service_name)
        for commit in commits:
            evidence.append(
                Evidence(
                    source="commits",
                    observation=(
                        f"Commit {commit['sha'][:7]} by {commit.get('author', '?')}: "
                        f"{commit.get('message', '')}"
                    ),
                    data=commit,
                )
            )
        return evidence

    def heuristic_finding(self, incident: Incident, evidence: List[Evidence]) -> SubagentFinding:
        deployments = [e for e in evidence if e.source == "deployments"]
        if deployments:
            newest = deployments[0]
            return SubagentFinding(
                subagent=self.name,
                summary=(
                    f"Found {len(deployments)} recent deployment(s) in the incident window. "
                    f"Most recent: {newest.observation[:160]}"
                ),
                suspected_cause=(
                    f"Recent change correlated with incident onset: {newest.data.get('description', newest.data.get('id'))}"
                ),
                confidence=0.7,
            )
        return SubagentFinding(
            subagent=self.name,
            summary="No deployments or commits found in the incident window.",
            suspected_cause=None,
            confidence=0.4,
        )
