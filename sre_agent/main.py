"""
CLI entrypoint for the SRE Agent.

  python -m sre_agent.main listen                       # Service Bus topic listener
  python -m sre_agent.main simulate <alert.json>        # run one alert locally
  python -m sre_agent.main simulate <alert.json> --approve   # auto-approve when paused
  python -m sre_agent.main graph                        # print the graph as mermaid
"""
import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from sre_agent.service import SREAgentService


async def _simulate(alert_file: str, approve: bool) -> None:
    payload = json.loads(Path(alert_file).read_text(encoding="utf-8"))
    service = SREAgentService()

    result = await service.handle_alert(payload)
    print(json.dumps(result, indent=2, default=str))

    if result.get("status") == "awaiting_approval" and approve:
        print("\n-- auto-approving (simulation) --\n")
        final = await service.submit_approval(
            incident_id=result["incident_id"],
            approved=True,
            approver="cli-simulation",
            reason="Approved via --approve flag",
        )
        print(json.dumps(final, indent=2, default=str))


def _print_graph() -> None:
    from sre_agent.graph.workflow import build_workflow

    graph = build_workflow()
    print(graph.get_graph().draw_mermaid())


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s"
    )
    from sre_agent.observability import configure_telemetry

    configure_telemetry()
    parser = argparse.ArgumentParser(prog="sre_agent")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("listen", help="Run the Service Bus topic listener")

    simulate = sub.add_parser("simulate", help="Process one alert payload locally")
    simulate.add_argument("alert_file", help="Path to a JSON alert payload")
    simulate.add_argument(
        "--approve", action="store_true",
        help="Auto-approve if the permission gate pauses for sign-off",
    )

    sub.add_parser("graph", help="Print the workflow graph as mermaid")

    args = parser.parse_args()

    if args.command == "listen":
        from sre_agent.triggers.service_bus_listener import ServiceBusTopicListener

        asyncio.run(ServiceBusTopicListener().run())
    elif args.command == "simulate":
        asyncio.run(_simulate(args.alert_file, args.approve))
    elif args.command == "graph":
        _print_graph()
    else:  # pragma: no cover
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
