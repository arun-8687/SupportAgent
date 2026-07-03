"""
Service Bus topic listener — the event-driven trigger.

Subscribes to the incidents TOPIC (pub/sub, not a queue): monitoring and
incident platforms publish alerts to the topic, and the agent consumes
its own subscription so other systems (dashboards, archival, additional
agents) can subscribe to the same events independently.

Message contract:
  - body: JSON alert payload (Azure Monitor / PagerDuty / ServiceNow / custom)
  - application_properties:
      event_type: "alert" (default) | "approval"
      source:     optional normalizer hint ("azure_monitor", "pagerduty", ...)

Approval messages resume investigations paused at the permission gate:
  {"incident_id": "...", "approved": true, "approver": "...", "reason": "..."}
"""
import asyncio
import json
import logging
from typing import Optional

from sre_agent.config import get_settings
from sre_agent.service import SREAgentService

logger = logging.getLogger(__name__)


class ServiceBusTopicListener:
    """Consumes the incidents topic subscription and drives the agent."""

    def __init__(self, service: Optional[SREAgentService] = None) -> None:
        self.settings = get_settings()
        self.service = service or SREAgentService()
        self._stopping = asyncio.Event()

    async def run(self) -> None:
        """Receive loop; renews locks, completes on success, abandons on error."""
        if not self.settings.servicebus_connection_string:
            raise RuntimeError(
                "SRE_AGENT_SERVICEBUS_CONNECTION_STRING is not set; "
                "use `python -m sre_agent.main simulate <alert.json>` for local runs."
            )

        from azure.servicebus.aio import ServiceBusClient

        logger.info(
            "Listening on topic '%s' subscription '%s'",
            self.settings.servicebus_topic,
            self.settings.servicebus_subscription,
        )
        async with ServiceBusClient.from_connection_string(
            self.settings.servicebus_connection_string
        ) as client:
            receiver = client.get_subscription_receiver(
                topic_name=self.settings.servicebus_topic,
                subscription_name=self.settings.servicebus_subscription,
                max_wait_time=30,
            )
            async with receiver:
                while not self._stopping.is_set():
                    messages = await receiver.receive_messages(
                        max_message_count=5, max_wait_time=30
                    )
                    for message in messages:
                        try:
                            await self._handle_message(message)
                            await receiver.complete_message(message)
                        except Exception:
                            logger.exception("Message handling failed; abandoning")
                            await receiver.abandon_message(message)

    def stop(self) -> None:
        self._stopping.set()

    # ------------------------------------------------------------------ #

    async def _handle_message(self, message) -> None:
        body = b"".join(
            part if isinstance(part, bytes) else part.encode() for part in message.body
        ).decode("utf-8")
        payload = json.loads(body)
        props = {
            (k.decode() if isinstance(k, bytes) else k):
            (v.decode() if isinstance(v, bytes) else v)
            for k, v in (message.application_properties or {}).items()
        }
        event_type = str(props.get("event_type", "alert"))

        if event_type == "approval":
            result = await self.service.submit_approval(
                incident_id=payload["incident_id"],
                approved=bool(payload.get("approved", False)),
                approver=str(payload.get("approver", "service-bus")),
                reason=str(payload.get("reason", "")),
                channel="service_bus",
            )
        else:
            result = await self.service.handle_alert(
                payload, source_hint=str(props.get("source", ""))
            )

        logger.info("Processed %s message: %s", event_type, result)


async def publish_alert(payload: dict, source: str = "custom") -> None:
    """Helper for publishers/tests: drop an alert onto the topic."""
    settings = get_settings()
    from azure.servicebus import ServiceBusMessage
    from azure.servicebus.aio import ServiceBusClient

    async with ServiceBusClient.from_connection_string(
        settings.servicebus_connection_string
    ) as client:
        sender = client.get_topic_sender(topic_name=settings.servicebus_topic)
        async with sender:
            await sender.send_messages(
                ServiceBusMessage(
                    json.dumps(payload),
                    application_properties={"event_type": "alert", "source": source},
                )
            )


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    listener = ServiceBusTopicListener()
    asyncio.run(listener.run())


if __name__ == "__main__":
    main()
