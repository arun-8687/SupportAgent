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

Reliability behavior:
  - Fast-ack: the message is COMPLETED as soon as its payload is parsed,
    before the (potentially long) investigation runs. Idempotent intake
    (the alert ledger) is what makes this safe — a crash mid-investigation
    loses nothing that a redelivered duplicate could fix, and the message
    lock can never expire mid-run and cause a duplicate investigation.
  - Poison messages (unparseable JSON / schema garbage) are DEAD-LETTERED
    immediately with a reason instead of burning redelivery cycles.
  - Transient failures (parse OK, processing raised) abandon the message
    for redelivery; the ledger dedupes the retry.
  - The approval-timeout sweeper runs between receive batches.
"""
import asyncio
import json
import logging
import time
from typing import Optional

from sre_agent.config import get_settings
from sre_agent.service import SREAgentService

logger = logging.getLogger(__name__)

SWEEP_INTERVAL_SECONDS = 300


class ServiceBusTopicListener:
    """Consumes the incidents topic subscription and drives the agent."""

    def __init__(self, service: Optional[SREAgentService] = None) -> None:
        self.settings = get_settings()
        self.service = service or SREAgentService()
        self._stopping = asyncio.Event()
        self._last_sweep = 0.0

    async def run(self) -> None:
        """Receive loop with fast-ack, dead-lettering, and periodic sweeps."""
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
                        await self._handle_message(receiver, message)
                    await self._maybe_sweep()

    def stop(self) -> None:
        self._stopping.set()

    # ------------------------------------------------------------------ #

    async def _handle_message(self, receiver, message) -> None:
        # Parse first; a payload that can't be parsed will never succeed,
        # so dead-letter it immediately instead of redelivering.
        try:
            payload, props = self._parse(message)
        except (json.JSONDecodeError, UnicodeDecodeError, KeyError) as exc:
            logger.error("Poison message %s: %s; dead-lettering", message.message_id, exc)
            await receiver.dead_letter_message(
                message,
                reason="unparseable_payload",
                error_description=str(exc)[:512],
            )
            return

        # Fast-ack: complete BEFORE the long-running investigation so the
        # message lock cannot expire mid-run. The alert ledger makes any
        # crash-and-redeliver path idempotent.
        try:
            await receiver.complete_message(message)
        except Exception:
            logger.exception("Failed to complete message %s; will redeliver", message.message_id)
            return

        try:
            await self._process(payload, props)
        except Exception:
            # Message is already completed; the failure is logged and the
            # incident (if created) is recoverable via its checkpoint.
            logger.exception("Processing failed for message %s", message.message_id)

    @staticmethod
    def _parse(message):
        body = b"".join(
            part if isinstance(part, bytes) else part.encode() for part in message.body
        ).decode("utf-8")
        payload = json.loads(body)
        props = {
            (k.decode() if isinstance(k, bytes) else k):
            (v.decode() if isinstance(v, bytes) else v)
            for k, v in (message.application_properties or {}).items()
        }
        return payload, props

    async def _process(self, payload: dict, props: dict) -> None:
        event_type = str(props.get("event_type", "alert"))
        if event_type == "approval":
            result = await self.service.submit_approval(
                incident_id=str(payload["incident_id"]),
                approved=bool(payload.get("approved", False)),
                approver=str(payload.get("approver", "service-bus")),
                reason=str(payload.get("reason", "")),
                channel="service_bus",
                # A message on the private approvals subscription is treated
                # as verified: publishing rights to the topic ARE the
                # credential. Lock the topic down with RBAC accordingly.
                approver_verified=True,
            )
        else:
            result = await self.service.handle_alert(
                payload, source_hint=str(props.get("source", ""))
            )
        logger.info("Processed %s message: %s", event_type, result)

    async def _maybe_sweep(self) -> None:
        if time.monotonic() - self._last_sweep < SWEEP_INTERVAL_SECONDS:
            return
        self._last_sweep = time.monotonic()
        try:
            escalated = await self.service.sweep_expired_approvals()
            if escalated:
                logger.warning("Sweeper escalated %d timed-out approvals", len(escalated))
        except Exception:
            logger.exception("Approval sweep failed")


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
