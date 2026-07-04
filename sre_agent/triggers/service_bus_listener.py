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

Reliability behavior (ordered to close every crash window):
  - Alerts are CLAIMED (durably, payload included) BEFORE the message is
    completed, then the long investigation runs after completion so the
    lock can't expire mid-run. Crash before the claim -> message redelivers;
    crash after the claim but before completion -> redelivery is detected
    as an unprocessed duplicate and reclaimed; crash mid-investigation ->
    the stalled-intake sweeper re-runs it from the stored payload.
  - Poison messages (unparseable JSON / schema garbage) are DEAD-LETTERED
    immediately with a reason instead of burning redelivery cycles.
  - The sweep between receive batches escalates timed-out approvals AND
    recovers stalled intakes.
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

        event_type = str(props.get("event_type", "alert"))

        # Alerts: claim durably (payload stored) BEFORE completing the
        # message, then run the long investigation after completion so the
        # lock can't expire mid-run. Every crash window is covered by
        # redelivery + reclaim or the stalled-intake sweeper.
        registration = None
        if event_type != "approval":
            try:
                registration = self.service.register_alert(
                    payload, source_hint=str(props.get("source", ""))
                )
            except Exception:
                logger.exception(
                    "Claim failed for message %s; abandoning for redelivery",
                    message.message_id,
                )
                await receiver.abandon_message(message)
                return

        try:
            await receiver.complete_message(message)
        except Exception:
            # Not completed -> Service Bus redelivers; the claim above makes
            # the redelivery land as duplicate-unprocessed and get reclaimed.
            logger.exception("Failed to complete message %s; will redeliver", message.message_id)
            return

        try:
            if event_type == "approval":
                await self._process_approval(payload)
            else:
                result = await self.service.run_registered(registration)
                logger.info("Processed alert message: %s", result)
        except Exception:
            # Message is completed; a crashed investigation is recovered by
            # the stalled-intake sweeper from the claim's stored payload.
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

    async def _process_approval(self, payload: dict) -> None:
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
        logger.info("Processed approval message: %s", result)

    async def _maybe_sweep(self) -> None:
        if time.monotonic() - self._last_sweep < SWEEP_INTERVAL_SECONDS:
            return
        self._last_sweep = time.monotonic()
        try:
            escalated = await self.service.sweep_expired_approvals()
            if escalated:
                logger.warning("Sweeper escalated %d timed-out approvals", len(escalated))
            recovered = await self.service.recover_stalled_intakes()
            if recovered:
                logger.warning("Sweeper recovered %d stalled intakes", len(recovered))
        except Exception:
            logger.exception("Sweep failed")


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
