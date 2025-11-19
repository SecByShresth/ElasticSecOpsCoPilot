# ============================================================================
# FILE 2: src/ingestion/stream_handler.py - FIXED
# ============================================================================
"""Real-time alert streaming handler."""

from typing import Any, Callable
from dataclasses import dataclass
from datetime import datetime
from src.models.event import SecurityEvent
from src.utils.logger import get_default_logger


@dataclass
class StreamConfig:
    """Configuration for stream handler."""
    batch_size: int = 10
    batch_mode: bool = False
    timeout_seconds: int = 30
    max_queue_size: int = 1000


@dataclass
class StreamMetrics:
    """Metrics for streaming."""
    events_received: int = 0
    events_processed: int = 0
    events_failed: int = 0
    start_time: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "events_received": self.events_received,
            "events_processed": self.events_processed,
            "events_failed": self.events_failed,
            "rate_per_second": (
                self.events_processed / (datetime.utcnow() - self.start_time).total_seconds()
                if self.start_time else 0
            ),
        }


class StreamHandler:
    """Handles real-time alert streaming."""

    def __init__(self, config: StreamConfig | None = None):
        """
        Initialize stream handler.

        Args:
            config: Stream configuration
        """
        self.config = config or StreamConfig()
        self.logger = get_default_logger(level="INFO")
        self.handlers: list[Callable] = []
        self.metrics = StreamMetrics(start_time=datetime.utcnow())
        self.event_queue: list[SecurityEvent] = []

    def add_handler(self, handler: Callable[[SecurityEvent], None]) -> None:
        """
        Add event handler.

        Args:
            handler: Callable that processes SecurityEvent
        """
        self.handlers.append(handler)
        self.logger.info(f"Added event handler: {handler.__name__}")

    def ingest_webhook(self, payload: dict[str, Any]) -> bool:
        """
        Ingest webhook payload.

        Args:
            payload: Webhook payload from Elasticsearch

        Returns:
            True if successful
        """
        try:
            # Parse Elastic alert from webhook
            event = SecurityEvent.from_elastic_alert(payload)

            # Check for duplicates
            if self._is_duplicate(event):
                self.logger.debug(f"Duplicate event: {event.event_id}")
                return False

            # Add to queue
            self.event_queue.append(event)
            self.metrics.events_received += 1

            # Process if batch mode or batch size reached
            if (
                not self.config.batch_mode
                or len(self.event_queue) >= self.config.batch_size
            ):
                self._process_queue()

            return True

        except Exception as e:
            self.logger.error(f"Failed to ingest webhook: {e}")
            self.metrics.events_failed += 1
            return False

    def _process_queue(self) -> None:
        """Process queued events."""
        for event in self.event_queue:
            try:
                for handler in self.handlers:
                    handler(event)
                self.metrics.events_processed += 1
            except Exception as e:
                self.logger.error(f"Handler failed: {e}")
                self.metrics.events_failed += 1

        self.event_queue.clear()

    def _is_duplicate(self, event: SecurityEvent) -> bool:
        """Check if event is duplicate."""
        for queued_event in self.event_queue:
            if queued_event.event_id == event.event_id:
                return True
        return False

    def get_metrics(self) -> StreamMetrics:
        """Get current metrics."""
        return self.metrics