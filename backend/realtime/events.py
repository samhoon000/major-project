import asyncio
import time
from typing import Callable, Dict, List, Any
import logging

logger = logging.getLogger(__name__)

class EventType:
    PACKET_CAPTURED = "PACKET_CAPTURED"
    FLOW_UPDATED = "FLOW_UPDATED"
    FLOW_COMPLETED = "FLOW_COMPLETED"
    GATV2_PREDICTION = "GATV2_PREDICTION"
    MESSAGE_RECEIVED = "MESSAGE_RECEIVED"
    URL_ANALYZED = "URL_ANALYZED"
    BEHAVIOR_UPDATED = "BEHAVIOR_UPDATED"
    THREAT_DETECTED = "THREAT_DETECTED"
    MESSAGE_BLOCKED = "MESSAGE_BLOCKED"
    USER_BLOCKED = "USER_BLOCKED"
    STATS_UPDATED = "STATS_UPDATED"

class EventBus:
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}

    def subscribe(self, event_type: str, callback: Callable):
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)

    async def emit(self, event_type: str, data: Any):
        event_payload = {
            "type": event_type,
            "timestamp": time.time(),
            "data": data
        }
        if event_type in self._subscribers:
            for callback in self._subscribers[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(event_payload)
                    else:
                        callback(event_payload)
                except Exception as e:
                    logger.error(f"Error executing event callback for {event_type}: {e}")

# Global Event Bus Singleton
event_bus = EventBus()

