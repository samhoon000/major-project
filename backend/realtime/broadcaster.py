import asyncio
import json
import logging
from typing import Set
from fastapi import WebSocket
from backend.realtime.events import event_bus, EventType

logger = logging.getLogger(__name__)

class DashboardBroadcaster:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._setup_event_listeners()

    def _setup_event_listeners(self):
        # Forward key security events to connected dashboard WebSockets
        for evt in [
            EventType.STATS_UPDATED,
            EventType.FLOW_UPDATED,
            EventType.GATV2_PREDICTION,
            EventType.THREAT_DETECTED,
            EventType.MESSAGE_BLOCKED,
            EventType.USER_BLOCKED,
            EventType.MESSAGE_RECEIVED
        ]:
            event_bus.subscribe(evt, self._broadcast_event)

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"Dashboard client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info(f"Dashboard client disconnected. Total clients: {len(self.active_connections)}")

    async def _broadcast_event(self, event_payload: dict):
        if not self.active_connections:
            return

        message = json.dumps(event_payload)
        dead_connections = set()

        for conn in list(self.active_connections):
            try:
                await conn.send_text(message)
            except Exception:
                dead_connections.add(conn)

        for dead in dead_connections:
            self.active_connections.discard(dead)

dashboard_broadcaster = DashboardBroadcaster()

