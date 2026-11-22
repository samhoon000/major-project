"""Bounded, content-free projection of existing chat moderation events."""

from collections import deque
import time


class ChatMonitoring:
    WINDOW = 60

    def __init__(self, clock=time.time):
        self.clock = clock
        self.started = int(clock())
        self.activity = {}
        self.events = deque(maxlen=50)

    def record(self, kind, data, timestamp):
        action = data.get("action")
        event_type = None
        bucket = None
        if kind == "threat_decision":
            bucket = 0
            if action == "WARN":
                event_type = "warning"
        elif kind == "message_blocked":
            bucket = 2
            event_type = "message_blocked"
        elif kind == "blocked":
            if data.get("message_id"):
                bucket = 2
            event_type = "blocked"
        elif kind == "admin_unblocked":
            event_type = "admin_unblocked"

        if bucket is not None:
            second = int(timestamp)
            self._expire(second)
            counts = self.activity.setdefault(second, [0, 0, 0])
            counts[bucket] += 1
            if kind == "threat_decision" and action in {"WARN", "BLOCK_MESSAGE", "BLOCK_USER"}:
                counts[1] += 1

        if event_type:
            self.events.appendleft({
                "type": event_type,
                "timestamp": timestamp,
                "username": data.get("username") or data.get("sender"),
                "reason": data.get("reason"),
            })

    def _expire(self, second):
        for expired in tuple(self.activity):
            if expired < second - self.WINDOW:
                del self.activity[expired]

    def snapshot(self):
        now = self.clock()
        second = int(now)
        self._expire(second)
        # Use completed one-second buckets, including during a quiet period.
        samples = [
            self.activity.get(slot, [0, 0, 0]) if slot >= self.started else [None, None, None]
            for slot in range(second - self.WINDOW, second)
        ]
        return {"timestamp": now, "samples": samples, "events": list(self.events)}
