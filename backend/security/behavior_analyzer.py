"""Sliding-window message behavior analysis; independent of network ML."""
from __future__ import annotations

import re
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class BehaviorConfig:
    warning_messages_30s: int = 12
    block_messages_30s: int = 24
    window_seconds: float = 60.0


@dataclass
class UserBehavior:
    messages: deque = field(default_factory=deque)
    total_messages: int = 0


class BehaviorAnalyzer:
    def __init__(self, config: BehaviorConfig | None = None, clock: Callable[[], float] = time.monotonic):
        self.config = config or BehaviorConfig()
        self.clock = clock
        self.users: dict[str, UserBehavior] = defaultdict(UserBehavior)

    def record(self, username: str, recipient: str, text: str) -> dict:
        now = self.clock()
        user = self.users[username]
        while user.messages and now - user.messages[0][0] > self.config.window_seconds:
            user.messages.popleft()
        normalized = text.strip().casefold()
        urls = re.findall(r"https?://[^\s<>\"']+", text, re.IGNORECASE)
        user.messages.append((now, recipient, normalized, tuple(urls)))
        user.total_messages += 1
        messages = list(user.messages)
        last = lambda seconds: [item for item in messages if now - item[0] <= seconds]
        one, five, thirty, sixty = (last(s) for s in (1, 5, 30, 60))
        repeats = sum(item[2] == normalized for item in sixty)
        counts = Counter(item[2] for item in sixty)
        repeated = sum(n for n in counts.values() if n > 1)
        recipient_counts = len({item[1] for item in sixty})
        url_count = sum(len(item[3]) for item in sixty)
        return {
            "total_messages": user.total_messages,
            "messages_last_second": len(one), "messages_last_5_seconds": len(five),
            "messages_last_30_seconds": len(thirty), "messages_last_60_seconds": len(sixty),
            "messages_per_second": round(len(one), 3),
            "messages_per_minute": round(len(sixty) * 60 / max(min(60.0, self.config.window_seconds), 1.0), 3),
            "unique_recipients_last_minute": recipient_counts,
            "repeated_messages": repeats,
            "repeated_message_ratio": round(repeated / len(sixty), 3) if sixty else 0.0,
            "repeated_url_count": max(0, url_count - len({url for item in sixty for url in item[3]})),
            "risk": "BLOCK" if len(thirty) >= self.config.block_messages_30s else "SUSPICIOUS" if len(thirty) >= self.config.warning_messages_30s else "SAFE",
        }

    def reset(self, username: str) -> None:
        self.users.pop(username, None)

    def snapshot(self) -> dict[str, dict]:
        now = self.clock()
        result = {}
        for name, user in self.users.items():
            items = [item for item in user.messages if now - item[0] <= 60]
            thirty = [item for item in items if now - item[0] <= 30]
            result[name] = {"total_messages": user.total_messages, "messages_last_30_seconds": len(thirty),
                            "messages_per_second": round(sum(now-item[0] <= 1 for item in items), 3),
                            "messages_per_minute": len(items), "unique_recipients": len({item[1] for item in items}),
                            "risk": "BLOCK" if len(thirty) >= self.config.block_messages_30s else "SUSPICIOUS" if len(thirty) >= self.config.warning_messages_30s else "SAFE"}
        return result
