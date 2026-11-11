import time
from collections import defaultdict, deque
from typing import Dict, Any, List
from backend.config import BEHAVIOR_WINDOW_SECONDS, MAX_MESSAGES_PER_WINDOW, MAX_REPEATED_MESSAGES

class UserBehaviorState:
    def __init__(self, username: str):
        self.username = username
        self.message_timestamps: deque = deque()
        self.recent_contents: deque = deque()
        self.recent_recipients: deque = deque()
        self.url_timestamps: deque = deque()
        self.risk_score: float = 0.0

    def purge_old_events(self, now: float, window: float):
        cutoff = now - window
        while self.message_timestamps and self.message_timestamps[0] < cutoff:
            self.message_timestamps.popleft()
        while self.recent_contents and self.recent_contents[0][0] < cutoff:
            self.recent_contents.popleft()
        while self.recent_recipients and self.recent_recipients[0][0] < cutoff:
            self.recent_recipients.popleft()
        while self.url_timestamps and self.url_timestamps[0] < cutoff:
            self.url_timestamps.popleft()

class BehaviorAnalyzer:
    def __init__(self):
        self.user_states: Dict[str, UserBehaviorState] = defaultdict(UserBehaviorState)

    def record_and_analyze(
        self, username: str, content: str, recipient: str, has_url: bool = False
    ) -> Dict[str, Any]:
        now = time.time()
        state = self.user_states[username]
        state.username = username

        # Purge events outside window
        state.purge_old_events(now, BEHAVIOR_WINDOW_SECONDS)

        # Record event
        state.message_timestamps.append(now)
        state.recent_contents.append((now, content.strip().lower()))
        state.recent_recipients.append((now, recipient))
        if has_url:
            state.url_timestamps.append(now)

        # 1. Rate calculation
        msg_count = len(state.message_timestamps)
        duration = max(0.5, now - state.message_timestamps[0]) if msg_count > 1 else 1.0
        msgs_per_second = round(msg_count / duration, 2)
        msgs_per_minute = round(msgs_per_second * 60, 1)

        # 2. Repeated message content
        identical_count = sum(1 for _, c in state.recent_contents if c == content.strip().lower())

        # 3. Unique recipients in window
        unique_recipients = len(set(r for _, r in state.recent_recipients))

        # 4. Score calculation
        score = 0.0
        indicators: List[str] = []

        # High message frequency
        if msg_count > MAX_MESSAGES_PER_WINDOW:
            freq_penalty = min(0.50, 0.10 * (msg_count - MAX_MESSAGES_PER_WINDOW))
            score += freq_penalty
            indicators.append(f"Message flooding: {msg_count} messages in {int(BEHAVIOR_WINDOW_SECONDS)}s ({msgs_per_second} msg/s)")

        # Repeated identical spam messages
        if identical_count >= MAX_REPEATED_MESSAGES:
            score += 0.35
            indicators.append(f"Identical message repetition ({identical_count} identical messages)")

        # Rapid-fire timing (< 0.25s interval)
        if len(state.message_timestamps) >= 2:
            last_interval = state.message_timestamps[-1] - state.message_timestamps[-2]
            if last_interval < 0.25:
                score += 0.20
                indicators.append(f"Unusually rapid message interval ({round(last_interval*1000)}ms)")

        # Mass messaging to multiple recipients
        if unique_recipients >= 3 and msg_count >= 5:
            score += 0.25
            indicators.append(f"Mass messaging: broadcast to {unique_recipients} unique targets")

        # URL repetition
        if len(state.url_timestamps) >= 3:
            score += 0.30
            indicators.append(f"Repeated link spreading ({len(state.url_timestamps)} links in window)")

        risk = min(1.0, round(score, 4))
        state.risk_score = risk

        return {
            "behavior_risk": risk,
            "messages_in_window": msg_count,
            "messages_per_second": msgs_per_second,
            "messages_per_minute": msgs_per_minute,
            "identical_count": identical_count,
            "unique_recipients": unique_recipients,
            "indicators": indicators
        }

behavior_analyzer = BehaviorAnalyzer()

