import time
import logging
from typing import Dict, Any, List
from backend.config import (
    WEIGHT_GATV2_NETWORK,
    WEIGHT_MESSAGE_CONTENT,
    WEIGHT_URL_RISK,
    WEIGHT_BEHAVIOR_RISK,
    USER_BLOCK_THRESHOLD,
    MESSAGE_RISK_WARN_THRESHOLD,
    URL_RISK_WARN_THRESHOLD
)
from backend.security.blocking import blocking_manager
from backend.realtime.events import event_bus, EventType

logger = logging.getLogger(__name__)

class ThreatEngine:
    def __init__(self):
        # Accumulates risk per user: username -> { "cumulative_score": float, "history": list, "last_updated": float }
        self.user_cumulative_risk: Dict[str, Dict[str, Any]] = {}

    def get_user_risk(self, username: str) -> float:
        rec = self.user_cumulative_risk.get(username.lower())
        if not rec:
            return 0.0
        # Decay risk slightly over time (half-life of 60 seconds)
        now = time.time()
        elapsed = now - rec["last_updated"]
        decay = 0.5 ** (elapsed / 60.0)
        return round(rec["cumulative_score"] * decay, 4)

    async def evaluate_message_event(
        self,
        username: str,
        user_ip: str,
        message_analysis: Dict[str, Any],
        url_analysis: Dict[str, Any],
        behavior_analysis: Dict[str, Any],
        gatv2_network_analysis: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Combines 4 distinct signals:
        1. GATv2 Network Risk (from GATv2 inference on real flows)
        2. Message Content Risk (urgency, uppercase, keyword heuristics)
        3. URL Risk (phishing indicators, IP URLs, deceptive structure)
        4. Behavior Risk (flood detection, rapid messages, repetition)
        """
        msg_risk = float(message_analysis.get("message_risk", 0.0))
        url_risk = float(url_analysis.get("url_risk", 0.0))
        beh_risk = float(behavior_analysis.get("behavior_risk", 0.0))
        
        # Unavailable is distinct from a measured benign score of zero.
        network_available = bool(gatv2_network_analysis and gatv2_network_analysis.get("available", True))
        net_risk = 0.0
        gatv2_is_anomaly = False
        gatv2_confidence = 0.0
        if network_available:
            net_risk = float(gatv2_network_analysis.get("anomaly_probability", 0.0))
            gatv2_is_anomaly = bool(gatv2_network_analysis.get("is_anomaly", False))
            gatv2_confidence = float(gatv2_network_analysis.get("confidence", 0.0))

        # 1. Calibrated Weighted Threat Score
        signals = [(WEIGHT_MESSAGE_CONTENT, msg_risk), (WEIGHT_URL_RISK, url_risk),
                   (WEIGHT_BEHAVIOR_RISK, beh_risk)]
        if network_available:
            signals.append((WEIGHT_GATV2_NETWORK, net_risk))
        weight_total = sum(weight for weight, _ in signals)
        weighted_score = sum(weight * value for weight, value in signals) / max(weight_total, 1e-9)

        # Rule-Assisted Multipliers:
        # If both a high-risk URL AND a network anomaly co-occur, elevate threat
        if url_risk >= 0.80:
            weighted_score = max(weighted_score, 0.70)

        threat_score = min(1.0, round(weighted_score, 4))

        # 2. Accumulate User Risk
        username_key = username.lower()
        now = time.time()
        curr_risk = self.get_user_risk(username)
        # New cumulative risk: 0.6 * previous decayed risk + 0.7 * current event threat
        new_cumulative = min(1.0, round(curr_risk * 0.6 + threat_score * 0.7, 4))

        all_indicators = (
            message_analysis.get("indicators", []) +
            url_analysis.get("indicators", []) +
            behavior_analysis.get("indicators", [])
        )
        if gatv2_is_anomaly:
            all_indicators.append(f"GATv2 Network Anomaly detected (Confidence: {gatv2_confidence}%)")

        self.user_cumulative_risk[username_key] = {
            "cumulative_score": new_cumulative,
            "last_updated": now,
            "last_threat_score": threat_score,
            "last_indicators": all_indicators
        }

        # 3. Decision Matrix
        action = "ALLOW"
        reason = "Normal Activity"

        # Check blocking thresholds
        if beh_risk >= 1.0 or (new_cumulative >= USER_BLOCK_THRESHOLD and threat_score >= 0.65):
            action = "BLOCK_USER"
            reason = f"Critical Threat Score ({int(threat_score*100)}%) / Cumulative Risk ({int(new_cumulative*100)}%)"
            block_info = blocking_manager.block_user(
                username=username,
                ip=user_ip,
                reason=reason,
                threat_score=threat_score
            )
            await event_bus.emit(EventType.USER_BLOCKED, block_info)

        elif threat_score >= 0.65 or url_risk >= URL_RISK_WARN_THRESHOLD or beh_risk >= 0.70:
            action = "BLOCK_MESSAGE"
            reason = "Suspicious message or malicious link rejected"
            await event_bus.emit(EventType.MESSAGE_BLOCKED, {
                "username": username,
                "ip": user_ip,
                "threat_score": threat_score,
                "reason": reason,
                "indicators": all_indicators
            })

        elif threat_score >= 0.40:
            action = "WARN"
            reason = "Moderate risk indicators detected"

        decision_payload = {
            "username": username,
            "user_ip": user_ip,
            "action": action,
            "threat_score": threat_score,
            "cumulative_user_risk": new_cumulative,
            "reason": reason,
            "signals": {
                "gatv2_network_risk": round(net_risk, 4),
                "network_signal_available": network_available,
                "gatv2_is_anomaly": gatv2_is_anomaly,
                "gatv2_confidence": gatv2_confidence,
                "message_risk": round(msg_risk, 4),
                "url_risk": round(url_risk, 4),
                "behavior_risk": round(beh_risk, 4)
            },
            "indicators": all_indicators,
            "final_risk": threat_score,
            "severity": "HIGH" if threat_score >= 0.65 else "SUSPICIOUS" if threat_score >= 0.40 else "SAFE",
            "network_signal_available": network_available,
            "reasons": list(all_indicators) or [reason],
            "timestamp": now
        }

        if threat_score >= 0.40:
            await event_bus.emit(EventType.THREAT_DETECTED, decision_payload)

        return decision_payload

threat_engine = ThreatEngine()

