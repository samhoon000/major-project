import re
from typing import Dict, Any, List

SUSPICIOUS_KEYWORDS = [
    "urgent", "immediately", "verify", "suspended", "account",
    "password", "login", "bank", "security alert", "action required",
    "winner", "lottery", "claim now", "unauthorized", "confirm",
    "click here", "gift card", "crypto", "bitcoin"
]

class MessageAnalyzer:
    def analyze(self, text: str) -> Dict[str, Any]:
        if not text or not text.strip():
            return {
                "message_risk": 0.0,
                "indicators": [],
                "length": 0
            }

        text_clean = text.strip()
        length = len(text_clean)
        indicators: List[str] = []
        score = 0.0

        # 1. Uppercase ratio (shouting / urgency)
        letters = [c for c in text_clean if c.isalpha()]
        if letters:
            upper_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
            if upper_ratio > 0.6 and len(letters) >= 8:
                score += 0.25
                indicators.append(f"High uppercase ratio ({int(upper_ratio*100)}%)")

        # 2. Exclamation mark flood
        exclamations = text_clean.count("!")
        if exclamations >= 3:
            score += 0.15
            indicators.append(f"Multiple exclamation marks ({exclamations})")

        # 3. Keyword matching
        text_lower = text_clean.lower()
        matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_lower]
        if matched_keywords:
            keyword_penalty = min(0.40, 0.12 * len(matched_keywords))
            score += keyword_penalty
            indicators.append(f"Suspicious security keywords: {', '.join(matched_keywords[:3])}")

        # 4. Repeated character patterns (e.g. 'aaaaa', '$$$$$')
        if re.search(r'(.)\1{4,}', text_clean):
            score += 0.10
            indicators.append("Repetitive character pattern")

        # 5. Very short urgency text
        if length < 40 and any(k in text_lower for k in ["urgent", "verify now", "click here"]):
            score += 0.15
            indicators.append("Short aggressive call-to-action")

        risk = min(1.0, round(score, 4))
        return {
            "message_risk": risk,
            "indicators": indicators,
            "length": length
        }

message_analyzer = MessageAnalyzer()

