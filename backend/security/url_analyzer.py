import re
import urllib.parse
from typing import Dict, Any, List

URL_REGEX = re.compile(
    r'(https?://[^\s<>"]+|www\.[^\s<>"]+)',
    re.IGNORECASE
)

SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".test", ".click"}
KNOWN_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly"}
PHISHING_KEYWORDS = {"login", "verify", "secure", "bank", "update", "account", "wallet", "signin", "auth"}

class URLAnalyzer:
    def analyze(self, text: str) -> Dict[str, Any]:
        urls = URL_REGEX.findall(text)
        if not urls:
            return {
                "url_risk": 0.0,
                "url_count": 0,
                "detected_urls": [],
                "indicators": []
            }

        max_risk = 0.0
        all_indicators: List[str] = []
        parsed_url_details = []

        for raw_url in urls:
            url_str = raw_url if raw_url.startswith(("http://", "https://")) else f"http://{raw_url}"
            try:
                parsed = urllib.parse.urlparse(url_str)
                hostname = parsed.hostname or ""
            except Exception:
                continue

            score = 0.0
            indicators = []

            # 1. Plain HTTP
            if parsed.scheme == "http":
                score += 0.25
                indicators.append("Insecure plain HTTP protocol")

            # 2. Raw IP address as hostname (e.g. http://192.168.1.50/login)
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
                score += 0.45
                indicators.append(f"Direct IP-based URL host ({hostname})")

            # 3. Suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if hostname.endswith(tld):
                    score += 0.30
                    indicators.append(f"High-risk TLD ({tld})")
                    break

            # 4. URL shortener
            if hostname.lower() in KNOWN_SHORTENERS:
                score += 0.35
                indicators.append(f"Obfuscated URL shortener ({hostname})")

            # 5. Excessive subdomains
            parts = hostname.split(".")
            if len(parts) >= 4 and not re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
                score += 0.20
                indicators.append(f"Excessive subdomain depth ({len(parts)} parts)")

            # 6. Phishing keywords in hostname or path
            lower_path = (hostname + parsed.path).lower()
            matched_phish = [kw for kw in PHISHING_KEYWORDS if kw in lower_path]
            if matched_phish:
                score += min(0.35, 0.15 * len(matched_phish))
                indicators.append(f"Phishing keywords in URL: {', '.join(matched_phish)}")

            # 7. Excessively long URL
            if len(url_str) > 75:
                score += 0.15
                indicators.append(f"Abnormally long URL length ({len(url_str)} chars)")

            single_risk = min(1.0, round(score, 4))
            max_risk = max(max_risk, single_risk)
            all_indicators.extend([f"[{raw_url[:30]}...] {ind}" for ind in indicators])

            parsed_url_details.append({
                "url": raw_url,
                "hostname": hostname,
                "risk": single_risk,
                "indicators": indicators
            })

        return {
            "url_risk": max_risk,
            "url_count": len(urls),
            "detected_urls": parsed_url_details,
            "indicators": all_indicators
        }

url_analyzer = URLAnalyzer()

