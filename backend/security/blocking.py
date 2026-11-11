import time
import logging
from typing import Dict, Any, Set, Optional

logger = logging.getLogger(__name__)

class BlockingManager:
    def __init__(self):
        self.blocked_users: Dict[str, Dict[str, Any]] = {}
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}

    def is_user_blocked(self, username: str) -> bool:
        return username.lower() in self.blocked_users

    def is_ip_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def get_block_info(self, username: str) -> Optional[Dict[str, Any]]:
        return self.blocked_users.get(username.lower())

    def block_user(self, username: str, ip: str = None, reason: str = "High Threat Score", threat_score: float = 1.0) -> Dict[str, Any]:
        username_key = username.lower()
        block_record = {
            "username": username,
            "ip": ip,
            "reason": reason,
            "threat_score": threat_score,
            "timestamp": time.time(),
            "formatted_time": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.blocked_users[username_key] = block_record
        if ip:
            self.blocked_ips[ip] = block_record

        logger.warning(f"🚫 [SECURITY ACTION] USER BLOCKED: {username} (IP: {ip}) | Reason: {reason} | Score: {threat_score}")
        return block_record

    def unblock_user(self, username: str):
        username_key = username.lower()
        if username_key in self.blocked_users:
            rec = self.blocked_users.pop(username_key)
            if rec.get("ip") and rec["ip"] in self.blocked_ips:
                self.blocked_ips.pop(rec["ip"], None)
            logger.info(f"User {username} has been unblocked.")

    def get_all_blocked(self) -> list:
        return list(self.blocked_users.values())

blocking_manager = BlockingManager()

