import ipaddress
import time
import logging
from typing import Any

logger = logging.getLogger(__name__)

class BlockingManager:
    def __init__(self):
        self.blocked_users: dict[str, dict[str, Any]] = {}
        self.blocked_ips: dict[str, set[str]] = {}

    @staticmethod
    def _ip_key(ip: str | None) -> str | None:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return str(address).split("%", 1)[0]

    def is_user_blocked(self, username: str) -> bool:
        return username.casefold() in self.blocked_users

    def is_ip_blocked(self, ip: str | None) -> bool:
        return self._ip_key(ip) in self.blocked_ips

    def get_block_info(self, username: str) -> dict[str, Any] | None:
        return self.blocked_users.get(username.casefold())

    def block_user(self, username: str, ip: str | None = None, reason: str = "High Threat Score",
                   threat_score: float = 1.0) -> dict[str, Any]:
        username_key = username.casefold()
        ip_key = self._ip_key(ip)
        previous = self.blocked_users.get(username_key)
        if previous and previous["ip"] != ip_key:
            self._remove_ip_block(previous["ip"], username_key)
        block_record = {
            "username": username,
            "ip": ip_key,
            "reason": reason,
            "threat_score": threat_score,
            "timestamp": time.time(),
            "formatted_time": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.blocked_users[username_key] = block_record
        if ip_key:
            self.blocked_ips.setdefault(ip_key, set()).add(username_key)

        logger.warning(f"🚫 [SECURITY ACTION] USER BLOCKED: {username} (IP: {ip}) | Reason: {reason} | Score: {threat_score}")
        return block_record

    def _remove_ip_block(self, ip: str | None, username_key: str) -> None:
        users = self.blocked_ips.get(ip)
        if users is not None:
            users.discard(username_key)
            if not users:
                self.blocked_ips.pop(ip, None)

    def unblock_user(self, username: str) -> dict[str, Any] | None:
        username_key = username.casefold()
        record = self.blocked_users.pop(username_key, None)
        if record:
            self._remove_ip_block(record["ip"], username_key)
            logger.info(f"User {username} has been unblocked.")
        return record

    def get_all_blocked(self) -> list:
        return list(self.blocked_users.values())

blocking_manager = BlockingManager()

