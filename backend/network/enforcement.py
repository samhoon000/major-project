"""Temporary, source-IP Windows Firewall quarantine for GATv2 attack events."""
from __future__ import annotations

import hashlib
import ipaddress
import os
import platform
import socket
import subprocess
import time
from dataclasses import asdict, dataclass
from typing import Callable


@dataclass
class Quarantine:
    source_ip: str
    reason: str
    anomaly_probability: float
    flow_id: str
    first_detected: float
    blocked_until: float
    status: str = "BLOCKED"
    rule_name: str | None = None


def protected_server_ips() -> set[str]:
    """Return local interface addresses used to prevent self-blocking."""
    addresses = {"127.0.0.1", "::1"}
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None):
            addresses.add(item[4][0].split("%", 1)[0])
    except OSError:
        pass
    try:
        # Scapy reports configured addresses without creating a capture handle.
        from scapy.all import get_if_addr, get_if_list
        for interface in get_if_list():
            address = get_if_addr(interface)
            if address and address != "0.0.0.0":
                addresses.add(address)
    except (ImportError, OSError):
        pass
    return addresses


class WindowsFirewall:
    """Creates/removes named inbound rules; caller is responsible for elevation."""
    def __init__(self, runner: Callable = subprocess.run):
        self.runner = runner

    @staticmethod
    def rule_name(source_ip: str) -> str:
        digest = hashlib.sha256(source_ip.encode("ascii")).hexdigest()[:16]
        return f"MajorProject-GATv2-Quarantine-{digest}"

    def block(self, source_ip: str) -> str:
        name = self.rule_name(source_ip)
        script = ("Get-NetFirewallRule -DisplayName '" + name + "' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; "
                  "New-NetFirewallRule -DisplayName '" + name + "' -Direction Inbound "
                  "-Action Block -RemoteAddress '" + source_ip + "' -Profile Any | Out-Null")
        self.runner(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                    check=True, capture_output=True, text=True)
        return name

    def unblock(self, rule_name: str) -> None:
        script = "Remove-NetFirewallRule -DisplayName '" + rule_name + "' -ErrorAction SilentlyContinue"
        self.runner(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                    check=True, capture_output=True, text=True)


class QuarantineManager:
    def __init__(self, firewall=None, duration_seconds: int | None = None,
                 protected_ips: set[str] | None = None, admin_ips: set[str] | None = None,
                 clock: Callable[[], float] = time.time, platform_name: str | None = None):
        self.firewall = firewall or WindowsFirewall()
        self.duration_seconds = duration_seconds or int(os.getenv("NETWORK_BLOCK_SECONDS", "300"))
        self.protected_ips = {str(ipaddress.ip_address(ip)) for ip in (protected_ips if protected_ips is not None else protected_server_ips())}
        configured = admin_ips if admin_ips is not None else filter(None, os.getenv("ADMIN_IPS", "").split(","))
        self.admin_ips = {str(ipaddress.ip_address(ip.strip())) for ip in configured}
        self.clock = clock
        self.platform_name = platform_name or platform.system()
        self.blocks: dict[str, Quarantine] = {}

    def handle_attack(self, event: dict) -> tuple[Quarantine | None, str]:
        """Block only an explicitly ATTACK prediction at or above the model threshold."""
        source = str(ipaddress.ip_address(event["source_ip"]))
        probability, threshold = float(event["anomaly_probability"]), float(event["threshold"])
        if event.get("prediction") != "ATTACK" or probability < threshold:
            return None, "NO_BLOCK_BENIGN_OR_BELOW_THRESHOLD"
        if source in self.protected_ips or source in self.admin_ips:
            return None, "SELF_ATTACK_NO_NETWORK_BLOCK" if source in self.protected_ips else "ADMIN_IP_PROTECTED"
        if self.platform_name != "Windows":
            return None, "BLOCK_UNAVAILABLE_NON_WINDOWS"
        existing = self.blocks.get(source)
        now = self.clock()
        if existing and existing.status == "BLOCKED" and existing.blocked_until > now:
            return existing, "DUPLICATE_BLOCK_PREVENTED"
        reason = f"GATv2 ATTACK probability {probability:.6f} >= threshold {threshold:.6f}"
        name = self.firewall.block(source)
        block = Quarantine(source, reason, probability, str(event["flow_id"]), now,
                           now + max(1, self.duration_seconds), "BLOCKED", name)
        self.blocks[source] = block
        return block, "BLOCK_APPLIED"

    def unblock(self, source_ip: str, status: str = "ADMIN_UNBLOCKED") -> Quarantine | None:
        source = str(ipaddress.ip_address(source_ip))
        block = self.blocks.get(source)
        if not block or block.status != "BLOCKED":
            return None
        if block.rule_name:
            self.firewall.unblock(block.rule_name)
        block.status = status
        return block

    def expire(self) -> list[Quarantine]:
        now, expired = self.clock(), []
        for source, block in list(self.blocks.items()):
            if block.status == "BLOCKED" and block.blocked_until <= now:
                expired_block = self.unblock(source, "EXPIRED")
                if expired_block:
                    expired.append(expired_block)
        return expired

    def close(self) -> list[Quarantine]:
        """Remove all managed rules during a normal application shutdown."""
        closed = []
        for source, block in list(self.blocks.items()):
            item = self.unblock(source, "SHUTDOWN_CLEANUP")
            if item:
                closed.append(item)
        return closed

    def snapshot(self) -> list[dict]:
        return [asdict(block) for block in self.blocks.values()]
