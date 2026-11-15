"""Temporary, source-IP Windows Firewall quarantine for GATv2 attack events."""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import platform
import socket
import subprocess
import time
from dataclasses import asdict, dataclass
from typing import Callable

log = logging.getLogger(__name__)


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


def get_default_gateways() -> set[str]:
    """Discover default network gateway IPs to prevent severing host internet/LAN access."""
    gateways: set[str] = set()
    # 1. Configured environment variable override
    env_gw = os.getenv("DEFAULT_GATEWAY_IP")
    if env_gw:
        for item in env_gw.split(","):
            item = item.strip()
            if item:
                try:
                    gateways.add(str(ipaddress.ip_address(item)))
                except ValueError:
                    pass

    # 2. Windows route table query
    if platform.system() == "Windows":
        try:
            out = subprocess.check_output(
                ["route", "print", "0.0.0.0"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=3.0,
            )
            for line in out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gw = parts[2]
                    if gw != "0.0.0.0":
                        try:
                            gateways.add(str(ipaddress.ip_address(gw)))
                        except ValueError:
                            pass
        except Exception:
            pass

    # 3. Scapy route table check if available
    try:
        from scapy.all import conf
        scapy_gw = conf.route.route("0.0.0.0")[2]
        if scapy_gw and scapy_gw != "0.0.0.0":
            gateways.add(str(ipaddress.ip_address(scapy_gw)))
    except Exception:
        pass

    return gateways


def protected_server_ips() -> set[str]:
    """Return local interface addresses, loopbacks, and default gateways to prevent self-blocking."""
    addresses = {"127.0.0.1", "::1"}
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None):
            raw = item[4][0].split("%", 1)[0]
            try:
                addresses.add(str(ipaddress.ip_address(raw)))
            except ValueError:
                pass
    except OSError:
        pass
    try:
        # Scapy reports configured addresses without creating a capture handle.
        from scapy.all import get_if_addr, get_if_list
        for interface in get_if_list():
            address = get_if_addr(interface)
            if address and address != "0.0.0.0":
                try:
                    addresses.add(str(ipaddress.ip_address(address)))
                except ValueError:
                    pass
    except (ImportError, OSError):
        pass

    # Protect default gateways
    addresses.update(get_default_gateways())

    # Protect any additional configured protected IPs
    configured_protected = os.getenv("PROTECTED_IPS", "")
    if configured_protected:
        for ip in configured_protected.split(","):
            ip = ip.strip()
            if ip:
                try:
                    addresses.add(str(ipaddress.ip_address(ip)))
                except ValueError:
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
                 clock: Callable[[], float] = time.time, platform_name: str | None = None,
                 auto_quarantine: bool | None = None):
        self.firewall = firewall or WindowsFirewall()
        self.duration_seconds = duration_seconds or int(os.getenv("NETWORK_BLOCK_SECONDS", "300"))
        
        # Protected host & gateway IPs
        raw_protected = protected_ips if protected_ips is not None else protected_server_ips()
        self.protected_ips: set[str] = set()
        for ip in raw_protected:
            try:
                self.protected_ips.add(str(ipaddress.ip_address(ip.strip() if isinstance(ip, str) else ip)))
            except ValueError:
                pass

        # Configured admin IPs
        configured_admin = admin_ips if admin_ips is not None else filter(None, os.getenv("ADMIN_IPS", "").split(","))
        self.admin_ips: set[str] = set()
        for ip in configured_admin:
            try:
                self.admin_ips.add(str(ipaddress.ip_address(ip.strip() if isinstance(ip, str) else ip)))
            except ValueError:
                pass

        self.clock = clock
        self.platform_name = platform_name or platform.system()
        
        # Safe toggle: default False unless explicitly enabled
        if auto_quarantine is not None:
            self.auto_quarantine = bool(auto_quarantine)
        else:
            self.auto_quarantine = os.getenv("NETWORK_AUTO_QUARANTINE", "false").lower() in ("true", "1", "yes")

        self.blocks: dict[str, Quarantine] = {}

    def handle_attack(self, event: dict) -> tuple[Quarantine | None, str]:
        """Block only an explicitly ATTACK prediction at or above the model threshold."""
        # 1. Validate source IP
        raw_source = event.get("source_ip")
        if not raw_source:
            return None, "INVALID_SOURCE_IP_EMPTY"
        try:
            source = str(ipaddress.ip_address(raw_source.strip()))
        except ValueError:
            return None, "INVALID_SOURCE_IP"

        # 2. Validate anomaly probability and threshold
        try:
            probability = float(event.get("anomaly_probability", 0.0))
            threshold = float(event.get("threshold", 0.53))
        except (ValueError, TypeError):
            return None, "INVALID_PROBABILITY_OR_THRESHOLD"

        if event.get("prediction") != "ATTACK" or probability < threshold:
            return None, "NO_BLOCK_BENIGN_OR_BELOW_THRESHOLD"

        # 3. Protected IP checks
        if source in self.protected_ips:
            return None, "SELF_ATTACK_NO_NETWORK_BLOCK"
        if source in self.admin_ips:
            return None, "ADMIN_IP_PROTECTED"

        # 4. Check OS platform
        if self.platform_name != "Windows":
            return None, "BLOCK_UNAVAILABLE_NON_WINDOWS"

        # 5. Check if auto quarantine is enabled
        if not self.auto_quarantine:
            return None, "AUTO_QUARANTINE_DISABLED"

        # 6. Check existing active quarantine
        now = self.clock()
        existing = self.blocks.get(source)
        if existing and existing.status == "BLOCKED" and existing.blocked_until > now:
            return existing, "DUPLICATE_BLOCK_PREVENTED"

        # 7. Apply firewall rule safely
        reason = f"GATv2 ATTACK probability {probability:.6f} >= threshold {threshold:.6f}"
        try:
            name = self.firewall.block(source)
            block = Quarantine(source, reason, probability, str(event.get("flow_id", "unknown")), now,
                               now + max(1, self.duration_seconds), "BLOCKED", name)
            self.blocks[source] = block
            return block, "BLOCK_APPLIED"
        except subprocess.CalledProcessError as exc:
            log.warning("Firewall block failed (requires Administrator privilege): %s", exc)
            return None, f"FIREWALL_ERROR: {exc}"
        except Exception as exc:
            log.warning("Firewall block failed: %s", exc)
            return None, f"FIREWALL_ERROR: {exc}"

    def unblock(self, source_ip: str, status: str = "ADMIN_UNBLOCKED") -> Quarantine | None:
        try:
            source = str(ipaddress.ip_address(source_ip.strip()))
        except ValueError:
            return None
        block = self.blocks.get(source)
        if not block or block.status != "BLOCKED":
            return None
        if block.rule_name:
            try:
                self.firewall.unblock(block.rule_name)
            except Exception as exc:
                log.warning("Firewall unblock failed for %s: %s", block.rule_name, exc)
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
