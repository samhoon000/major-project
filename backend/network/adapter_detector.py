r"""Automatic network adapter detection and Npcap interface resolution.

Provides deterministic route-based selection of active Wi-Fi and Ethernet adapters,
resolves corresponding Npcap device identifiers (\Device\NPF_{GUID}), and exposes
detailed selection telemetry for dashboard and SOC visibility.
"""
from __future__ import annotations

import logging
import os
import re
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, List, Optional

log = logging.getLogger(__name__)

# Virtual adapter indicator patterns (case-insensitive)
VIRTUAL_NAME_PATTERNS = [
    r"virtual",
    r"vethernet",
    r"hyper-v",
    r"virtualbox",
    r"vmware",
    r"wsl",
    r"tap-windows",
    r"wireguard",
    r"openvpn",
    r"tailscale",
    r"zerotier",
    r"fortinet",
    r"cisco anyconnect",
    r"pANGP",
    r"direct virtual adapter",
    r"lightweight filter",
    r"qos packet scheduler",
    r"native wifi filter",
    r"packet driver \(npcap\)",
    r"teredo",
    r"6to4",
    r"ip-https",
    r"wan miniport",
]

_VIRTUAL_REGEX = re.compile("|".join(VIRTUAL_NAME_PATTERNS), re.IGNORECASE)


@dataclass
class NetworkAdapter:
    """Represents a discovered network adapter on the host operating system."""
    name: str
    description: str
    guid: str
    npcap_name: str
    adapter_type: str  # "Wi-Fi", "Ethernet", "Loopback", "Virtual", "Other"
    ipv4_addresses: List[str] = field(default_factory=list)
    mac_address: str = ""
    interface_index: Optional[int] = None
    is_connected: bool = False
    is_virtual: bool = False
    is_loopback: bool = False
    ipv4_metric: Optional[int] = None
    raw_data: dict = field(default_factory=dict)

    @property
    def primary_ipv4(self) -> Optional[str]:
        for ip in self.ipv4_addresses:
            if not ip.startswith("127.") and not ip.startswith("169.254.") and ip != "0.0.0.0":
                return ip
        return self.ipv4_addresses[0] if self.ipv4_addresses else None


@dataclass
class AdapterSelectionResult:
    """Result of the deterministic adapter selection process."""
    adapter: Optional[NetworkAdapter]
    interface_id: Optional[str]
    adapter_name: Optional[str]
    adapter_description: Optional[str]
    adapter_type: Optional[str]
    local_ip: Optional[str]
    selection_mode: str  # "explicit_network_interface", "explicit_capture_interface", "automatic_default_route", "fallback", "none"
    selection_reason: str
    is_automatic: bool
    gateway_ip: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "interface_id": self.interface_id,
            "adapter_name": self.adapter_name,
            "adapter_description": self.adapter_description,
            "adapter_type": self.adapter_type,
            "local_ip": self.local_ip,
            "selection_mode": self.selection_mode,
            "selection_reason": self.selection_reason,
            "is_automatic": self.is_automatic,
            "gateway_ip": self.gateway_ip,
            "error": self.error,
        }


def _classify_adapter(name: str, description: str, if_type: int = 0) -> str:
    """Classifies adapter type based on Win32 interface type, name, and description."""
    combined = f"{name} {description}".lower()
    if if_type == 24 or "loopback" in combined:
        return "Loopback"
    if if_type == 71 or any(k in combined for k in ("wi-fi", "wifi", "wireless", "802.11", "wlan")):
        return "Wi-Fi"
    if if_type == 6 or any(k in combined for k in ("ethernet", "gigabit", "i219", "i210", "i211", "realtek", "lan")):
        return "Ethernet"
    if _VIRTUAL_REGEX.search(combined):
        return "Virtual"
    return "Other"


def _is_virtual_adapter(name: str, description: str, if_type: int = 0) -> bool:
    """Detects whether an adapter is virtual, VPN, or a driver filter."""
    if if_type in (24, 131):  # Loopback or Tunnel
        return True
    combined = f"{name} {description}".lower()
    return bool(_VIRTUAL_REGEX.search(combined))


def enumerate_windows_adapters() -> List[NetworkAdapter]:
    """Enumerates Windows network adapters using Scapy's Win32 integration or ipconfig fallback."""
    adapters: List[NetworkAdapter] = []

    # Try Scapy's native Win32 adapter enumeration (GetAdaptersAddresses)
    try:
        import scapy.arch.windows as sw
        raw_list = sw.get_windows_if_list()
        for item in raw_list:
            name = item.get("name", "")
            desc = item.get("description", "")
            guid = item.get("guid", "")
            if_type = item.get("type", 0)
            ips = item.get("ips", [])
            mac = item.get("mac", "")
            idx = item.get("index")
            metric = item.get("ipv4_metric")

            ipv4s = [ip for ip in ips if ":" not in ip]
            adapter_type = _classify_adapter(name, desc, if_type)
            is_virtual = _is_virtual_adapter(name, desc, if_type)
            is_loopback = (adapter_type == "Loopback")

            # Check if adapter has a valid non-APIPA IPv4 address
            has_valid_ipv4 = any(
                not ip.startswith("127.") and not ip.startswith("169.254.") and ip != "0.0.0.0"
                for ip in ipv4s
            )
            is_connected = has_valid_ipv4 and not is_virtual and not is_loopback

            npcap_name = f"\\Device\\NPF_{guid}" if guid and not guid.startswith("\\") else guid

            adapters.append(NetworkAdapter(
                name=name,
                description=desc,
                guid=guid,
                npcap_name=npcap_name,
                adapter_type=adapter_type,
                ipv4_addresses=ipv4s,
                mac_address=mac,
                interface_index=idx,
                is_connected=is_connected,
                is_virtual=is_virtual,
                is_loopback=is_loopback,
                ipv4_metric=metric,
                raw_data=item,
            ))
        if adapters:
            return adapters
    except Exception as exc:
        log.warning("[ADAPTER_DETECTOR] Native Windows adapter enumeration failed: %s", exc)

    # Fallback to ipconfig /all parser if Scapy Win32 enumeration fails
    try:
        adapters = _parse_ipconfig_all()
    except Exception as exc:
        log.error("[ADAPTER_DETECTOR] ipconfig fallback enumeration failed: %s", exc)

    return adapters


def _parse_ipconfig_all() -> List[NetworkAdapter]:
    """Fallback parser using 'ipconfig /all' output."""
    output = subprocess.check_output("ipconfig /all", text=True, stderr=subprocess.DEVNULL)
    adapters: List[NetworkAdapter] = []
    current_name = None
    current_desc = None
    current_ips: List[str] = []
    current_mac = ""
    is_disconnected = False

    def save_current():
        nonlocal current_name, current_desc, current_ips, current_mac, is_disconnected
        if current_name:
            adapter_type = _classify_adapter(current_name, current_desc or "")
            is_virtual = _is_virtual_adapter(current_name, current_desc or "")
            is_connected = bool(current_ips) and not is_disconnected and not is_virtual
            adapters.append(NetworkAdapter(
                name=current_name,
                description=current_desc or current_name,
                guid="",
                npcap_name="",
                adapter_type=adapter_type,
                ipv4_addresses=current_ips,
                mac_address=current_mac,
                is_connected=is_connected,
                is_virtual=is_virtual,
                is_loopback=(adapter_type == "Loopback"),
            ))
        current_name = None
        current_desc = None
        current_ips = []
        current_mac = ""
        is_disconnected = False

    for line in output.splitlines():
        line_s = line.strip()
        if line and not line.startswith(" ") and ":" in line:
            save_current()
            header = line.split(":", 1)[0].strip()
            # e.g. "Ethernet adapter Ethernet" or "Wireless LAN adapter Wi-Fi"
            for prefix in ("Ethernet adapter", "Wireless LAN adapter", "Tunnel adapter"):
                if header.startswith(prefix):
                    header = header[len(prefix):].strip()
            current_name = header
        elif current_name:
            if "Description" in line_s and ":" in line_s:
                current_desc = line_s.split(":", 1)[1].strip()
            elif "Physical Address" in line_s and ":" in line_s:
                current_mac = line_s.split(":", 1)[1].strip().lower().replace("-", ":")
            elif "Media State" in line_s and "disconnected" in line_s.lower():
                is_disconnected = True
            elif "IPv4 Address" in line_s and ":" in line_s:
                ip = line_s.split(":", 1)[1].replace("(Preferred)", "").strip()
                current_ips.append(ip)

    save_current()
    return adapters


def get_default_ipv4_routes() -> List[dict]:
    """Discovers active default IPv4 routes (0.0.0.0/0) on Windows.

    Returns a list of dicts: [{'index': int, 'gateway': str, 'interface_ip': str, 'metric': int}]
    sorted by metric ascending.
    """
    routes: List[dict] = []

    # 1. Primary: Scapy Win32 GetIpForwardTable2 API
    try:
        import scapy.arch.windows as sw
        fwd_table = sw.GetIpForwardTable2()
        for entry in fwd_table:
            dest_prefix = entry.get("DestinationPrefix", {})
            prefix_len = dest_prefix.get("PrefixLength", -1)
            family = dest_prefix.get("Prefix", {}).get("si_family")
            if prefix_len == 0 and family == socket.AF_INET:
                idx = entry.get("InterfaceIndex")
                metric = entry.get("Metric", 0)
                nh = entry.get("NextHop", {}).get("Ipv4", {}).get("sin_addr", {})
                gateway = None
                if isinstance(nh, dict) and "byte" in nh:
                    try:
                        gateway = socket.inet_ntoa(bytes(nh["byte"]))
                    except Exception:
                        pass
                routes.append({
                    "index": idx,
                    "gateway": gateway,
                    "interface_ip": None,
                    "metric": metric,
                    "source": "GetIpForwardTable2",
                })
        if routes:
            routes.sort(key=lambda r: r.get("metric", 99999))
            return routes
    except Exception as exc:
        log.debug("[ADAPTER_DETECTOR] GetIpForwardTable2 query failed: %s", exc)

    # 2. Secondary: Parse 'route print 0.0.0.0'
    try:
        output = subprocess.check_output(
            ["cmd", "/c", "route", "print", "0.0.0.0"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        in_active = False
        for line in output.splitlines():
            line_s = line.strip()
            if "Active Routes:" in line_s:
                in_active = True
                continue
            if in_active and line_s.startswith("0.0.0.0"):
                parts = line_s.split()
                if len(parts) >= 5:
                    dest, mask, gateway, if_ip, metric_s = parts[:5]
                    try:
                        metric = int(metric_s)
                    except ValueError:
                        metric = 9999
                    routes.append({
                        "index": None,
                        "gateway": gateway,
                        "interface_ip": if_ip,
                        "metric": metric,
                        "source": "route_print",
                    })
            elif in_active and line_s.startswith("Persistent Routes:"):
                break
        if routes:
            routes.sort(key=lambda r: r.get("metric", 99999))
            return routes
    except Exception as exc:
        log.debug("[ADAPTER_DETECTOR] route print parsing failed: %s", exc)

    # 3. Tertiary: Route lookup via UDP socket probe (does not send traffic)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        if local_ip and not local_ip.startswith("127."):
            routes.append({
                "index": None,
                "gateway": None,
                "interface_ip": local_ip,
                "metric": 100,
                "source": "socket_probe",
            })
    except Exception as exc:
        log.debug("[ADAPTER_DETECTOR] socket route probe failed: %s", exc)

    routes.sort(key=lambda r: r.get("metric", 99999))
    return routes


def select_network_adapter(
    explicit_network_interface: Optional[str] = None,
    explicit_capture_interface: Optional[str] = None,
    adapters: Optional[List[NetworkAdapter]] = None,
    default_routes: Optional[List[dict]] = None,
) -> AdapterSelectionResult:
    """Deterministically selects the optimal capture adapter following strict priority rules.

    Priority:
    1. Explicit NETWORK_INTERFACE configuration (if provided and non-empty).
    2. Explicit CAPTURE_INTERFACE configuration (if provided and non-empty).
    3. Automatically detected active default-route interface (Ethernet/Wi-Fi).
    4. Clearly reported fallback if automatic detection cannot identify a suitable interface.

    Returns:
        AdapterSelectionResult with chosen adapter, npcap interface ID, mode, and reason.
    """
    if adapters is None:
        adapters = enumerate_windows_adapters()
    if default_routes is None:
        default_routes = get_default_ipv4_routes()

    # Map adapters for fast lookup
    adapter_by_guid = {a.guid.upper(): a for a in adapters if a.guid}
    adapter_by_npcap = {a.npcap_name.upper(): a for a in adapters if a.npcap_name}
    adapter_by_name = {a.name.lower(): a for a in adapters}
    adapter_by_ip = {}
    for a in adapters:
        for ip in a.ipv4_addresses:
            adapter_by_ip[ip] = a

    # -------------------------------------------------------------
    # Priority 1: Explicit NETWORK_INTERFACE configuration
    # -------------------------------------------------------------
    explicit_net = (explicit_network_interface or "").strip()
    if explicit_net:
        matched = _find_matching_adapter(explicit_net, adapter_by_npcap, adapter_by_guid, adapter_by_name, adapter_by_ip)
        if matched:
            npcap_id = matched.npcap_name or explicit_net
            return AdapterSelectionResult(
                adapter=matched,
                interface_id=npcap_id,
                adapter_name=matched.name,
                adapter_description=matched.description,
                adapter_type=matched.adapter_type,
                local_ip=matched.primary_ipv4,
                selection_mode="explicit_network_interface",
                selection_reason=f"Configured via NETWORK_INTERFACE='{explicit_net}' matching '{matched.name}' ({matched.description}).",
                is_automatic=False,
            )
        # Raw interface identifier provided directly
        return AdapterSelectionResult(
            adapter=None,
            interface_id=explicit_net,
            adapter_name=explicit_net,
            adapter_description="Explicitly configured interface identifier",
            adapter_type="Explicit",
            local_ip=None,
            selection_mode="explicit_network_interface",
            selection_reason=f"Explicitly configured via NETWORK_INTERFACE='{explicit_net}' (raw device).",
            is_automatic=False,
        )

    # -------------------------------------------------------------
    # Priority 2: Explicit CAPTURE_INTERFACE configuration
    # -------------------------------------------------------------
    explicit_cap = (explicit_capture_interface or "").strip()
    if explicit_cap:
        matched = _find_matching_adapter(explicit_cap, adapter_by_npcap, adapter_by_guid, adapter_by_name, adapter_by_ip)
        if matched:
            npcap_id = matched.npcap_name or explicit_cap
            return AdapterSelectionResult(
                adapter=matched,
                interface_id=npcap_id,
                adapter_name=matched.name,
                adapter_description=matched.description,
                adapter_type=matched.adapter_type,
                local_ip=matched.primary_ipv4,
                selection_mode="explicit_capture_interface",
                selection_reason=f"Configured via CAPTURE_INTERFACE='{explicit_cap}' matching '{matched.name}' ({matched.description}).",
                is_automatic=False,
            )
        return AdapterSelectionResult(
            adapter=None,
            interface_id=explicit_cap,
            adapter_name=explicit_cap,
            adapter_description="Explicitly configured capture interface identifier",
            adapter_type="Explicit",
            local_ip=None,
            selection_mode="explicit_capture_interface",
            selection_reason=f"Explicitly configured via CAPTURE_INTERFACE='{explicit_cap}' (raw device).",
            is_automatic=False,
        )

    # -------------------------------------------------------------
    # Priority 3: Automatically detected active default-route interface
    # -------------------------------------------------------------
    active_route_candidates = []
    for r in default_routes:
        matched_adapter = None
        idx = r.get("index")
        if idx is not None:
            for a in adapters:
                if a.interface_index == idx:
                    matched_adapter = a
                    break
        if not matched_adapter and r.get("interface_ip"):
            matched_adapter = adapter_by_ip.get(r["interface_ip"])

        if matched_adapter:
            # Must be a connected physical adapter (not loopback, not virtual)
            if matched_adapter.is_connected and not matched_adapter.is_loopback and not matched_adapter.is_virtual:
                active_route_candidates.append((r, matched_adapter))

    if active_route_candidates:
        # Sort candidates deterministically:
        # 1. Route metric ascending (lower is preferred by Windows)
        # 2. Preference: Ethernet over Wi-Fi on equal metric
        # 3. Interface index ascending
        def sort_key(item):
            route, adapter = item
            route_metric = route.get("metric") if route.get("metric") is not None else 9999
            if_metric = adapter.ipv4_metric if adapter.ipv4_metric is not None else 0
            total_metric = route_metric + if_metric
            type_weight = 0 if adapter.adapter_type == "Ethernet" else 1
            idx = adapter.interface_index or 9999
            return (total_metric, type_weight, idx)

        active_route_candidates.sort(key=sort_key)
        best_route, best_adapter = active_route_candidates[0]

        npcap_id = best_adapter.npcap_name or (f"\\Device\\NPF_{best_adapter.guid}" if best_adapter.guid else best_adapter.name)
        gateway_str = f" to gateway {best_route['gateway']}" if best_route.get("gateway") else ""
        metric_str = f" (metric: {best_route.get('metric', 'default')})"
        reason = (
            f"Automatically selected active {best_adapter.adapter_type} adapter '{best_adapter.name}' "
            f"({best_adapter.description}, IP: {best_adapter.primary_ipv4}){gateway_str}{metric_str} "
            f"via default network route."
        )

        return AdapterSelectionResult(
            adapter=best_adapter,
            interface_id=npcap_id,
            adapter_name=best_adapter.name,
            adapter_description=best_adapter.description,
            adapter_type=best_adapter.adapter_type,
            local_ip=best_adapter.primary_ipv4,
            selection_mode="automatic_default_route",
            selection_reason=reason,
            is_automatic=True,
            gateway_ip=best_route.get("gateway"),
        )

    # -------------------------------------------------------------
    # Priority 4: Fallback to any active connected physical adapter
    # -------------------------------------------------------------
    connected_physical = [
        a for a in adapters
        if a.is_connected and not a.is_loopback and not a.is_virtual and a.primary_ipv4
    ]
    if connected_physical:
        # Prefer Ethernet over Wi-Fi
        connected_physical.sort(
            key=lambda a: (0 if a.adapter_type == "Ethernet" else (1 if a.adapter_type == "Wi-Fi" else 2),
                           a.ipv4_metric or 9999,
                           a.interface_index or 9999)
        )
        fallback_adapter = connected_physical[0]
        npcap_id = fallback_adapter.npcap_name or (f"\\Device\\NPF_{fallback_adapter.guid}" if fallback_adapter.guid else fallback_adapter.name)
        reason = (
            f"No active default route found. Fallback selected active {fallback_adapter.adapter_type} "
            f"adapter '{fallback_adapter.name}' ({fallback_adapter.description}, IP: {fallback_adapter.primary_ipv4})."
        )
        return AdapterSelectionResult(
            adapter=fallback_adapter,
            interface_id=npcap_id,
            adapter_name=fallback_adapter.name,
            adapter_description=fallback_adapter.description,
            adapter_type=fallback_adapter.adapter_type,
            local_ip=fallback_adapter.primary_ipv4,
            selection_mode="fallback",
            selection_reason=reason,
            is_automatic=True,
        )

    # -------------------------------------------------------------
    # Priority 5: No suitable physical adapter detected
    # -------------------------------------------------------------
    return AdapterSelectionResult(
        adapter=None,
        interface_id=None,
        adapter_name=None,
        adapter_description=None,
        adapter_type=None,
        local_ip=None,
        selection_mode="none",
        selection_reason="No active physical Wi-Fi or Ethernet adapter with a valid IPv4 address was found.",
        is_automatic=True,
        error="No active physical network adapter detected. Connect to Wi-Fi or Ethernet.",
    )


def _find_matching_adapter(
    target: str,
    by_npcap: dict,
    by_guid: dict,
    by_name: dict,
    by_ip: dict,
) -> Optional[NetworkAdapter]:
    """Finds an adapter matching by npcap device name, GUID, name, or IP."""
    target_clean = target.strip()
    target_upper = target_clean.upper()
    target_lower = target_clean.lower()

    if target_upper in by_npcap:
        return by_npcap[target_upper]
    if target_upper in by_guid:
        return by_guid[target_upper]
    # Check if target is enclosed in curlies or without
    if f"{{{target_upper.strip('{}')}}}" in by_guid:
        return by_guid[f"{{{target_upper.strip('{}')}}}"]
    if target_lower in by_name:
        return by_name[target_lower]
    if target_clean in by_ip:
        return by_ip[target_clean]
    return None


def register_scapy_npcap_interface(selection: AdapterSelectionResult) -> bool:
    """Registers the resolved Npcap interface into Scapy's conf.ifaces if missing.

    Ensures Scapy's sniff(iface=...) can locate Windows NPF devices without throwing
    ValueError('Interface ... not found !').
    """
    if not selection.interface_id:
        return False

    try:
        from scapy.all import conf
        import scapy.arch.windows as sw

        npcap_id = selection.interface_id
        if npcap_id in conf.ifaces:
            return True

        if hasattr(sw, "NetworkInterface_Win") and hasattr(sw, "WindowsInterfacesProvider"):
            adapter = selection.adapter
            guid = adapter.guid if adapter else (npcap_id.split(r"\Device\NPF_")[-1] if r"\Device\NPF_" in npcap_id else "")
            name = adapter.name if adapter else npcap_id
            desc = adapter.description if adapter else "Configured Network Interface"
            ips = adapter.ipv4_addresses if adapter else []
            mac = (adapter.mac_address if adapter else "") or "00:00:00:00:00:00"
            idx = (adapter.interface_index if adapter else 0) or 0
            metric = (adapter.ipv4_metric if adapter else 0) or 0

            adapter_data = {
                "name": name,
                "description": desc,
                "guid": guid,
                "network_name": npcap_id,
                "ips": ips,
                "mac": mac,
                "index": idx,
                "ipv4_metric": metric,
                "ipv6_metric": 0,
                "flags": 0,
                "nameservers": [],
            }
            dev = sw.NetworkInterface_Win(sw.WindowsInterfacesProvider(), adapter_data)
            conf.ifaces[npcap_id] = dev
            log.info("[ADAPTER_DETECTOR] Registered Npcap interface '%s' into Scapy conf.ifaces.", npcap_id)
            return True
    except Exception as exc:
        log.warning("[ADAPTER_DETECTOR] Failed to register Scapy interface '%s': %s", selection.interface_id, exc)
    return False
