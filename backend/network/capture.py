"""Optional Scapy/Npcap capture. Requires operator-authorized interface access."""
from __future__ import annotations

import logging
import os
import threading
from typing import Callable

log = logging.getLogger(__name__)


def parse_scapy_packet(packet) -> dict | None:
    try:
        from scapy.layers.inet import IP, TCP, UDP
        if IP not in packet:
            return None
        ip = packet[IP]
        if TCP in packet:
            transport, protocol = packet[TCP], "TCP"
            flags = str(transport.flags)
        elif UDP in packet:
            transport, protocol, flags = packet[UDP], "UDP", None
        else:
            return None
        return {"timestamp": float(packet.time), "source_ip": ip.src, "destination_ip": ip.dst,
                "source_port": int(transport.sport), "destination_port": int(transport.dport),
                "protocol": protocol, "packet_length": int(len(packet)), "tcp_flags": flags}
    except (AttributeError, TypeError, ValueError, IndexError):
        return None


class PacketCapture:
    def __init__(self, handler: Callable[[dict], None], interface: str | None = None, bpf_filter: str | None = None):
        self.handler = handler
        self.interface = interface or os.getenv("NETWORK_INTERFACE") or os.getenv("CAPTURE_INTERFACE") or None
        self.bpf_filter = bpf_filter if bpf_filter is not None else os.getenv("NETWORK_CAPTURE_FILTER", "ip and (tcp or udp)")
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.error: str | None = None

    @staticmethod
    def interfaces() -> list[str]:
        try:
            from scapy.all import get_if_list
            return list(get_if_list())
        except ImportError as exc:
            raise RuntimeError("Scapy is not installed. Install requirements to enable packet capture.") from exc

    @staticmethod
    def interface_details(devices: list[str]) -> list[str]:
        """Map Scapy NPF device names to the current Windows adapter labels."""
        try:
            from scapy.arch.windows import get_windows_if_list
            adapters = get_windows_if_list()
        except (ImportError, AttributeError, OSError):
            adapters = []
        by_guid = {str(item.get("guid", "")).strip("{}").casefold(): item for item in adapters}
        details = []
        for device in devices:
            guid = device.rsplit("_", 1)[-1].strip("{}").casefold() if device.startswith("\\Device\\NPF_{") else ""
            adapter = by_guid.get(guid)
            if adapter:
                ips = ", ".join(adapter.get("ips", [])) or "no IP assigned"
                details.append(f"{device} | {adapter.get('name')} | {adapter.get('description')} | {ips}")
            else:
                details.append(f"{device} | adapter details unavailable")
        return details

    def _resolve_configured_interface(self, devices: list[str]) -> str | None:
        """Allow friendly Windows adapter names while retaining an exact NPF selection."""
        if not self.interface:
            return None
        if self.interface in devices:
            return self.interface
        try:
            from scapy.arch.windows import get_windows_if_list
            adapters = get_windows_if_list()
        except (ImportError, AttributeError, OSError):
            adapters = []
        requested = self.interface.casefold()
        for adapter in adapters:
            labels = {str(adapter.get("name", "")).casefold(),
                      str(adapter.get("description", "")).casefold(),
                      str(adapter.get("guid", "")).casefold()}
            if requested in labels and adapter.get("guid"):
                candidate = "\\Device\\NPF_" + str(adapter["guid"])
                if candidate in devices:
                    return candidate
                raise RuntimeError(
                    f"Windows adapter '{adapter.get('name')}' exists, but its NPF device is not visible to Scapy. "
                    "Run the server in an elevated terminal and verify the Npcap adapter binding. "
                    f"Scapy currently lists: {', '.join(devices) or '<none>'}."
                )
        return None

    def start(self) -> None:
        try:
            from scapy.all import sniff
            devices = self.interfaces()
            details = self.interface_details(devices)
            log.info("[CAPTURE] Available capture interfaces:\n%s", "\n".join(f"  {i}. {item}" for i, item in enumerate(details, 1)) or "  <none>")
            resolved = self._resolve_configured_interface(devices)
            if self.interface and not resolved:
                raise RuntimeError(
                    f"Configured capture interface '{self.interface}' is not available to Scapy. "
                    f"Available NPF interfaces: {', '.join(devices) or '<none>'}. "
                    "No loopback fallback is selected."
                )
            if resolved:
                self.interface = resolved
                selected = next((item for item in details if item.startswith(resolved + " |")), resolved)
                log.info("[CAPTURE] Selected interface: %s", selected)
            if not self.interface:
                raise RuntimeError(
                    "No capture interface is configured. Set NETWORK_INTERFACE or CAPTURE_INTERFACE to an exact "
                    "Scapy NPF device or Windows adapter name (for example, Wi-Fi). No loopback fallback is selected."
                )
            if self._stop.is_set():
                return
        except Exception as exc:
            self.error = str(exc)
            log.error("[CAPTURE] Unable to start: %s", self.error)
            return
        self._stop.clear()
        def run():
            try:
                sniff(iface=self.interface, filter=self.bpf_filter or None, prn=self._handle, store=False, timeout=1)
            except Exception as exc:
                self.error = str(exc)
                log.exception("[CAPTURE] Capture failed")
        self._thread = threading.Thread(target=self._run_until_stopped, args=(run,), name="scapy-capture", daemon=True)
        self._thread.start()

    def _run_until_stopped(self, sniff_once):
        while not self._stop.is_set():
            sniff_once()

    def _handle(self, packet) -> None:
        parsed = parse_scapy_packet(packet)
        if parsed:
            self.handler(parsed)

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout)
        self._thread = None
