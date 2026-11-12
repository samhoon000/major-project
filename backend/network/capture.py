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
                "protocol": protocol, "packet_length": int(len(ip)), "tcp_flags": flags}
    except (AttributeError, TypeError, ValueError, IndexError):
        return None


class PacketCapture:
    def __init__(self, handler: Callable[[dict], None], interface: str | None = None, bpf_filter: str | None = None):
        self.handler, self.interface = handler, interface or os.getenv("NETWORK_INTERFACE") or None
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

    def start(self) -> None:
        try:
            from scapy.all import sniff
            devices = self.interfaces()
            if self.interface and self.interface not in devices:
                raise RuntimeError(f"NETWORK_INTERFACE '{self.interface}' not found. Available interfaces: {', '.join(devices)}")
            if not self.interface:
                log.info("[CAPTURE] Available interfaces: %s. Set NETWORK_INTERFACE to choose one.", ", ".join(devices))
                raise RuntimeError("NETWORK_INTERFACE is not configured; select an interface from the logged list.")
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
