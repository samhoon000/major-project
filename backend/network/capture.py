"""Scapy/Npcap packet capture with automatic network adapter resolution."""
from __future__ import annotations

import logging
import os
import threading
from typing import Callable, Optional

from backend.network.adapter_detector import (
    AdapterSelectionResult,
    register_scapy_npcap_interface,
    select_network_adapter,
)

log = logging.getLogger(__name__)


def is_npcap_available() -> bool:
    """Checks whether the Npcap packet capture driver is installed."""
    for path in (r"C:\Windows\System32\Npcap\wpcap.dll", r"C:\Windows\System32\wpcap.dll"):
        if os.path.exists(path):
            return True
    try:
        import ctypes
        ctypes.cdll.LoadLibrary("wpcap.dll")
        return True
    except Exception:
        return False


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
        return {
            "timestamp": float(packet.time),
            "source_ip": ip.src,
            "destination_ip": ip.dst,
            "source_port": int(transport.sport),
            "destination_port": int(transport.dport),
            "protocol": protocol,
            "packet_length": int(len(ip)),
            "tcp_flags": flags,
        }
    except (AttributeError, TypeError, ValueError, IndexError):
        return None


class PacketCapture:
    """Manages live packet capture with automatic Windows adapter resolution and Npcap binding."""

    def __init__(
        self,
        handler: Callable[[dict], None],
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
    ):
        self.handler = handler
        self.bpf_filter = (
            bpf_filter
            if bpf_filter is not None
            else os.getenv("NETWORK_CAPTURE_FILTER", "ip and (tcp or udp)")
        )
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lifecycle_lock = threading.RLock()
        self.error: Optional[str] = None
        self.status: str = "starting"

        # Telemetry fields for dashboard visibility
        self.interface: Optional[str] = None
        self.adapter_name: Optional[str] = None
        self.adapter_description: Optional[str] = None
        self.adapter_type: Optional[str] = None
        self.local_ip: Optional[str] = None
        self.selection_mode: str = "none"
        self.selection_reason: str = ""
        self.is_automatic: bool = False
        self.selection_result: Optional[AdapterSelectionResult] = None

        self._resolve_adapter(interface)

    def _resolve_adapter(self, explicit_interface: Optional[str] = None) -> None:
        """Resolves adapter using explicit configuration or automatic route discovery."""
        explicit_net = explicit_interface or os.getenv("NETWORK_INTERFACE") or None
        explicit_cap = os.getenv("CAPTURE_INTERFACE") or None

        selection = select_network_adapter(
            explicit_network_interface=explicit_net,
            explicit_capture_interface=explicit_cap,
        )
        self.selection_result = selection
        self.interface = selection.interface_id
        self.adapter_name = selection.adapter_name
        self.adapter_description = selection.adapter_description
        self.adapter_type = selection.adapter_type
        self.local_ip = selection.local_ip
        self.selection_mode = selection.selection_mode
        self.selection_reason = selection.selection_reason
        self.is_automatic = selection.is_automatic

        if selection.error:
            self.error = selection.error
            self.status = "unavailable"
        else:
            log.info("[CAPTURE] %s", selection.selection_reason)
            # Register in Scapy if needed
            register_scapy_npcap_interface(selection)

    @staticmethod
    def interfaces() -> list[str]:
        try:
            from scapy.all import get_if_list
            return list(get_if_list())
        except ImportError as exc:
            raise RuntimeError("Scapy is not installed. Install requirements to enable packet capture.") from exc

    def start(self) -> bool:
        """Starts live packet capture in a background worker thread.
        
        Protected by self._lifecycle_lock against concurrent start/stop races.
        Refuses to start if a previous worker is still active and refuses termination.
        Returns True if started (or already running), False otherwise.
        """
        with self._lifecycle_lock:
            # If a healthy worker is already actively running, return True immediately
            if self._thread and self._thread.is_alive():
                if not self._stop.is_set() and self.status == "running":
                    log.debug("[CAPTURE] Capture worker already actively running.")
                    return True
                # Worker is either stopping or unconfirmed; attempt clean shutdown first
                log.warning("[CAPTURE] Previous capture worker still active; attempting graceful shutdown before restart.")
                stopped = self.stop()
                if not stopped or (self._thread and self._thread.is_alive()):
                    self.error = (
                        "Cannot start capture: previous capture worker thread is still active and failed to terminate."
                    )
                    self.status = "unavailable"
                    log.error("[CAPTURE] %s", self.error)
                    return False

            # Check Npcap prerequisite
            if not is_npcap_available():
                self.error = "Npcap packet capture driver is not installed. Live packet capture requires Npcap (https://npcap.com)."
                self.status = "unavailable"
                log.warning("[CAPTURE] %s", self.error)
                return False

            # Ensure an interface is selected
            if not self.interface:
                self.error = self.error or "No valid physical capture interface selected."
                self.status = "unavailable"
                log.error("[CAPTURE] Unable to start: %s", self.error)
                return False

            # Register interface with Scapy in case not registered yet
            if self.selection_result:
                register_scapy_npcap_interface(self.selection_result)

            self._stop.clear()

            def run():
                first_run = True
                while not self._stop.is_set():
                    try:
                        from scapy.all import sniff
                        sniff(
                            iface=self.interface,
                            filter=self.bpf_filter or None,
                            prn=self._handle,
                            store=False,
                            timeout=1,
                        )
                        if first_run:
                            self.status = "running"
                            self.error = None
                            first_run = False
                    except OSError as exc:
                        err_msg = str(exc)
                        if any(p in err_msg.lower() for p in ("permission", "admin-only", "access is denied")):
                            self.error = (
                                f"Npcap capture permission denied on '{self.adapter_name or self.interface}': "
                                "Run terminal as Administrator or configure Npcap without Admin-only restriction."
                            )
                        else:
                            self.error = f"Npcap capture error on '{self.adapter_name or self.interface}': {err_msg}"
                        self.status = "unavailable"
                        log.error("[CAPTURE] %s", self.error)
                        break
                    except Exception as exc:
                        self.error = f"Packet capture failed on '{self.adapter_name or self.interface}': {exc}"
                        self.status = "unavailable"
                        log.exception("[CAPTURE] Capture exception")
                        break

            self._thread = threading.Thread(target=run, name="scapy-capture", daemon=True)
            self._thread.start()
            return True

    def _handle(self, packet) -> None:
        parsed = parse_scapy_packet(packet)
        if parsed:
            self.handler(parsed)

    def reconfigure(self, interface: Optional[str] = None) -> bool:
        """Gracefully reconfigures adapter selection and restarts capture without leaking threads.
        
        Protected by self._lifecycle_lock. Re-entrant lock avoids self-deadlock when calling stop() and start().
        Returns True if reconfigured and restarted, False if previous worker could not be stopped.
        """
        with self._lifecycle_lock:
            if self._thread and self._thread.is_alive():
                stopped = self.stop()
                if not stopped or (self._thread and self._thread.is_alive()):
                    self.error = "Cannot reconfigure adapter: previous capture worker thread failed to terminate."
                    self.status = "unavailable"
                    log.error("[CAPTURE] %s", self.error)
                    return False

            self.error = None
            self.status = "starting"
            self._resolve_adapter(interface)
            return self.start()

    def stop(self, timeout: float = 3.0) -> bool:
        """Signals the capture worker to stop and waits for it to terminate.
        
        Protected by self._lifecycle_lock.
        Returns True if the worker is confirmed terminated (or was not running),
        False if shutdown timed out and the worker remains alive.
        """
        with self._lifecycle_lock:
            self._stop.set()
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout)
                if self._thread.is_alive():
                    self.error = (
                        f"Capture worker thread '{self._thread.name}' failed to terminate "
                        f"within {timeout}s timeout; retaining thread reference and refusing restart."
                    )
                    self.status = "unavailable"
                    log.error("[CAPTURE] %s", self.error)
                    return False

            # Only clear thread reference after confirming the worker has terminated
            self._thread = None
            if self.status != "unavailable":
                self.status = "stopped"
            return True
