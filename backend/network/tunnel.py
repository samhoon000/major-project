"""Cloudflare Named Tunnel management and automatic LAN/Public URL resolution.

Supports named Cloudflare Tunnels via cloudflared, automatic detection of the local LAN URL,
verification of active tunnel connectivity, and exposure of joining endpoints for
local and remote chat attendees.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from typing import Optional

from backend.config import (
    PORT,
    CLOUDFLARE_TUNNEL_TOKEN,
    CLOUDFLARE_PUBLIC_HOSTNAME,
    CLOUDFLARE_PATH,
)
from backend.network.adapter_detector import select_network_adapter

log = logging.getLogger(__name__)


def get_lan_ipv4() -> str:
    """Discovers the active host IPv4 address using adapter detector or socket routing."""
    try:
        selection = select_network_adapter()
        if selection and selection.local_ip:
            return selection.local_ip
    except Exception as exc:
        log.debug("[TUNNEL] Adapter detection for LAN IP failed: %s", exc)

    # Secondary fallback: non-connecting UDP socket probe
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass

    # Tertiary fallback
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


class TunnelManager:
    """Manages the background cloudflared named tunnel process and tracks public reachability."""

    def __init__(
        self,
        token: Optional[str] = None,
        public_hostname: Optional[str] = None,
        local_port: Optional[int] = None,
        cloudflared_path: Optional[str] = None,
        mode: Optional[str] = None,
    ):
        self._lock = threading.RLock()
        self.token = (
            token
            if token is not None
            else (CLOUDFLARE_TUNNEL_TOKEN or os.getenv("CLOUDFLARE_TUNNEL_TOKEN", "")).strip()
        ) or None
        self.mode = mode or ("named" if self.token else os.getenv("CLOUDFLARE_TUNNEL_MODE", "disabled").lower())
        if self.mode not in ("named", "quick", "disabled"):
            raise ValueError("CLOUDFLARE_TUNNEL_MODE must be named, quick or disabled")

        raw_hostname = (
            public_hostname
            if public_hostname is not None
            else (CLOUDFLARE_PUBLIC_HOSTNAME or os.getenv("CLOUDFLARE_PUBLIC_HOSTNAME", "")).strip()
        )
        self.public_hostname = self._clean_hostname(raw_hostname)
        if self.mode == "quick":
            self.public_hostname = None  # Assigned only by this process's startup banner.

        self.local_port = int(
            local_port
            if local_port is not None
            else (int(os.getenv("PORT", str(PORT))))
        )
        self.cloudflared_path = (
            cloudflared_path
            if cloudflared_path is not None
            else (CLOUDFLARE_PATH or os.getenv("CLOUDFLARE_PATH", "cloudflared")).strip()
        )

        self.status = "starting" if self.token or self.mode == "quick" else "disabled"
        self.error: Optional[str] = None
        self.process: Optional[subprocess.Popen] = None
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._connected_event = threading.Event()
        self._recent_logs: list[str] = []
        self._active_connections: set[str] = set()
        self._local_ip_cache: Optional[str] = None
        self._local_ip_checked = 0.0
        self._local_ip_refresh_lock = threading.Lock()

        if not self.token and self.mode != "quick":
            self.status = "disabled"
            self.error = "Cloudflare Tunnel token is not configured in .env. Local LAN access is fully active."

    @staticmethod
    def _clean_hostname(raw: str) -> Optional[str]:
        if not raw:
            return None
        cleaned = raw.strip()
        for prefix in ("https://", "http://"):
            if cleaned.lower().startswith(prefix):
                cleaned = cleaned[len(prefix):]
        cleaned = cleaned.rstrip("/").strip()
        return cleaned if cleaned else None

    @property
    def local_ip(self) -> str:
        if os.getenv("SENTINEL_LOOPBACK_ONLY") == "true":
            return "127.0.0.1"
        now = time.monotonic()
        if self._local_ip_cache and now - self._local_ip_checked < 10:
            return self._local_ip_cache
        # Only one caller performs native discovery. Other status/QR readers
        # keep using the last known address instead of tying up worker threads.
        if not self._local_ip_refresh_lock.acquire(blocking=False):
            return self._local_ip_cache or "127.0.0.1"
        try:
            self._local_ip_cache = get_lan_ipv4()
            self._local_ip_checked = time.monotonic()
            return self._local_ip_cache
        finally:
            self._local_ip_refresh_lock.release()

    @property
    def local_url(self) -> str:
        return f"http://{self.local_ip}:{self.local_port}"

    @property
    def public_url(self) -> Optional[str]:
        if self.public_hostname and self.status == "running":
            return f"https://{self.public_hostname}"
        return None

    @property
    def is_public_ready(self) -> bool:
        return bool(self.status == "running" and self.public_url)

    @property
    def edge_connected(self) -> bool:
        return bool(self.status == "running" and self._connected_event.is_set())

    @property
    def public_hostname_verified(self) -> bool:
        """Returns False because edge daemon registration alone does not prove end-to-end public HTTP/DNS reachability."""
        return False

    @property
    def readiness_note(self) -> str:
        if self.status == "running" and self.public_hostname:
            if self.mode == "quick":
                return "Quick Tunnel edge registered. Temporary public URL assigned; public HTTPS/WSS reachability requires independent verification."
            return (
                "Cloudflare Edge tunnel registered. Public hostname reachability is unverified "
                "(requires DNS and ingress routing configured in Cloudflare Zero Trust dashboard)."
            )
        if self.status == "disabled":
            return "Cloudflare Tunnel token is not configured in .env. Local LAN access is fully active."
        if self.status == "error":
            return self.error or "Cloudflare Tunnel error."
        return f"Tunnel status: {self.status}."

    @property
    def active_joining_url(self) -> str:
        base = self.public_url if (self.is_public_ready and self.public_url) else self.local_url
        return f"{base}/chat"

    @property
    def joining_mode(self) -> str:
        return "public_https" if self.is_public_ready else "local_lan"

    def find_cloudflared_executable(self) -> Optional[str]:
        """Locates the cloudflared executable in PATH or standard Windows installation paths."""
        # 1. Direct path or PATH lookup
        found = shutil.which(self.cloudflared_path)
        if found:
            return found

        # 2. Common Windows paths
        candidates = [
            r"C:\Program Files\cloudflared\cloudflared.exe",
            r"C:\Program Files (x86)\cloudflared\cloudflared.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\cloudflared\cloudflared.exe"),
            os.path.expandvars(r"%USERPROFILE%\cloudflared.exe"),
            os.path.join(os.getcwd(), "cloudflared.exe"),
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return None

    def start(self) -> bool:
        """Starts cloudflared in a background process using the configured named tunnel token."""
        with self._lock:
            if self.mode == "disabled" or (not self.token and self.mode != "quick"):
                self.status = "disabled"
                self.error = "Cloudflare Tunnel token is not configured in .env. Local LAN access is fully active."
                log.info("[TUNNEL] %s", self.error)
                return False

            if self.process and self.process.poll() is None:
                log.debug("[TUNNEL] cloudflared process is already running (PID: %d).", self.process.pid)
                return True

            executable = self.find_cloudflared_executable()
            if not executable:
                self.status = "error"
                self.error = (
                    "cloudflared executable was not found. Install cloudflared from "
                    "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/ "
                    "to enable public attendance."
                )
                log.warning("[TUNNEL] %s", self.error)
                return False

            self._stop_event.clear()
            self._connected_event.clear()
            self.status = "starting"
            self.error = None
            self._recent_logs = []
            self._active_connections.clear()
            if self.mode == "quick":
                self.public_hostname = None

            # Use cloudflared's supported environment variable so credentials
            # never appear in command-line process listings or command logs.
            cmd = ([executable, "tunnel", "--url", f"http://127.0.0.1:{self.local_port}", "--no-autoupdate"]
                   if self.mode == "quick" else [executable, "tunnel", "run"])
            child_env = {key:value for key,value in os.environ.items()
                         if key not in ("ADMIN_TOKEN", "CLOUDFLARE_TUNNEL_TOKEN", "TUNNEL_TOKEN", "TUNNEL_TOKEN_FILE")}
            if self.mode == "named":
                child_env["TUNNEL_TOKEN"] = self.token
            try:
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    env=child_env,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                log.info("[TUNNEL] cloudflared launched with PID %d", self.process.pid)
            except Exception as exc:
                self.status = "error"
                self.error = f"Failed to launch cloudflared: {exc}"
                log.error("[TUNNEL] %s", self.error)
                return False

            self._monitor_thread = threading.Thread(
                target=self._monitor_output,
                name="cloudflared-monitor",
                daemon=True,
            )
            self._monitor_thread.start()
            return True

    def _monitor_output(self) -> None:
        """Reads cloudflared logs to confirm connection to Cloudflare Edge or capture errors."""
        connection_pattern = re.compile(
            r"\bRegistered tunnel connection\b|Connection .* registered|INF Registered tunnel connection",
            re.IGNORECASE,
        )
        error_pattern = re.compile(
            r"ERR|fatal|Cannot determine default configuration|Unauthorized|invalid tunnel",
            re.IGNORECASE,
        )

        try:
            for line in iter(self.process.stdout.readline, ""):
                line_s = line.strip()
                if self.token:
                    line_s = line_s.replace(self.token, "[redacted]")
                if not line_s:
                    continue

                with self._lock:
                    self._recent_logs.append(line_s)
                    if len(self._recent_logs) > 50:
                        self._recent_logs.pop(0)
                    if self.mode == "quick" and not self.public_hostname:
                        public = re.search(r"https://([a-z0-9-]+\.trycloudflare\.com)\b", line_s, re.IGNORECASE)
                        if public:
                            self.public_hostname = public.group(1).lower()
                            log.info("[TUNNEL] Quick Tunnel URL: https://%s", self.public_hostname)

                # Check for successful Edge connection
                if connection_pattern.search(line_s):
                    with self._lock:
                        index = re.search(r"connIndex=(\d+)", line_s)
                        self._active_connections.add(index.group(1) if index else "unknown")
                        self.status = "running"
                        self.error = None
                        self._connected_event.set()
                    log.info("[TUNNEL] cloudflared successfully connected to Cloudflare Edge!")

                # cloudflared reconnects its own edge connections. A single
                # disconnected edge doesn't imply all other connections failed.
                elif re.search(r"connection terminated|lost connection|failed to serve.*connection|unregistered tunnel connection", line_s, re.IGNORECASE):
                    with self._lock:
                        index = re.search(r"connIndex=(\d+)", line_s)
                        if index:
                            self._active_connections.discard(index.group(1))
                        else:
                            self._active_connections.clear()
                        if not self._active_connections:
                            self.status = "reconnecting"
                            self._connected_event.clear()
                            self.error = "Cloudflare edge connection interrupted; cloudflared is reconnecting."

                # Check for critical errors
                elif error_pattern.search(line_s) and self.status != "running":
                    with self._lock:
                        if not self._connected_event.is_set():
                            self.error = f"Cloudflare Tunnel error: {line_s}"

                if self._stop_event.is_set():
                    break
        except Exception as exc:
            log.debug("[TUNNEL] Monitor stream closed: %s", exc)
        finally:
            with self._lock:
                if self.process:
                    code = self.process.poll()
                    if code is not None and not self._stop_event.is_set():
                        self.status = "error"
                        last_err = self._recent_logs[-1] if self._recent_logs else f"exited with code {code}"
                        self.error = f"cloudflared exited unexpectedly ({last_err})"
                        log.error("[TUNNEL] %s", self.error)

    def stop(self, timeout: float = 4.0) -> bool:
        """Stops the cloudflared process gracefully."""
        with self._lock:
            self._stop_event.set()
            if not self.process:
                if self.status != "disabled":
                    self.status = "stopped"
                return True

            log.info("[TUNNEL] Stopping cloudflared process (PID %d)...", self.process.pid)
            try:
                self.process.terminate()
                self.process.wait(timeout=timeout)
            except (subprocess.TimeoutExpired, Exception):
                log.warning("[TUNNEL] cloudflared did not stop within %ss; killing forcefully.", timeout)
                try:
                    self.process.kill()
                    self.process.wait(timeout=1.0)
                except Exception:
                    pass

            self.process = None
            self._active_connections.clear()
            self._connected_event.clear()
            if self.status != "disabled":
                self.status = "stopped"
            return True

    def status_dict(self) -> dict:
        """Returns the public and local URL state without exposing the secret tunnel token."""
        # Never hold the tunnel lifecycle lock across Windows adapter discovery.
        local_ip = self.local_ip
        local_url = f"http://{local_ip}:{self.local_port}"
        with self._lock:
            # Check process liveness if marked as running
            if self.process and self.process.poll() is not None and self.status == "running":
                self.status = "error"
                code = self.process.poll()
                self.error = f"cloudflared process terminated (exit code: {code})"

            return {
                "enabled": bool(self.token) or self.mode == "quick",
                "mode": self.mode,
                "status": self.status,
                "edge_connected": self.edge_connected,
                "public_hostname": self.public_hostname,
                "public_hostname_verified": self.public_hostname_verified,
                "public_url": self.public_url,
                "configured_public_url": f"https://{self.public_hostname}" if self.public_hostname else None,
                "attack_lab_url": f"{self.public_url or local_url}/attack-lab",
                "dashboard_url": f"{self.public_url or local_url}/dashboard",
                "dashboard_websocket_url": f"{self.public_url.replace('https://', 'wss://') if self.public_url else local_url.replace('http://', 'ws://')}/ws/dashboard",
                "local_ip": local_ip,
                "local_url": local_url,
                "active_joining_url": f"{self.public_url or local_url}/chat",
                "joining_mode": self.joining_mode,
                "is_public_ready": self.is_public_ready,
                "readiness_note": self.readiness_note,
                "error": self.error,
            }


tunnel_manager = TunnelManager()

