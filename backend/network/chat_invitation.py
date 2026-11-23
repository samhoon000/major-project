"""Keep one verified Chat URL while the connector is rechecked in the background."""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import math
import secrets
import time

import httpx

from backend.network.tunnel import tunnel_manager
from backend.security.demo_access import boundary, public_origin

CHAT_INSTANCE_HEADER = "X-Sentinel-Chat-Instance"
FORWARDED_HEADERS = ("cf-connecting-ip", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded")
PROBE_INTERVAL = 10
RETRY_INTERVAL = 5
FAILURE_GRACE = 45
MAX_UNVERIFIED = 90
MIN_FAILED_PROBES = 3


class ChatInvitation:
    def __init__(self, clock=time.monotonic):
        self.instance = secrets.token_hex(16)
        self.clock = clock
        self.candidate = None
        self.verified_url = None
        self.last_verified = 0.0
        self.failed_probes = 0
        self.generation = 0
        self.next_probe_at = 0.0
        self.probe_task = None
        self.lan_seen = (None, 0.0)

    @staticmethod
    def connector_stopped():
        if tunnel_manager.mode == "disabled":
            return False  # A manually attached connector has no managed process.
        process = tunnel_manager.process
        return tunnel_manager.status in {"stopped", "error", "disabled"} or (
            process is not None and process.poll() is not None
        )

    def public_candidate(self):
        origin = public_origin()
        return origin + "/chat" if origin and not self.connector_stopped() else None

    def sync_candidate(self):
        candidate = self.public_candidate()
        if candidate != self.candidate:
            self.candidate = candidate
            self.generation += 1
            self.failed_probes = 0
            self.next_probe_at = 0.0
        if self.connector_stopped():
            self.verified_url = None
        return candidate

    def confirm_public(self, candidate):
        self.verified_url = candidate
        self.last_verified = self.clock()
        self.failed_probes = 0
        self.generation += 1
        self.next_probe_at = self.last_verified + PROBE_INTERVAL

    @staticmethod
    def lan_candidate(request):
        if not request.client or any(request.headers.get(name) for name in FORWARDED_HEADERS):
            return None
        listener = request.scope.get("server")
        if not listener:
            return None
        try:
            peer, address = map(ipaddress.IPv4Address, (request.client.host, listener[0]))
        except ipaddress.AddressValueError:
            return None
        if (peer.is_loopback or address.is_loopback or not peer.is_private or not address.is_private
                or address.is_unspecified or peer.is_unspecified or peer == address):
            return None
        origin = f"http://{address}:{listener[1]}" if listener[1] != 80 else f"http://{address}"
        return origin + "/chat" if boundary(request).origin == origin else None

    def observe_chat_page(self, request):
        context = boundary(request)
        if context.tunnel:
            candidate = self.sync_candidate()
            if candidate == context.origin + "/chat":
                self.confirm_public(candidate)
        else:
            candidate = self.lan_candidate(request)
            if candidate:
                self.lan_seen = candidate, self.clock() + 60

    async def verify_public(self, candidate):
        try:
            async with asyncio.timeout(3), httpx.AsyncClient(trust_env=False, follow_redirects=False) as client:
                async with client.stream("GET", candidate) as response:
                    instance = response.headers.get(CHAT_INSTANCE_HEADER)
                    if response.status_code == 200 and instance == self.instance:
                        return "connected"
                    if response.status_code == 410 or (response.status_code == 200 and instance):
                        return "invalid"
        except (httpx.HTTPError, TimeoutError):
            pass
        return "retry"

    async def check_public(self, candidate, generation):
        result = await self.verify_public(candidate)
        if candidate != self.sync_candidate() or generation != self.generation:
            return
        if result == "connected":
            self.confirm_public(candidate)
            return
        self.failed_probes += 1
        self.next_probe_at = self.clock() + RETRY_INTERVAL
        if result == "invalid" and candidate == self.verified_url:
            self.verified_url = None

    def schedule_probe(self, candidate):
        if candidate and self.clock() >= self.next_probe_at and (self.probe_task is None or self.probe_task.done()):
            self.probe_task = asyncio.create_task(self.check_public(candidate, self.generation))

    async def close(self):
        if self.probe_task and not self.probe_task.done():
            self.probe_task.cancel()
            await asyncio.gather(self.probe_task, return_exceptions=True)

    def snapshot(self, *, allow_lan):
        candidate = self.sync_candidate()
        self.schedule_probe(candidate)
        now = self.clock()
        age = now - self.last_verified
        if self.verified_url and (age >= MAX_UNVERIFIED or (
            candidate == self.verified_url and age >= FAILURE_GRACE and self.failed_probes >= MIN_FAILED_PROBES
        )):
            self.verified_url = None
        public = self.verified_url
        connector_checking = tunnel_manager.mode != "disabled" and tunnel_manager.status != "running"
        connected = bool(public and public == candidate and not self.failed_probes and not connector_checking
                         and age < FAILURE_GRACE)
        lan = self.lan_seen[0] if allow_lan and self.lan_seen[1] > now else None
        active = public or lan
        qr_url = ("/api/tunnel/qr.svg?v=" + hashlib.sha256(active.encode()).hexdigest()[:16]) if active else None
        if public:
            state = "connected" if connected else "reconnecting"
            valid_for = MAX_UNVERIFIED - age
        elif lan:
            state, valid_for = "connected", self.lan_seen[1] - now
        else:
            state, valid_for = "disconnected", 0
        return dict(active_joining_url=active, qr_url=qr_url, is_public_ready=connected,
                    public_url=public.removesuffix("/chat") if connected else None,
                    joining_mode="public_https" if public else "local_lan" if lan else "unavailable",
                    sharing_state=state, share_valid_for=math.ceil(valid_for))


chat_invitation = ChatInvitation()
