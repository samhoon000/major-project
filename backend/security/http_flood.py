"""Bounded loopback HTTP lab. Detection observes traffic, never generator commands."""
from __future__ import annotations
import asyncio
import ipaddress
import logging
import math
import os
import secrets
import time
from collections import deque
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field
from starlette.requests import Request
from starlette.responses import JSONResponse

log = logging.getLogger(__name__)
TARGET = "/api/attack-lab/http-flood-target"
HEADER = "x-sentinel-lab-key"
METHOD = "Rule-Based HTTP Flood Detection"


class RunConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rate: int = Field(default=25, ge=1, le=50, strict=True)
    duration: float = Field(default=8, ge=1, le=20, allow_inf_nan=False)
    concurrency: int = Field(default=4, ge=1, le=8, strict=True)


@dataclass(frozen=True)
class DetectorConfig:
    window: float = 2.0
    warning_rps: float = 5.0
    block_rps: float = 12.0
    block_seconds: float = 10.0

    def __post_init__(self):
        if not all(math.isfinite(x) for x in (self.window, self.warning_rps, self.block_rps, self.block_seconds)):
            raise ValueError("Detector settings must be finite")
        if not (1 <= self.window <= 10 and 0 < self.warning_rps < self.block_rps <= 50
                and 1 <= self.block_seconds <= 60):
            raise ValueError("Invalid HTTP lab detector thresholds/window/block duration")

    @classmethod
    def from_environment(cls):
        return cls(*(float(os.getenv(key, default)) for key, default in (
            ("HTTP_FLOOD_WINDOW_SECONDS", "2"), ("HTTP_FLOOD_WARNING_RPS", "5"),
            ("HTTP_FLOOD_BLOCK_RPS", "12"), ("HTTP_FLOOD_BLOCK_SECONDS", "10"))))


def validate_base_url(value: str) -> str:
    """Numeric loopback only: no DNS, proxies, redirects or user-provided targets."""
    parsed = urlsplit(value)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError as exc:
        raise ValueError("HTTP lab target must be a numeric loopback HTTP origin") from exc
    if (parsed.scheme != "http" or not address.is_loopback or not port
            or parsed.username or parsed.password or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment):
        raise ValueError("HTTP lab target must be a numeric loopback HTTP origin with an explicit port")
    return value.rstrip("/")


class HTTPFloodSimulator:
    """One bounded run, normal-traffic monitor, and bounded rolling telemetry."""
    def __init__(self, detector: DetectorConfig | None = None, clock=time.monotonic, wall_clock=time.time):
        self.detector = detector or DetectorConfig.from_environment()
        self.clock, self.wall_clock = clock, wall_clock
        self.lock = asyncio.Lock()
        self.task = self.monitor_task = self.publisher_task = None
        self._closed = False
        self._clear()

    def _clear(self):
        self.run_id = secrets.token_hex(8)
        self.keys = {role: secrets.token_urlsafe(32) for role in ("flood", "legitimate")}
        self.config = RunConfig()
        self.base_url = self.started = self.ended = self.detected_at = None
        self.detection_rps = self.block_until = self.baseline_rps = 0.0
        self.warned = self.recovered = False
        self.status, self.error, self.sequence = "ready", None, 0
        self.timeline, self.pending_events = deque(maxlen=200), deque(maxlen=500)
        self.recent_rejections, self._published_rejected = deque(maxlen=200), 0
        self.samples, self.traffic = deque(maxlen=120), deque(maxlen=4096)
        self.source_windows = {role: deque(maxlen=1000) for role in self.keys}
        self.counts = {role: dict(generated=0, successful=0, blocked=0, failed=0,
                                 received=0, accepted=0, rejected=0, in_flight=0, latency_ms=None)
                       for role in self.keys}
        self.endpoints = set()
        self.peak_rate = 0

    def _event(self, kind, message, **data):
        self.sequence += 1
        event = dict(type=kind, timestamp=self.wall_clock(), sequence=self.sequence,
                     run_id=self.run_id, message=message, source_identity="lab-flood",
                     target=TARGET, detection_method=METHOD, **data)
        if kind == "HTTP_REQUEST_BLOCKED":
            self.recent_rejections.append(event)
        else:
            self.timeline.append(event)
        self.pending_events.append(event)

    def role_for_key(self, key):
        for role, capability in self.keys.items():
            if secrets.compare_digest(key.encode(), capability.encode()):
                return role
        return None

    def _expire(self):
        now = self.clock()
        for window in self.source_windows.values():
            while window and now - window[0] >= self.detector.window:
                window.popleft()
        while self.traffic and now - self.traffic[0][0] > 60:
            self.traffic.popleft()
        if self.block_until and now >= self.block_until:
            self.block_until = 0
            if self.ended is None and self.started is not None:
                self.status = "attack_running"
            self.source_windows["flood"].clear()
            self.warned = False
            self._event("HTTP_SOURCE_UNBLOCKED", "Temporary application block expired", reason="expiry")
        if self.ended is not None and not self.block_until and not self.recovered:
            self.recovered = True
            self.status = "recovered" if not self.error else "error"
            self._event("HTTP_FLOOD_RECOVERED", "Generator stopped and no application block remains")

    def observe(self, role):
        """Called only after a real authenticated target request arrives."""
        self._expire()
        now = self.clock()
        counts = self.counts[role]
        counts["received"] += 1
        window = self.source_windows[role]
        window.append(now)
        rps = len(window) / self.detector.window
        blocked = role == "flood" and self.block_until > now
        if not blocked and rps >= self.detector.warning_rps and role == "flood" and not self.warned:
            self.warned = True
            self._event("HTTP_RATE_WARNING", "Rolling request rate exceeded warning threshold",
                        observed_rps=rps, warning_rps=self.detector.warning_rps,
                        baseline_rps=self.baseline_rps, spike_ratio=round(rps / max(1, self.baseline_rps), 2))
        if not blocked and rps >= self.detector.block_rps and role == "flood":
            self.detected_at = self.wall_clock()
            self.detection_rps = rps
            self.block_until = now + self.detector.block_seconds
            self.status, self.recovered = "mitigation_active", False
            self._event("HTTP_FLOOD_ATTACK_DETECTED", "HTTP FLOOD ATTACK DETECTED",
                        observed_rps=rps, severity="HIGH", detected_at=self.detected_at)
            self._event("HTTP_MITIGATION_ACTIVATED", "THREAT MITIGATED — SOURCE BLOCKED",
                        block_seconds=self.detector.block_seconds, mitigation="Application-level HTTP 429")
            blocked = True
        counts["rejected" if blocked else "accepted"] += 1
        self.traffic.append((now, role, blocked))
        if blocked:
            self._event("HTTP_REQUEST_BLOCKED", "Offending lab request rejected with HTTP 429",
                        rejected_requests=counts["rejected"], status_code=429)
        return blocked

    def _rates(self):
        recent = [x for x in self.traffic if self.clock() - x[0] < 1]
        return dict(total_rps=len(recent), accepted_rps=sum(not x[2] for x in recent),
                    blocked_rps=sum(x[2] for x in recent), legitimate_rps=sum(x[1] == "legitimate" for x in recent))

    def _network_evidence(self):
        """Only exact socket endpoints and this run's time interval may associate a flow."""
        evidence = []
        try:
            from backend.network.runtime import network_runtime
            for flow in list(network_runtime.completed_flows):
                forward = (flow.get("source_ip"), flow.get("source_port"),
                           flow.get("destination_ip"), flow.get("destination_port"))
                reverse = (forward[2], forward[3], forward[0], forward[1])
                if (forward not in self.endpoints and reverse not in self.endpoints
                        or flow.get("protocol") != "TCP" or self.started is None
                        or flow.get("start_time", 0) < self.started
                        or self.ended is not None and flow.get("start_time", 0) > self.ended
                        or flow.get("gatv2_status") != "analyzed"):
                    continue
                evidence.append({k: flow.get(k) for k in ("flow_id", "source_ip", "source_port",
                    "destination_ip", "destination_port", "gatv2_prediction", "gatv2_anomaly_probability", "gatv2_confidence",
                    "graph_nodes", "graph_edges")})
        except ImportError:
            pass
        return evidence[-20:]

    def get_state(self):
        self._expire()
        rates = self._rates()
        evidence = self._network_evidence()
        legitimate = dict(self.counts["legitimate"])
        completed = legitimate["generated"] - legitimate["in_flight"]
        legitimate["success_rate"] = round(legitimate["successful"]/completed,4) if completed else None
        return dict(run_id=self.run_id, sequence=self.sequence, snapshot_at=self.wall_clock(), status=self.status,
                    running=bool(self.task and not self.task.done()),
                    monitoring=bool(self.monitor_task and not self.monitor_task.done()),
                    attack_name="HTTP Flood (Application-Layer DoS)", target=TARGET,
                    target_origin=self.base_url, source_identity="lab-flood",
                    source_ip="loopback / isolated capability (shared IP never blocked)",
                    config=self.config.model_dump(), limits=dict(max_rate=50, max_duration=20,
                        max_concurrency=8, max_requests=1000),
                    thresholds=dict(window_seconds=self.detector.window, warning_rps=self.detector.warning_rps,
                        block_rps=self.detector.block_rps, block_seconds=self.detector.block_seconds),
                    detected=self.detected_at is not None, detected_at=self.detected_at, detection_rps=self.detection_rps,
                    blocked=self.block_until > self.clock(),
                    block_remaining_seconds=round(max(0, self.block_until-self.clock()), 1),
                    recovered=self.recovered, error=self.error,
                    elapsed_seconds=round(max(0, (self.ended or self.wall_clock())-self.started), 2)
                        if self.started is not None else 0,
                    started_at=self.started, stopped_at=self.ended,
                    flood=dict(self.counts["flood"]), legitimate=legitimate,
                    **rates, peak_rps=self.peak_rate, samples=list(self.samples), timeline=list(self.timeline),
                    recent_rejections=list(self.recent_rejections),
                    detection_method=METHOD,
                    gatv2=dict(evidence=evidence, status="associated" if evidence else "unavailable",
                        note="Only exact recorded TCP socket tuples are associated. Loopback may not be visible "
                             "on the selected adapter; no model prediction is inferred from HTTP rules."))

    async def _publish(self):
        from backend.chat_service import state
        self._expire()
        rates = self._rates()
        self.peak_rate = max(self.peak_rate, rates["total_rps"])
        if self.started is None:
            self.baseline_rps = rates["total_rps"]
        self.samples.append(dict(timestamp=self.wall_clock(), **rates))
        rejected = self.counts["flood"]["rejected"]
        if rejected > self._published_rejected:
            self._event("HTTP_REQUESTS_REJECTED", f"{rejected-self._published_rejected} requests rejected; {rejected} total",
                        rejected_requests=rejected)
            self._published_rejected = rejected
        pending = list(self.pending_events)
        self.pending_events.clear()
        for event in pending:
            await state.event(event["type"], {k:v for k,v in event.items() if k != "type"})
        # Snapshots already include bounded history; don't duplicate them in the
        # chat event ring on every tick.
        await state.broadcast_dashboard({"type":"HTTP_FLOOD_TELEMETRY", **self.get_state()})

    async def _publisher(self):
        while True:
            try:
                await asyncio.wait_for(self._publish(), timeout=2)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("HTTP lab telemetry broadcast failed")
            await asyncio.sleep(0.5)

    def _ensure_publisher(self):
        if self.publisher_task is None or self.publisher_task.done():
            self.publisher_task = asyncio.create_task(self._publisher(), name="http-lab-telemetry")

    async def prepare(self, base_url):
        async with self.lock:
            await self._probe_origin(base_url)
            return self._prepare(base_url)

    async def _probe_origin(self, base_url):
        # A single capability-authenticated health request must prove this is
        # the same app instance before any sustained traffic is dispatched.
        if self._closed:
            raise ValueError("HTTP lab is shutting down")
        base_url = validate_base_url(base_url)
        if self.base_url and self.base_url != base_url:
            raise ValueError("Reset before changing the configured origin")
        self.base_url = base_url
        async with self._client(1) as client:
            if not await self._request(client, "legitimate"):
                raise ValueError("Local lab preflight failed; verify the configured listener and reset. " + (self.error or ""))

    def _prepare(self, base_url):
        if self._closed:
            raise ValueError("HTTP lab is shutting down")
        base_url = validate_base_url(base_url)
        if self.base_url and self.base_url != base_url:
            raise ValueError("Reset before changing the configured origin")
        self.base_url = base_url
        self._ensure_publisher()
        if self.monitor_task is None or self.monitor_task.done():
            self.monitor_task = asyncio.create_task(self._normal_traffic(), name="http-lab-legitimate")
        return self.get_state()

    async def start(self, base_url, config: RunConfig | None = None):
        async with self.lock:
            if self.task and not self.task.done() or self.started is not None:
                raise ValueError("A run already exists; stop and reset before starting another")
            self.config = config or RunConfig()
            await self._probe_origin(base_url)
            self._prepare(base_url)
            self.started, self.status = self.wall_clock(), "attack_running"
            self._event("HTTP_FLOOD_STARTED", "Bounded real loopback HTTP generator started",
                        config=self.config.model_dump())
            self.task = asyncio.create_task(self._run(), name="http-flood-generator")
            return self.get_state()

    async def _request(self, client, role):
        counts = self.counts[role]
        counts["generated"] += 1
        counts["in_flight"] += 1
        before = self.clock()
        try:
            async with client.stream("GET", TARGET, headers={HEADER:self.keys[role]}) as response:
                if role == "flood":
                    stream = response.extensions.get("network_stream")
                    if stream is not None:
                        local, remote = stream.get_extra_info("client_addr"), stream.get_extra_info("server_addr")
                        if local and remote and len(self.endpoints) < 1000:
                            self.endpoints.add((str(local[0]), int(local[1]), str(remote[0]), int(remote[1])))
                await response.aread()
                if response.status_code == 200 and response.json().get("run_id") != self.run_id:
                    raise ValueError("Configured loopback origin is not this Sentinel lab instance")
                key = "successful" if response.status_code == 200 else "blocked" if response.status_code == 429 else "failed"
                counts[key] += 1
                if key == "failed":
                    self.error = f"{role} client received HTTP {response.status_code}"
                    self._event("HTTP_REQUEST_FAILED", f"{role} client received HTTP {response.status_code}")
                return key == "successful"
        except asyncio.CancelledError:
            counts["failed"] += 1
            raise
        except Exception as exc:
            counts["failed"] += 1
            self.error = f"{type(exc).__name__}: {exc}"
            self._event("HTTP_REQUEST_FAILED", f"{role} request failed: {self.error}")
            log.warning("HTTP lab request failed: %s", self.error)
            return False
        finally:
            counts["in_flight"] -= 1
            counts["latency_ms"] = round((self.clock()-before)*1000, 2)

    def _client(self, concurrency):
        return httpx.AsyncClient(base_url=self.base_url, timeout=1.0, trust_env=False,
                                 follow_redirects=False, limits=httpx.Limits(
                                     max_connections=concurrency, max_keepalive_connections=concurrency))

    async def _normal_traffic(self):
        self._event("HTTP_NORMAL_TRAFFIC_STARTED", "Independent legitimate client: one real request per second; 120s limit")
        try:
            async with self._client(1) as client:
                deadline = self.clock()+120
                while self.clock() < deadline:
                    await self._request(client, "legitimate")
                    await asyncio.sleep(1)
        finally:
            self._event("HTTP_NORMAL_TRAFFIC_STOPPED", "Legitimate monitor stopped")

    async def _run(self):
        active = set()
        try:
            async with self._client(self.config.concurrency) as client:
                begin = self.clock()
                for index in range(min(1000, math.ceil(self.config.rate*self.config.duration))):
                    delay = begin+index/self.config.rate-self.clock()
                    if delay > 0:
                        await asyncio.sleep(delay)
                    if self.clock()-begin >= self.config.duration:
                        break
                    active = {t for t in active if not t.done()}
                    if len(active) < self.config.concurrency:
                        active.add(asyncio.create_task(self._request(client, "flood")))
                if active:
                    await asyncio.gather(*active)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            log.exception("HTTP flood generator failed")
        finally:
            for task in active:
                task.cancel()
            if active:
                await asyncio.gather(*active, return_exceptions=True)
            self.ended = self.wall_clock()
            self.status = "error" if self.error else "attack_stopped"
            self._event("HTTP_FLOOD_STOPPED", "Bounded generator stopped")
            self._expire()

    async def stop(self):
        async with self.lock:
            if self.task and not self.task.done():
                self.task.cancel()
                await asyncio.gather(self.task, return_exceptions=True)
            # Cancellation before the coroutine's first step doesn't execute its
            # finally block. Still publish an honest terminal state.
            if self.started is not None and self.ended is None:
                self.ended, self.status = self.wall_clock(), "attack_stopped"
                self._event("HTTP_FLOOD_STOPPED", "Generator cancelled before dispatch")
            return self.get_state()

    async def unblock(self):
        async with self.lock:
            if self.task and not self.task.done():
                raise ValueError("Stop the generator before manually unblocking")
            if self.block_until:
                self.block_until = 0
                self.source_windows["flood"].clear()
                self._event("HTTP_SOURCE_UNBLOCKED", "Administrator removed application block", reason="manual")
            return self.get_state()

    async def reset(self):
        async with self.lock:
            if self.task and not self.task.done():
                raise ValueError("Stop the generator before resetting")
            tasks = [t for t in (self.monitor_task, self.publisher_task) if t]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.task = self.monitor_task = self.publisher_task = None
            self._clear()
            self._event("HTTP_LAB_RESET", "Demonstration reset; capabilities rotated")
            await self._publish()
            return self.get_state()

    async def close(self):
        async with self.lock:
            self._closed = True
            tasks = [t for t in (self.task, self.monitor_task, self.publisher_task) if t]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            self.block_until = 0


http_flood_simulator = HTTPFloodSimulator()


class HTTPFloodGuard:
    def __init__(self, app, controller=None):
        self.app = app
        self.controller = controller or http_flood_simulator

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") != TARGET:
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive=receive)
        try:
            local_peer = ipaddress.ip_address(request.client.host).is_loopback
        except (ValueError, AttributeError):
            local_peer = False
        role = self.controller.role_for_key(request.headers.get(HEADER, ""))
        if not local_peer or request.headers.get("cf-connecting-ip") or request.headers.get("x-forwarded-for") or not role:
            response = JSONResponse({"detail":"Isolated local lab capability required"}, status_code=403)
        elif self.controller.observe(role):
            response = JSONResponse({"detail":"Lab source temporarily rate limited"}, status_code=429,
                headers={"Retry-After":str(max(1, math.ceil(self.controller.block_until-self.controller.clock())))})
        else:
            await self.app(scope, receive, send)
            return
        await response(scope, receive, send)
