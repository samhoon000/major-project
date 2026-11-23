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
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.requests import Request
from starlette.responses import JSONResponse

log = logging.getLogger(__name__)
TARGET = "/api/attack-lab/http-flood-target"
BROWSER_TARGET = "/api/attack-lab/http-verification/request"
HEADER = "x-sentinel-lab-key"
METHOD = "Rule-Based HTTP Flood Detection"
POLICY_CHECK_MAX_REQUESTS = 25
POLICY_CHECK_TIMEOUT_MARGIN = 2
POLICY_TRAFFIC_WINDOW = 60
PHONE_CHECK_COOLDOWN = 5
PHONE_CHECK_TIMEOUT_MARGIN = 8


class RunConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rate: int = Field(default=25, ge=1, le=50, strict=True)
    duration: float = Field(default=8, ge=1, le=20, allow_inf_nan=False)
    concurrency: int = Field(default=4, ge=1, le=8, strict=True)


class PolicyCheckConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rate: int = Field(default=1, ge=1, le=1, strict=True)
    request_count: int = Field(default=1, ge=1, le=POLICY_CHECK_MAX_REQUESTS, strict=True)
    concurrency: int = Field(default=1, ge=1, le=1, strict=True)
    # Older callers supplied a duration to select how many one-second slots to run.
    duration: int | None = Field(default=None, ge=1, le=10, strict=True)

    @model_validator(mode="after")
    def check_count_source(self):
        if "duration" in self.model_fields_set:
            if self.duration is None or "request_count" in self.model_fields_set:
                raise ValueError("Supply either a request count or a legacy duration")
        return self

    @property
    def selected_count(self):
        return self.duration if self.duration is not None else self.request_count


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
        self.source_identity = "lab-flood"
        self.target_path = TARGET
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
                     run_id=self.run_id, message=message, source_identity=self.source_identity,
                     target=self.target_path, detection_method=METHOD, **data)
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
        if role == "flood" and counts["received"] == 1:
            self._event("HTTP_TRAFFIC_OBSERVED", "First request received at the isolated HTTP endpoint")
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
            self._event("HTTP_FLOOD_ATTACK_DETECTED", "HTTP request rate reached the configured detection threshold",
                        observed_rps=rps, severity="HIGH", detected_at=self.detected_at)
            self._event("HTTP_SECURITY_ALERT", "Isolated HTTP request rate exceeded the configured policy",
                        alert_id=f"http-{self.run_id}-{self.sequence}", severity="HIGH",
                        observed_rps=rps, threshold_rps=self.detector.block_rps,
                        status="open")
            self.block_until = now + self.detector.block_seconds
            self.status, self.recovered = "mitigation_active", False
            self._event("HTTP_MITIGATION_ACTIVATED", "Temporary restriction applied to the isolated client",
                        block_seconds=self.detector.block_seconds, mitigation="Application-level HTTP 429",
                        expires_at=self.wall_clock() + self.detector.block_seconds)
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

    def get_state(self, *, include_network_evidence=True):
        self._expire()
        rates = self._rates()
        evidence = self._network_evidence() if include_network_evidence else []
        legitimate = dict(self.counts["legitimate"])
        completed = legitimate["generated"] - legitimate["in_flight"]
        legitimate["success_rate"] = round(legitimate["successful"]/completed,4) if completed else None
        return dict(run_id=self.run_id, sequence=self.sequence, snapshot_at=self.wall_clock(), status=self.status,
                    running=bool(self.task and not self.task.done()),
                    monitoring=bool(self.monitor_task and not self.monitor_task.done()),
                    attack_name="HTTP Flood (Application-Layer DoS)", target=self.target_path,
                    target_origin=self.base_url, source_identity=self.source_identity,
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

    async def _request(self, client, role, *, verify_rejection=False):
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
                if (response.status_code == 200 or verify_rejection and response.status_code == 429) and (
                    response.json().get("run_id") != self.run_id
                ):
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
            await self._stop()
            return self.get_state()

    async def _stop(self):
        if self.task and not self.task.done():
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        if self.started is not None and self.ended is None:
            self.ended, self.status = self.wall_clock(), "attack_stopped"
            self._event("HTTP_FLOOD_STOPPED", "Run cancelled before dispatch")

    async def unblock(self):
        async with self.lock:
            if self.task and not self.task.done():
                raise ValueError("Stop the generator before manually unblocking")
            if self.block_until:
                self.block_until = 0
                self.source_windows["flood"].clear()
                self._event("HTTP_SOURCE_UNBLOCKED", "Administrator removed application block", reason="manual")
            return self.get_state()

    async def reset(self, *, stop_running=False):
        async with self.lock:
            return await self._reset(stop_running)

    async def _reset(self, stop_running):
        if stop_running:
            await self._stop()
        elif self.task and not self.task.done():
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


class HTTPPolicyVerification(HTTPFloodSimulator):
    """Exercise the detector against a quota of three requests per four seconds."""

    def __init__(self):
        self.next_request_at = 0.0
        self.phone_cooldown_until = 0.0
        # The chart spans runs, so reset only clears the per-run detector state.
        self.traffic_responses: list[tuple[float, int, str]] = []
        super().__init__(DetectorConfig(window=4, warning_rps=0.5, block_rps=0.75, block_seconds=8))

    def _clear(self):
        super()._clear()
        self.config = PolicyCheckConfig()
        self.response_latencies = []
        self.outcome = None
        self.phone_owner = None
        self.phone_next_request_at = 0.0
        self.phone_deadline = 0.0

    def get_state(self, *, include_network_evidence=True):
        snapshot = super().get_state(include_network_evidence=include_network_evidence)
        unused_count_field = "request_count" if self.config.duration is not None else "duration"
        snapshot["config"].pop(unused_count_field)
        return dict(
            snapshot, profile="policy-verification", outcome=self.outcome,
            run_source="cloudflare-browser" if self.phone_owner is not None else "host-loopback",
            source_ip="Cloudflare / operator browser" if self.phone_owner is not None else snapshot["source_ip"],
            request_count=self.config.selected_count,
            attack_name="Isolated HTTP rate-policy verification",
            limits=dict(max_rate=1, max_requests=POLICY_CHECK_MAX_REQUESTS, max_concurrency=1,
                        max_duration=(POLICY_CHECK_MAX_REQUESTS + POLICY_CHECK_TIMEOUT_MARGIN if self.phone_owner is None
                                      else PHONE_CHECK_TIMEOUT_MARGIN + POLICY_CHECK_MAX_REQUESTS * 2)),
            latency_average_ms=round(sum(self.response_latencies) / len(self.response_latencies), 2)
            if self.response_latencies else None,
        )

    def operator_snapshot(self, session=None):
        """Expose measured policy results without host details, raw flows, or exception text."""
        state = self.get_state(include_network_evidence=False)
        fields = ("run_id", "snapshot_at", "profile", "config", "request_count", "running", "outcome",
                  "started_at", "stopped_at", "elapsed_seconds", "total_rps", "peak_rps", "thresholds",
                  "blocked", "latency_average_ms", "detection_method", "run_source")
        event_fields = {"type", "timestamp", "observed_rps", "severity", "alert_id", "expires_at", "status_code"}
        result_fields = ("generated", "in_flight", "successful", "blocked", "failed")
        return dict(type="HTTP_POLICY_RUN", **{key: state[key] for key in fields},
                    owns_run=session is not None and session is self.phone_owner,
                    error="Local policy check failed. See the host console." if state["error"] else None,
                    timeline=[{key: value for key, value in event.items() if key in event_fields}
                              for event in state["timeline"]],
                    flood={key: state["flood"][key] for key in result_fields})

    def _prune_traffic(self, now):
        self.traffic_responses = [response for response in self.traffic_responses
                                  if now - POLICY_TRAFFIC_WINDOW < response[0] <= now]

    def record_traffic_response(self, arrived_at, status, source="host-loopback"):
        if status in (200, 429):
            self.traffic_responses.append((arrived_at, status, source))
            self._prune_traffic(self.wall_clock())

    def traffic_snapshot(self):
        now = self.wall_clock()
        self._prune_traffic(now)
        first = math.floor(now - POLICY_TRAFFIC_WINDOW)
        counts = [[0, 0] for _ in range(POLICY_TRAFFIC_WINDOW + 1)]
        sources = {"host-loopback": 0, "cloudflare-browser": 0}
        for arrived_at, status, source in self.traffic_responses:
            counts[math.floor(arrived_at) - first][0 if status == 200 else 1] += 1
            sources[source] += 1
        buckets = []
        for second, (accepted, blocked) in enumerate(counts, start=first):
            buckets.append(dict(timestamp=second, total_rps=accepted + blocked,
                                accepted_rps=accepted, blocked_rps=blocked))
        accepted = sum(bucket["accepted_rps"] for bucket in buckets)
        blocked = sum(bucket["blocked_rps"] for bucket in buckets)
        return dict(type="HTTP_POLICY_TRAFFIC", snapshot_at=now, window_seconds=POLICY_TRAFFIC_WINDOW, buckets=buckets,
                    run_id=self.run_id if self.started is not None else None,
                    run_source=("cloudflare-browser" if self.phone_owner is not None else "host-loopback")
                    if self.started is not None else None, sources=sources,
                    totals=dict(total=accepted + blocked, accepted=accepted, blocked=blocked),
                    thresholds=dict(block_rps=self.detector.block_rps, window_seconds=self.detector.window))

    async def start_check(self, base_url, config: PolicyCheckConfig | None = None):
        async with self.lock:
            if self._closed or self.started is not None:
                raise ValueError("Reset the lab before starting another check")
            self.base_url = validate_base_url(base_url)
            self.config = config or PolicyCheckConfig()
            self.started, self.status = self.wall_clock(), "attack_running"
            self.task = asyncio.create_task(self._run_check(), name="http-policy-verification")
            self._ensure_publisher()
            return self.get_state()

    async def start_phone_check(self, session, request_count):
        async with self.lock:
            if self._closed or self.started is not None:
                raise ValueError("Reset the lab before starting another check")
            if self.clock() < self.phone_cooldown_until:
                raise ValueError("Wait five seconds after the previous browser run")
            self.config = PolicyCheckConfig(request_count=request_count)
            self.phone_owner = session
            self.source_identity = "cloudflare-browser"
            self.target_path = BROWSER_TARGET
            self.started, self.status = self.wall_clock(), "attack_running"
            self.phone_deadline = self.clock() + PHONE_CHECK_TIMEOUT_MARGIN + request_count * 2
            self.task = asyncio.create_task(self._phone_timeout(), name="http-browser-verification")
            self._ensure_publisher()
            return self.operator_snapshot(session)

    async def _phone_timeout(self):
        await asyncio.sleep(max(0, self.phone_deadline - self.clock()))
        async with self.lock:
            self._expire_phone_check()

    def _expire_phone_check(self):
        if self.ended is None and self.clock() >= self.phone_deadline:
            self.error = "Browser verification timed out"
            self._finish_phone_check("error")

    def _require_phone_run(self, session, run_id):
        if session is not self.phone_owner or not self.phone_owner or run_id != self.run_id:
            raise ValueError("No matching browser run for this operator session")

    async def phone_request(self, session, run_id, sequence):
        started = self.clock()
        arrived_at = self.wall_clock()
        async with self.lock:
            self._require_phone_run(session, run_id)
            self._expire_phone_check()
            counts = self.counts["flood"]
            if self.ended is not None or sequence != counts["generated"] + 1:
                raise ValueError("Browser run ended or request sequence is out of order")
            if self.clock() < self.phone_next_request_at:
                raise ValueError("Wait at least one second between verification requests")
            self.phone_next_request_at = self.clock() + 1
            counts["generated"] += 1
            previous_blocks = counts["blocked"]
            blocked = self.observe("flood")
            counts["blocked" if blocked else "successful"] += 1
            status = 429 if blocked else 200
            self.record_traffic_response(arrived_at, status, "cloudflare-browser")
            self.response_latencies.append(round((self.clock() - started) * 1000, 2))
            self._verify_followup(previous_blocks, counts["blocked"])
            if sequence == self.config.selected_count:
                self._finish_phone_check("complete")
            return status

    def _finish_phone_check(self, outcome):
        if self.task is not None and self.task is not asyncio.current_task():
            self.task.cancel()
        self.task = None
        self.phone_cooldown_until = self.clock() + PHONE_CHECK_COOLDOWN
        self.ended = self.wall_clock()
        self.outcome = outcome
        self.status = "error" if self.error else "attack_stopped"
        self._event("HTTP_FLOOD_STOPPED", "Cloudflare browser policy check ended", outcome=outcome)
        self._expire()

    async def phone_command(self, session, run_id, action):
        async with self.lock:
            self._require_phone_run(session, run_id)
            self._expire_phone_check()
            if action == "stop" and self.ended is None:
                self._finish_phone_check("stopped")
            if action == "reset":
                await self._reset(stop_running=False)
            return self.operator_snapshot(session)

    def _verify_followup(self, previous_blocks, blocked):
        if previous_blocks == 1 and blocked == 2:
            self._event("HTTP_PROTECTION_VERIFIED", "Subsequent request received HTTP 429 from this lab",
                        status_code=429, rejected_requests=blocked)

    async def _run_check(self):
        request_count = self.config.selected_count

        async def check_responses():
            async with self._client(1) as client:
                counts = self.counts["flood"]
                for _ in range(request_count):
                    await asyncio.sleep(max(0, self.next_request_at - self.clock()))
                    self.next_request_at = self.clock() + 1
                    previous_blocks, previous_errors = counts["blocked"], counts["failed"]
                    await self._request(client, "flood", verify_rejection=True)
                    if counts["failed"] > previous_errors:
                        return "error"
                    self.response_latencies.append(counts["latency_ms"])
                    self._verify_followup(previous_blocks, counts["blocked"])
                return "complete"

        try:
            # Allow for the pacing delay from the preceding run and the last response.
            async with asyncio.timeout(request_count + POLICY_CHECK_TIMEOUT_MARGIN):
                self.outcome = await check_responses()
        except TimeoutError:
            self.error, self.outcome = "Verification timed out", "error"
        except asyncio.CancelledError:
            self.outcome = "stopped"
            raise
        except Exception as exc:
            self.error, self.outcome = f"{type(exc).__name__}: {exc}", "error"
            log.exception("HTTP policy check failed")
        finally:
            self.ended = self.wall_clock()
            self.status = "error" if self.error else "attack_stopped"
            self._event("HTTP_FLOOD_STOPPED", "Local HTTP policy check ended", outcome=self.outcome)

    async def _stop(self):
        if self.phone_owner is not None and self.ended is None:
            self._finish_phone_check("stopped")
            return
        await super()._stop()
        if self.started is not None and self.outcome is None:
            self.outcome = "stopped"


policy_verification = HTTPPolicyVerification()


class HTTPFloodGuard:
    def __init__(self, app, controller=None):
        self.app = app
        self.controller = controller

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") != TARGET:
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive=receive)
        try:
            local_peer = ipaddress.ip_address(request.client.host).is_loopback
        except (ValueError, AttributeError):
            local_peer = False
        if not local_peer or any(request.headers.get(name) for name in (
            "cf-connecting-ip", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded"
        )):
            response = JSONResponse({"detail":"Isolated local lab capability required"}, status_code=403)
        else:
            response = JSONResponse({"detail":"Isolated local lab capability required"}, status_code=403)
            controllers = ((self.controller,) if self.controller is not None
                           else (http_flood_simulator, policy_verification))
            for controller in controllers:
                role = controller.role_for_key(request.headers.get(HEADER, ""))
                if not role:
                    continue
                target_send = send
                if isinstance(controller, HTTPPolicyVerification) and role == "flood":
                    arrived_at = controller.wall_clock()

                    async def record_response(message):
                        await send(message)
                        if message["type"] == "http.response.start":
                            controller.record_traffic_response(arrived_at, message["status"])

                    target_send = record_response
                if controller.observe(role):
                    response = JSONResponse(
                        {"detail": "Lab source temporarily rate limited", "run_id": controller.run_id},
                        status_code=429, headers={"Retry-After": str(max(1, math.ceil(
                            controller.block_until - controller.clock())))})
                    await response(scope, receive, target_send)
                    return
                request.state.http_lab_run_id = controller.run_id
                await self.app(scope, receive, target_send)
                return
        await response(scope, receive, send)
