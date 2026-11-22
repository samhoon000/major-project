"""Passive TCP scan detection and scoped application enforcement evidence."""
from __future__ import annotations

import ipaddress
import logging
import os
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from uuid import uuid4

VERIFY_PATH = "/api/attack-lab/port-scan/verify"
MAX_GROUPS = 512
MAX_ATTEMPTS_PER_GROUP = 128
log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanPolicy:
    window_seconds: int = 30
    distinct_ports: int = 8
    failed_ports: int = 3
    restriction_seconds: int = 15

    def __post_init__(self):
        if not (1 <= self.window_seconds <= 600 and 2 <= self.distinct_ports <= MAX_ATTEMPTS_PER_GROUP
                and 1 <= self.failed_ports <= self.distinct_ports and 1 <= self.restriction_seconds <= 60):
            raise ValueError("Invalid port scan policy")

    @classmethod
    def from_environment(cls):
        value = os.getenv("SENTINEL_PORT_SCAN_WINDOW_SECONDS")
        if value is not None:
            try:
                return cls(window_seconds=int(value))
            except ValueError:
                log.warning("Ignoring invalid SENTINEL_PORT_SCAN_WINDOW_SECONDS")
        return cls()


@dataclass
class Attempt:
    opened: float
    result: str = "pending"


@dataclass
class SourcePair:
    attempts: dict[tuple[int, int, int], Attempt] = field(default_factory=dict)
    observation_id: str = field(default_factory=lambda: uuid4().hex)
    suspicious: bool = False
    alert_id: str | None = None
    detection_at: float | None = None
    restricted_until: float = 0
    verified: bool = False
    recovered: bool = False
    latched: bool = False

    def evidence(self):
        ports = {key[1] for key in self.attempts}
        refused = [key[1] for key, attempt in self.attempts.items() if attempt.result == "refused"]
        return dict(attempts=len(self.attempts), unique_ports=len(ports),
                    failed_attempts=len(refused), failed_ports=len(set(refused)))


class PortScanMonitor:
    def __init__(self, policy=None, clock=time.monotonic, wall_clock=time.time):
        self.policy = policy or ScanPolicy.from_environment()
        self.clock, self.wall_clock = clock, wall_clock
        self._lock = threading.Lock()
        self._groups: OrderedDict[tuple[str, str], SourcePair] = OrderedDict()
        self._events = deque(maxlen=120)
        self._samples = deque(maxlen=60)
        self._total_attempts = 0
        self._total_failed = 0
        self._last_detection = None

    def _log(self, kind, pair, group, message, **details):
        self._events.append(dict(type=kind, timestamp=self.wall_clock(), source=pair[0], destination=pair[1],
                                 protocol="TCP", observation_id=group.observation_id, alert_id=group.alert_id,
                                 message=message, **details))

    def _expire(self, pair, group, now):
        cutoff = now - self.policy.window_seconds
        while group.attempts:
            key = next(iter(group.attempts))
            if group.attempts[key].opened > cutoff:
                break
            del group.attempts[key]
        if group.restricted_until and group.restricted_until <= now:
            group.restricted_until = 0
            group.recovered = True
            self._log("recovered", pair, group, "Dedicated HTTP endpoint restriction expired.")

    def _evaluate(self, pair, group, now):
        evidence = group.evidence()
        suspicious = evidence["unique_ports"] >= max(2, self.policy.distinct_ports - 2) and evidence["failed_ports"] > 0
        confirmed = evidence["unique_ports"] >= self.policy.distinct_ports and evidence["failed_ports"] >= self.policy.failed_ports
        if suspicious and not group.suspicious and not group.latched:
            self._log("suspicious", pair, group, "Multiple destination ports and TCP refusals observed.", **evidence)
        group.suspicious = suspicious
        if not suspicious:
            if group.latched and not group.recovered and not group.restricted_until:
                group.recovered = True
                self._log("recovered", pair, group, "Connection evidence dropped below the alert window.")
            group.latched = False
        if not confirmed or group.latched or group.restricted_until:
            return
        group.latched = True
        group.alert_id = uuid4().hex
        group.detection_at = self.wall_clock()
        self._last_detection = group.detection_at
        group.verified = group.recovered = False
        self._log("detected", pair, group, "Distinct-port and refused-port thresholds met.", **evidence)
        self._log("alert", pair, group, "TCP port scan alert generated.", severity="high", **evidence)
        if all(ipaddress.ip_address(address).is_loopback for address in pair):
            group.restricted_until = now + self.policy.restriction_seconds
            self._log("mitigation", pair, group, "Temporary application restriction activated.", scope=VERIFY_PATH)

    def observe(self, packet):
        flags = packet.get("tcp_flags") or ""
        if packet.get("protocol") != "TCP" or not ("S" in flags or "R" in flags):
            return
        initial = "S" in flags and "A" not in flags and "R" not in flags
        source, destination = packet["source_ip"], packet["destination_ip"]
        source_port, destination_port = packet["source_port"], packet["destination_port"]
        if initial:
            sequence = packet.get("tcp_sequence")
            if sequence is None:
                return
            pair, key = (source, destination), (source_port, destination_port, sequence)
        else:
            acknowledgement = packet.get("tcp_ack")
            if "A" not in flags or acknowledgement is None:
                return
            sequence = (acknowledgement - 1) % (1 << 32)
            pair, key = (destination, source), (destination_port, source_port, sequence)
        with self._lock:
            now = self.clock()
            group = self._groups.get(pair)
            if group is None:
                if not initial:
                    return
                if len(self._groups) >= MAX_GROUPS:
                    victim = next((p for p, g in self._groups.items() if not g.restricted_until), None)
                    if victim is None:
                        return
                    del self._groups[victim]
                self._groups[pair] = group = SourcePair()
            self._expire(pair, group, now)
            self._groups.move_to_end(pair)
            if initial:
                if key in group.attempts:
                    return
                if not group.attempts:
                    self._log("observed", pair, group, "TCP connection activity observed.")
                if len(group.attempts) >= MAX_ATTEMPTS_PER_GROUP:
                    del group.attempts[next(iter(group.attempts))]
                group.attempts[key] = Attempt(now)
                self._total_attempts += 1
            else:
                attempt = group.attempts.get(key)
                if attempt is None or attempt.result != "pending":
                    return
                attempt.result = "refused" if "R" in flags else "syn_ack"
                self._total_failed += int(attempt.result == "refused")
            self._evaluate(pair, group, now)

    def restriction(self, pair):
        with self._lock:
            group = self._groups.get(pair)
            if group is None:
                return None
            self._expire(pair, group, self.clock())
            return group.alert_id if group.restricted_until else None

    def record_rejection(self, pair, alert_id):
        with self._lock:
            group = self._groups.get(pair)
            if group and group.alert_id == alert_id and not group.verified:
                group.verified = True
                self._log("verified", pair, group, "Dedicated endpoint returned HTTP 429.", scope=VERIFY_PATH)

    def _metrics(self, now):
        attempts, failed, current, ports = 0, 0, 0, set()
        rows = []
        for pair, group in list(self._groups.items()):
            self._expire(pair, group, now)
            self._evaluate(pair, group, now)
            if not group.attempts and not group.restricted_until:
                del self._groups[pair]
                continue
            evidence = group.evidence()
            attempts += evidence["attempts"]
            failed += evidence["failed_attempts"]
            current += sum(attempt.opened > now - 1 for attempt in group.attempts.values())
            ports.update((pair[1], port) for _, port, _ in group.attempts)
            if group.suspicious or group.alert_id:
                rows.append(dict(source=pair[0], destination=pair[1], **evidence, suspicious=group.suspicious,
                                 active_alert=group.latched, restricted=bool(group.restricted_until),
                                 observation_id=group.observation_id, alert_id=group.alert_id,
                                 detection_at=group.detection_at, verified=group.verified,
                                 status=("Mitigation Active" if group.restricted_until else
                                         "Recovered" if group.recovered else
                                         "Port Scan Detected" if group.alert_id else "Suspicious")))
        return dict(attempts=attempts, failed_attempts=failed, attempts_per_second=current, unique_ports=len(ports)), rows

    def sample(self):
        with self._lock:
            metrics, _ = self._metrics(self.clock())
            self._samples.append(dict(timestamp=self.wall_clock(), **metrics))

    def snapshot(self):
        with self._lock:
            metrics, rows = self._metrics(self.clock())
            rows.sort(key=lambda row: (row["restricted"], row["active_alert"], row["suspicious"],
                                       row["detection_at"] or 0, row["unique_ports"]), reverse=True)
            return dict(**metrics, total_attempts=self._total_attempts, total_failed=self._total_failed,
                        window_seconds=self.policy.window_seconds, distinct_threshold=self.policy.distinct_ports,
                        failed_port_threshold=self.policy.failed_ports,
                        suspicious_sources=len({row["source"] for row in rows if row["suspicious"]}),
                        active_alerts=sum(row["active_alert"] for row in rows),
                        active_mitigations=sum(row["restricted"] for row in rows),
                        last_detection=self._last_detection, sources=rows[:12],
                        samples=list(self._samples), events=list(self._events))
