"""Bidirectional 5-tuple flow aggregation with idle and max-age expiry."""
from __future__ import annotations

import time
import uuid
import threading
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Flow:
    flow_id: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    start_time: float
    last_seen: float
    forward_packet_count: int = 0
    backward_packet_count: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    packet_lengths: list[int] = field(default_factory=list)
    inter_arrival_times: list[float] = field(default_factory=list)
    tcp_flags: dict[str, int] = field(default_factory=dict)

    def snapshot(self) -> dict:
        duration = max(0.0, self.last_seen - self.start_time)
        packets = self.forward_packet_count + self.backward_packet_count
        octets = self.forward_bytes + self.backward_bytes
        return {"flow_id": self.flow_id, "source_ip": self.source_ip, "destination_ip": self.destination_ip,
                "source_port": self.source_port, "destination_port": self.destination_port, "protocol": self.protocol,
                "start_time": self.start_time, "last_seen": self.last_seen, "duration": duration,
                "forward_packet_count": self.forward_packet_count, "backward_packet_count": self.backward_packet_count,
                "total_packets": packets, "forward_bytes": self.forward_bytes, "backward_bytes": self.backward_bytes,
                "total_bytes": octets, "packet_lengths": list(self.packet_lengths),
                "inter_arrival_times": list(self.inter_arrival_times), "tcp_flags": dict(self.tcp_flags),
                "packets_per_second": packets / duration if duration else float(packets),
                "bytes_per_second": octets / duration if duration else float(octets)}


class FlowTracker:
    def __init__(self, idle_timeout: float = 15.0, max_duration: float = 120.0,
                 on_finalize: Callable[[dict], None] | None = None, clock: Callable[[], float] = time.time):
        self.idle_timeout, self.max_duration = idle_timeout, max_duration
        self.on_finalize, self.clock = on_finalize, clock
        self.active: dict[tuple, Flow] = {}
        self.completed: list[dict] = []
        self._lock = threading.RLock()

    @staticmethod
    def key(src: str, dst: str, sport: int, dport: int, protocol: str) -> tuple:
        a, b = (src, sport), (dst, dport)
        return (*sorted((a, b)), protocol.upper())

    def add_packet(self, src: str, dst: str, sport: int, dport: int, protocol: str, length: int,
                   timestamp: float | None = None, tcp_flags: str | None = None) -> dict:
        now = self.clock() if timestamp is None else timestamp
        with self._lock:
            self.expire(now)
            protocol = protocol.upper()
            key = self.key(src, dst, sport, dport, protocol)
            flow = self.active.get(key)
            if flow is None:
                flow = Flow(uuid.uuid4().hex, src, dst, int(sport), int(dport), protocol, now, now)
                self.active[key] = flow
            if (src, int(sport), dst, int(dport)) == (flow.source_ip, flow.source_port, flow.destination_ip, flow.destination_port):
                flow.forward_packet_count += 1
                flow.forward_bytes += max(0, int(length))
            else:
                flow.backward_packet_count += 1
                flow.backward_bytes += max(0, int(length))
            if flow.packet_lengths:
                flow.inter_arrival_times.append(max(0.0, now - flow.last_seen))
            flow.packet_lengths.append(max(0, int(length)))
            if tcp_flags:
                for flag in str(tcp_flags):
                    flow.tcp_flags[flag] = flow.tcp_flags.get(flag, 0) + 1
            flow.last_seen = now
            return flow.snapshot()

    def expire(self, now: float | None = None, force: bool = False) -> list[dict]:
        now = self.clock() if now is None else now
        expired = []
        with self._lock:
            for key, flow in list(self.active.items()):
                if force or now - flow.last_seen >= self.idle_timeout or now - flow.start_time >= self.max_duration:
                    result = flow.snapshot()
                    result["expired_at"] = now
                    del self.active[key]
                    self.completed.append(result)
                    expired.append(result)
                    if self.on_finalize:
                        self.on_finalize(result)
        return expired

    def active_snapshots(self) -> list[dict]:
        with self._lock:
            return [flow.snapshot() for flow in self.active.values()]

    def features(self, flow: dict) -> dict:
        """The CICIDS edge feature names/units used in graph_builder.py."""
        duration_seconds = float(flow["duration"])
        return {"Flow Duration": duration_seconds * 1_000_000,
                "Total Fwd Packets": flow["forward_packet_count"],
                "Total Backward Packets": flow["backward_packet_count"],
                "Flow Bytes/s": flow["total_bytes"] / duration_seconds if duration_seconds else 0.0,
                "Flow Packets/s": flow["total_packets"] / duration_seconds if duration_seconds else 0.0}
