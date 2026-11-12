"""Coordinates capture, flow expiry, and truthful network status reporting."""
from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from collections import deque
from threading import Lock

from backend.network.capture import PacketCapture
from backend.network.flow_tracker import FlowTracker
from backend.network.gatv2_inference import GATv2Inference
from backend.network.enforcement import QuarantineManager

log = logging.getLogger(__name__)


def build_attack_event(flow: dict, result: dict, timestamp: float | None = None) -> dict:
    probability, threshold = result["anomaly_probability"], result["threshold"]
    return {"flow_id": flow["flow_id"], "source_ip": flow["source_ip"],
            "destination_ip": flow["destination_ip"], "source_port": flow["source_port"],
            "destination_port": flow["destination_port"], "protocol": flow["protocol"],
            "anomaly_probability": probability, "threshold": threshold,
            "prediction": result["prediction"], "gatv2_prediction": result["prediction"],
            "reason": f"GATv2 {result['prediction']} probability={probability:.6f} threshold={threshold:.6f}",
            "timestamp": timestamp if timestamp is not None else time.time()}


class NetworkRuntime:
    def __init__(self):
        self.loop = None
        self.capture = None
        self._capture_bootstrap = None
        self.tracker = FlowTracker(float(os.getenv("FLOW_IDLE_TIMEOUT", "15")), float(os.getenv("FLOW_MAX_DURATION", "120")), self._finalized)
        self.flows = deque(maxlen=300)
        self.pending = deque()
        self.inference = GATv2Inference()
        self.enforcement = QuarantineManager()
        self.packet_count = 0
        self.byte_count = 0
        self.recent_packets = deque()
        self._traffic_lock = Lock()
        self._expire_task = None

    def _packet(self, packet: dict):
        with self._traffic_lock:
            self.packet_count += 1
            self.byte_count += packet["packet_length"]
            self.recent_packets.append((packet["timestamp"], packet["packet_length"]))
        self.tracker.add_packet(packet["source_ip"], packet["destination_ip"], packet["source_port"], packet["destination_port"], packet["protocol"], packet["packet_length"], packet["timestamp"], packet.get("tcp_flags"))

    def _finalized(self, flow: dict):
        flow["features"] = self.tracker.features(flow)
        flow["gatv2_status"] = "unavailable"
        flow["gatv2_prediction"] = None
        flow["gatv2_anomaly_probability"] = None
        self.flows.append(flow)
        self.pending.append(flow)
        log.info("[FLOW] Flow finalized id=%s packets=%s", flow["flow_id"], flow["total_packets"])
        if self.loop and self.loop.is_running():
            from backend.chat_service import state
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(state.event("network_flow", flow)))

    async def start(self):
        self.loop = asyncio.get_running_loop()
        self.capture = PacketCapture(self._packet)
        self._capture_bootstrap = threading.Thread(target=self.capture.start, name="capture-bootstrap", daemon=True)
        self._capture_bootstrap.start()
        self._expire_task = asyncio.create_task(self._expire_loop())

    async def _expire_loop(self):
        try:
            while True:
                await asyncio.sleep(1)
                self.tracker.expire()
                for block in self.enforcement.expire():
                    await self._publish("BLOCK_EXPIRED", block.__dict__)
                if self.pending and self.inference.available:
                    batch = [self.pending.popleft() for _ in range(min(16, len(self.pending)))]
                    try:
                        results = await asyncio.to_thread(self.inference.analyze, batch)
                        by_id = {result["flow_id"]: result for result in results}
                        for flow in batch:
                            result = by_id[flow["flow_id"]]
                            flow.update({"gatv2_status": "analyzed", "gatv2_prediction": result["prediction"],
                                         "gatv2_anomaly_probability": result["anomaly_probability"],
                                         "gatv2_threshold": result["threshold"],
                                         "node_features": result["node_features"], "edge_features": result["edge_features"],
                                         "node_model_features": result["node_model_features"],
                                         "edge_model_features": result["edge_model_features"],
                                         "graph_node_count": result["graph_node_count"], "graph_edge_count": result["graph_edge_count"]})
                            analysis = {**flow, "capture_interface": self.capture.interface if self.capture else None,
                                        "timestamp": flow["last_seen"], "detection_source": "GATV2"}
                            await self._publish("gatv2_analysis", analysis)
                            if result["prediction"] == "ATTACK":
                                attack = build_attack_event(flow, result)
                                await self._publish("GATV2_ATTACK_DETECTED", attack)
                                try:
                                    block, action = self.enforcement.handle_attack(attack)
                                    await self._publish("BLOCK_APPLIED" if action == "BLOCK_APPLIED" else "enforcement_decision",
                                                        {**attack, "action": action, "reason": action,
                                                         "block": block.__dict__ if block else None})
                                except Exception as exc:
                                    log.exception("[ENFORCEMENT] Unable to apply quarantine")
                                    await self._publish("enforcement_error", {**attack, "action": "BLOCK_FAILED", "error": str(exc)})
                    except Exception as exc:
                        log.exception("[GATV2] live inference failed")
                        self.inference.available = False
                        self.inference.error = str(exc)
                        for flow in batch:
                            flow["gatv2_status"] = "unavailable"
                            flow["gatv2_error"] = str(exc)
                            await self._publish("gatv2_unavailable", {"flow_id": flow["flow_id"], "error": str(exc)})
        except asyncio.CancelledError:
            pass

    async def _publish(self, kind, event):
        from backend.chat_service import state
        await state.event(kind, event)

    async def stop(self):
        if self._expire_task:
            self._expire_task.cancel()
            await asyncio.gather(self._expire_task, return_exceptions=True)
        if self.capture:
            await asyncio.to_thread(self.capture.stop)
        if self._capture_bootstrap and self._capture_bootstrap.is_alive():
            self._capture_bootstrap.join(timeout=1.0)
        self.tracker.expire(force=True)
        for block in self.enforcement.expire():
            await self._publish("BLOCK_EXPIRED", block.__dict__)
        for block in self.enforcement.close():
            await self._publish("BLOCK_SHUTDOWN_CLEANUP", block.__dict__)

    def status(self):
        now = time.time()
        with self._traffic_lock:
            while self.recent_packets and self.recent_packets[0][0] < now - 1.0:
                self.recent_packets.popleft()
            packets_per_second = len(self.recent_packets)
            bytes_per_second = sum(length for _, length in self.recent_packets)
        return {"capture": "running" if self.capture and self.capture._thread and self.capture._thread.is_alive() else "unavailable",
                "capture_error": self.capture.error if self.capture else "not started",
                "interface": self.capture.interface if self.capture else None,
                "capture_filter": self.capture.bpf_filter if self.capture else "",
                "packets": self.packet_count, "bytes": self.byte_count,
                "packets_per_second": packets_per_second,
                "bytes_per_second": bytes_per_second,
                "active_flows": self.tracker.active_snapshots(),
                "completed_flows": list(self.flows), "gatv2": "available" if self.inference.available else "unavailable",
                "gatv2_error": self.inference.error,
                "analyses": sum(flow.get("gatv2_status") == "analyzed" for flow in self.flows),
                "attack_predictions": sum(flow.get("gatv2_prediction") == "ATTACK" for flow in self.flows),
                "latest_analysis": next((flow for flow in reversed(self.flows) if flow.get("gatv2_status") == "analyzed"), None),
                "threshold": getattr(self.inference, "threshold", None),
                "server_ips": sorted(self.enforcement.protected_ips),
                "blocked_sources": self.enforcement.snapshot()}


network_runtime = NetworkRuntime()
