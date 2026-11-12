"""Owns live capture, flow expiry and batched GATv2 inference."""
from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from collections import deque

from backend.chat_service import state as chat_state
from backend.network.capture import PacketCapture
from backend.network.flow_tracker import FlowTracker
from backend.network.gatv2_inference import gatv2_engine

log = logging.getLogger(__name__)


class NetworkRuntime:
    def __init__(self):
        self.loop = None
        self.capture = None
        self._capture_bootstrap = None
        self._worker = None
        self._pending: list[dict] = []
        self._pending_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._recent_packets = deque()
        self.packet_count = 0
        self.byte_count = 0
        self.last_prediction = None
        self.analysis_count = 0
        self.anomaly_count = 0
        self.completed_flows = deque(maxlen=300)
        self.started_at = time.monotonic()
        self.inference_window = float(os.getenv("GATV2_INFERENCE_WINDOW_SECONDS", "5"))
        self.tracker = FlowTracker(
            idle_timeout=float(os.getenv("FLOW_IDLE_TIMEOUT", "15")),
            max_duration=float(os.getenv("FLOW_MAX_DURATION", "120")),
            on_finalize=self._finalized,
        )

    async def start(self) -> None:
        if self._worker and not self._worker.done():
            return
        self.loop = asyncio.get_running_loop()
        interface = os.getenv("NETWORK_INTERFACE") or os.getenv("CAPTURE_INTERFACE")
        self.capture = PacketCapture(self._packet, interface=interface)
        # Windows adapter discovery may be slow; do not block FastAPI startup or chat.
        self._capture_bootstrap = threading.Thread(target=self.capture.start, name="capture-bootstrap", daemon=True)
        self._capture_bootstrap.start()
        self._worker = asyncio.create_task(self._run(), name="network-inference-worker")
        log.info("[CAPTURE] Startup requested interface=%s filter=%s", interface or "<unset>", self.capture.bpf_filter)

    def _packet(self, packet: dict) -> None:
        timestamp = float(packet["timestamp"])
        length = int(packet["packet_length"])
        with self._stats_lock:
            self.packet_count += 1
            self.byte_count += length
            self._recent_packets.append((timestamp, length))
            cutoff = timestamp - 1.0
            while self._recent_packets and self._recent_packets[0][0] < cutoff:
                self._recent_packets.popleft()
        flow = self.tracker.add_packet(
            packet["source_ip"], packet["destination_ip"], packet["source_port"],
            packet["destination_port"], packet["protocol"], length, timestamp,
            packet.get("tcp_flags"),
        )
        if flow["total_packets"] == 1:
            self._schedule_event("flow_started", {**flow, "username": self._resolve_user(flow)})

    def _resolve_user(self, flow: dict) -> str:
        return chat_state.resolve_flow_user(flow)

    def _finalized(self, flow: dict) -> None:
        flow["features"] = self.tracker.features(flow)
        flow["username"] = self._resolve_user(flow)
        flow["gatv2_status"] = "pending"
        flow["gatv2_prediction"] = None
        flow["gatv2_confidence"] = None
        self.completed_flows.append(flow)
        with self._pending_lock:
            self._pending.append(flow)
        log.info("[FLOW] Finalized %s packets=%d bytes=%d", flow["flow_id"], flow["total_packets"], flow["total_bytes"])
        self._schedule_event("flow_completed", flow)

    def _schedule_event(self, kind: str, payload: dict) -> None:
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(lambda: asyncio.create_task(chat_state.event(kind, payload)))

    async def _run(self) -> None:
        last_batch = time.monotonic()
        try:
            while True:
                await asyncio.sleep(1)
                self.tracker.expire()
                now = time.monotonic()
                if now - last_batch >= self.inference_window:
                    batch = self._take_pending()
                    if batch:
                        await self._analyze(batch)
                    last_batch = now
        except asyncio.CancelledError:
            return

    def _take_pending(self) -> list[dict]:
        with self._pending_lock:
            batch, self._pending = self._pending, []
        return batch

    async def _analyze(self, flows: list[dict]) -> None:
        if not getattr(gatv2_engine, "_is_loaded", False):
            error = "GATv2 model or preprocessing artifacts are unavailable; no prediction was produced."
            for flow in flows:
                flow["gatv2_status"] = "unavailable"
            await chat_state.event("gatv2_unavailable", {"error": error, "flow_ids": [f["flow_id"] for f in flows]})
            return

        inputs = []
        for flow in flows:
            edge = flow["features"]
            inputs.append({
                "flow_id": flow["flow_id"], "src_ip": flow["source_ip"], "dst_ip": flow["destination_ip"],
                "src_port": flow["source_port"], "dst_port": flow["destination_port"],
                "protocol": flow["protocol"], "duration": edge["Flow Duration"],
                "fwd_packets": edge["Total Fwd Packets"], "bwd_packets": edge["Total Backward Packets"],
                "flow_bytes_s": edge["Flow Bytes/s"], "flow_packets_s": edge["Flow Packets/s"],
            })
        try:
            results = await asyncio.to_thread(gatv2_engine.predict_flows, inputs)
            if len(results) != len(flows):
                raise RuntimeError(f"GATv2 returned {len(results)} results for {len(flows)} flows")
        except Exception as exc:
            log.exception("[GATV2] Inference failed")
            for flow in flows:
                flow["gatv2_status"] = "unavailable"
                flow["gatv2_error"] = str(exc)
            await chat_state.event("gatv2_unavailable", {"error": str(exc), "flow_ids": [f["flow_id"] for f in flows]})
            return

        for flow, result in zip(flows, results):
            anomaly = bool(result["is_anomaly"])
            prediction = "ATTACK" if anomaly else "BENIGN"
            confidence = float(result["confidence"]) / 100.0
            flow.update({"gatv2_status": "analyzed", "gatv2_prediction": prediction,
                         "gatv2_confidence": confidence, "gatv2_anomaly_probability": result["anomaly_probability"],
                         "graph_nodes": result["graph_nodes"], "graph_edges": result["graph_edges"]})
            self.analysis_count += 1
            self.anomaly_count += int(anomaly)
            self.last_prediction = prediction
            event = {"flow_id": flow["flow_id"], "username": flow["username"],
                     "source_ip": flow["source_ip"], "destination_ip": flow["destination_ip"],
                     "source_port": flow["source_port"], "destination_port": flow["destination_port"],
                     "protocol": flow["protocol"], "packets": flow["total_packets"], "bytes": flow["total_bytes"],
                     "duration": flow["duration"], "prediction": prediction,
                     "gatv2_prediction": prediction, "confidence": confidence,
                     "detection_source": "GATV2", "action": "ALERT" if anomaly else "OBSERVED"}
            await chat_state.event("gatv2_analysis", event)

    async def stop(self) -> None:
        if self.capture:
            await asyncio.to_thread(self.capture.stop)
        if self._capture_bootstrap and self._capture_bootstrap.is_alive():
            await asyncio.to_thread(self._capture_bootstrap.join, 1.0)
        if self._worker:
            self._worker.cancel()
            await asyncio.gather(self._worker, return_exceptions=True)
            self._worker = None
        self.tracker.expire(force=True)
        pending = self._take_pending()
        if pending:
            await self._analyze(pending)

    def status(self) -> dict:
        now = time.time()
        with self._stats_lock:
            recent = [(ts, size) for ts, size in self._recent_packets if now - ts <= 1.0]
            pps = len(recent)
            bps = sum(size for _, size in recent)
        capture_state = "unavailable"
        if self._capture_bootstrap and self._capture_bootstrap.is_alive():
            capture_state = "starting"
        elif self.capture and self.capture._thread and self.capture._thread.is_alive() and not self.capture.error:
            capture_state = "running"
        with self._pending_lock:
            pending = len(self._pending)
        return {"capture": capture_state, "capture_error": self.capture.error if self.capture else "not started",
                "interface": self.capture.interface if self.capture else None,
                "capture_filter": self.capture.bpf_filter if self.capture else None,
                "packets": self.packet_count, "bytes": self.byte_count, "packets_per_second": pps,
                "bytes_per_second": bps, "active_flows": self.tracker.active_snapshots(),
                "completed_flows": list(self.completed_flows), "gatv2": "available" if gatv2_engine._is_loaded else "unavailable",
                "gatv2_error": None if gatv2_engine._is_loaded else "Model/scalers did not load; see server log.",
                "gatv2_analyses": self.analysis_count, "gatv2_anomalies": self.anomaly_count,
                "latest_prediction": self.last_prediction, "pending_flows": pending,
                "inference_window_seconds": self.inference_window}


network_runtime = NetworkRuntime()
