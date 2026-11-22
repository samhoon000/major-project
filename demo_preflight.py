"""Read-only checks for a running Sentinel instance on localhost."""

import argparse
import json
from math import isfinite

import httpx
from websockets.sync.client import connect
from websockets.exceptions import WebSocketException


def main(port):
    origin = f"http://127.0.0.1:{port}"
    failures = []

    def report(label, status, detail):
        print(f"{status:<11} {label} - {detail}")
        if status == "FAIL":
            failures.append(label)

    with httpx.Client(base_url=origin, trust_env=False, timeout=4) as client:
        for label, path, marker in (
            ("Dashboard", "/dashboard", "Detection pipeline"),
            ("Standalone Lab", "/attack-lab", "Attack Lifecycle"),
        ):
            try:
                response = client.get(path).raise_for_status()
                if marker not in response.text:
                    raise ValueError("Expected page content was absent")
                report(label, "PASS", origin + path)
            except (httpx.HTTPError, ValueError) as error:
                report(label, "FAIL", str(error))

        try:
            network = client.get("/api/network/state").raise_for_status().json()
            report("Backend", "PASS", "Network state responds")
            capture = network.get("capture", "unknown")
            report("Packet capture", "PASS" if capture == "running" else "UNAVAILABLE",
                   f"{capture}; {network.get('selected_adapter_name') or 'adapter not reported'}")
            if network.get("gatv2") != "available":
                report("Server GATv2 model", "FAIL", "Server reports the model unavailable")
            else:
                report("Server GATv2 model", "PASS", "Server reports the checkpoint loaded")
        except (httpx.HTTPError, ValueError) as error:
            report("Backend", "FAIL", str(error))

        try:
            state = client.get("/api/attack-lab/verification").raise_for_status().json()
            target = client.get("/api/attack-lab/http-flood-target")
            if target.status_code != 403 or state.get("profile") != "policy-verification":
                raise ValueError("Expected an isolated target and a policy verification profile")
            report("HTTP guard", "PASS", "Verification state reachable and target denies unauthenticated traffic")
            verified = any(event["type"] == "HTTP_PROTECTION_VERIFIED" for event in state["timeline"])
            report("Latest verification", "PASS" if verified else "UNAVAILABLE",
                   "Subsequent HTTP 429 recorded" if verified else "No verified result in the current lab state")
        except (httpx.HTTPError, ValueError) as error:
            report("HTTP guard", "FAIL", str(error))

    try:
        with connect(f"ws://127.0.0.1:{port}/ws/dashboard", origin=origin, proxy=None,
                     open_timeout=4, close_timeout=2) as stream:
            if json.loads(stream.recv(timeout=4)).get("type") != "snapshot":
                raise ValueError("Expected an initial dashboard snapshot")
        report("Dashboard stream", "PASS", "Initial WebSocket snapshot received")
    except (OSError, ValueError, WebSocketException) as error:
        report("Dashboard stream", "FAIL", str(error))

    try:
        from backend.config import GATV2_MODEL_PATH
        from backend.network.gatv2_inference import gatv2_engine

        if not GATV2_MODEL_PATH.is_file() or not gatv2_engine._is_loaded:
            raise ValueError("Checkpoint or model assets unavailable")
        report("Local checkpoint", "PASS", GATV2_MODEL_PATH.name)
        # This fixture exercises inference in this process without publishing a dashboard event.
        results = gatv2_engine.predict_flows([{
            "src_ip": "192.0.2.10", "dst_ip": "192.0.2.20", "duration": 1_000_000,
            "fwd_packets": 3, "bwd_packets": 3, "flow_bytes_s": 800, "flow_packets_s": 6,
        }])
        if len(results) != 1 or not isfinite(results[0]["anomaly_probability"]):
            raise ValueError("Model did not return a finite probability")
        report("GATv2 inference", "PASS", f"Read-only fixture probability {results[0]['anomaly_probability']:.4f}")
    except Exception as error:
        report("GATv2 inference", "FAIL", str(error))
    return int(bool(failures))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8001)
    raise SystemExit(main(parser.parse_args().port))
