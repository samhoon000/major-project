"""Replay signed synthetic HTTP telemetry into a new, isolated local SQLite database."""

import argparse
import json
import secrets
import time
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from . import detection, protection, store
from .api import create_app, signature
from .protection_policy import Policy
from .schemas import INGEST_PATH


def request(route, *, status=200, method="GET", auth="authenticated", timestamp=None):
    return {
        "request_id": str(uuid4()), "timestamp": detection.now_ms() if timestamp is None else timestamp,
        "route": route, "method": method, "status": status, "duration_ms": 12.5, "auth": auth,
    }


def deliver(client, app, key, events):
    for start in range(0, len(events), 32):
        items = events[start:start + 32]
        body = json.dumps({
            "version": 1, "events": items,
            "delivery": {"queued": 0, "sent": start, "dropped": 0, "retries": 0, "failed_batches": 0},
        }).encode()
        timestamp, nonce = str(int(time.time())), str(uuid4())
        response = client.post(INGEST_PATH, content=body, headers={
            "content-type": "application/json", "x-telemetry-app": app,
            "x-telemetry-timestamp": timestamp, "x-telemetry-nonce": nonce,
            "x-telemetry-signature": signature(key, app, timestamp, nonce, body),
        })
        if response.status_code != 200:
            raise RuntimeError(f"Synthetic delivery failed with HTTP {response.status_code}")
        if response.json() != {"accepted": len(items), "duplicates": 0}:
            raise RuntimeError("Synthetic event was not inserted")


def normal_events():
    return [
        request("/api/auth/login", method="POST"),
        request("/api/courses/{course_id}/enroll", method="POST", status=201),
        request("/api/assignments/{assignment_id}/submit", method="POST", status=201),
    ]


def scenarios():
    return {
        "demo-login-local": [request("/api/auth/login", status=401, method="POST", auth="denied") for _ in range(5)],
        "demo-route-local": [request("/api/courses") for _ in range(31)],
        "demo-denial-local": [request("/api/students", status=403, auth="denied") for _ in range(5)],
        "demo-probe-local": [request("unmatched", status=404, auth="none") for _ in range(8)],
        "demo-error-local": [request("/api/profile") for _ in range(10)]
            + [request("/api/profile", status=503) for _ in range(10)],
        "demo-traffic-local": [request(f"/api/example-{index % 10}") for index in range(100)],
    }


def shadow_examples(path, collector, keys):
    block_app, limit_app = "demo-block-local", "demo-limit-local"
    login = lambda: request("/api/auth/login", method="POST", status=401, auth="denied")
    denial = lambda: request("/api/students", status=403, auth="denied")
    probe = lambda: request("unmatched", status=404, auth="none")
    deliver(collector, block_app, keys[block_app],
            [login() for _ in range(8)] + [denial() for _ in range(5)] + [probe() for _ in range(8)])
    deliver(collector, limit_app, keys[limit_app], [request("/api/students") for _ in range(40)])
    # Simulate a sustained burst without sleeping or contacting any external service.
    with store.connect(path) as db:
        db.execute("UPDATE http_detection_events SET arrived=arrived-4000 WHERE app=?", (limit_app,))
    deliver(collector, limit_app, keys[limit_app], [denial() for _ in range(5)])


def replay(path, shadow=False):
    # Refuse to replace any existing database, including the live collector database.
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=False)
    if shadow:
        protection.initialize(path)
        protection.change_mode(path, "shadow", "isolated replay")
    else:
        detection.initialize(path)
    traffic_app = "demo-traffic-local"
    sequences = scenarios()
    keys = {app: secrets.token_bytes(32) for app in (*sequences, "demo-normal-local")}
    if shadow:
        keys.update({app: secrets.token_bytes(32) for app in ("demo-block-local", "demo-limit-local")})
    with TestClient(create_app(path, keys)) as collector:
        deliver(collector, "demo-normal-local", keys["demo-normal-local"], normal_events())
        while detection.process(path):
            pass
        if detection.alert_snapshot(path, {})["alerts"]:
            raise RuntimeError("The normal workflow produced an alert")
        print("Normal login, enrollment, and submission: no alerts")
        baseline = [request(item["route"]) for item in sequences[traffic_app]]
        deliver(collector, traffic_app, keys[traffic_app], baseline)
        # The isolated demonstration compresses the prior five-minute baseline.
        with store.connect(path) as db:
            db.execute("UPDATE http_detection_events SET arrived=arrived-90000 WHERE app=?", (traffic_app,))
        for app, sequence in sequences.items():
            deliver(collector, app, keys[app], sequence)
        if shadow:
            shadow_examples(path, collector, keys)
        while detection.process(path):
            pass
    snapshot = detection.alert_snapshot(path, {})
    observed = {alert["rule"] for alert in snapshot["alerts"]}
    aggregate_rules = {"authorization_denials", "login_failures", "route_burst",
                       "route_probing", "server_errors", "traffic_spike"}
    if observed != aggregate_rules:
        raise RuntimeError(f"Unexpected demonstration rule coverage: {', '.join(sorted(observed))}")
    for alert in sorted(snapshot["alerts"], key=lambda item: item["rule"]):
        print(f"{alert['rule']}: {alert['evidence']['observed_count']} in {alert['evidence']['window_seconds']}s")
    if shadow:
        while protection.process(path, Policy()):
            pass
        view = protection.snapshot(path)
        proposals = {item["app"]: item for item in view["decisions"] if item["action"] in {"BLOCK", "RATE_LIMIT"}}
        if {app: item["action"] for app, item in proposals.items()} != {
            "demo-block-local": "BLOCK", "demo-limit-local": "RATE_LIMIT",
        } or any(item["enforced"] for item in view["decisions"]):
            raise RuntimeError("Unexpected shadow proposals")
        for app, item in sorted(proposals.items()):
            print(f"{app}: {item['action']} proposed, enforced={item['enforced']}")
    print(f"Demo database: {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path(f"data/http-detection-demo-{int(time.time())}.sqlite3"),
                        help="Path to a new demonstration database")
    parser.add_argument("--shadow", action="store_true", help="Run the Stage 3 shadow policy demonstration")
    args = parser.parse_args()
    replay(args.db.resolve(), shadow=args.shadow)


if __name__ == "__main__":
    main()
