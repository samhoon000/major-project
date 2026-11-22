"""Exercise the local policy check over actual HTTP and dashboard WebSocket sockets."""
import json
import threading
import time

import httpx
import pytest
import uvicorn
from websockets.sync.client import connect

from app import app
from backend import attack_lab
from backend.network.port_scan import PortScanMonitor, ScanPolicy, VERIFY_PATH
from backend.security import http_flood

VERIFICATION = "/api/attack-lab/verification"
STAGES = [
    "HTTP_TRAFFIC_OBSERVED", "HTTP_FLOOD_ATTACK_DETECTED", "HTTP_SECURITY_ALERT",
    "HTTP_MITIGATION_ACTIVATED", "HTTP_PROTECTION_VERIFIED",
]


@pytest.fixture
def server(monkeypatch):
    verifier = http_flood.HTTPPolicyVerification()
    monkeypatch.setattr(attack_lab, "policy_verification", verifier)
    monkeypatch.setattr(http_flood, "policy_verification", verifier)
    target_responses = []

    async def record_responses(scope, receive, send):
        async def record(message):
            if (scope.get("path") == http_flood.TARGET and message["type"] == "http.response.start"
                    and message["status"] in (200, 429)):
                target_responses.append((time.monotonic(), message["status"]))
            await send(message)

        await app(scope, receive, record)

    config = uvicorn.Config(record_responses, host="127.0.0.1", port=0, lifespan="off",
                            loop="asyncio", http="h11", ws="websockets-sansio", proxy_headers=False,
                            log_level="error", timeout_graceful_shutdown=3)
    instance = uvicorn.Server(config)
    thread = threading.Thread(target=instance.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 15
        while thread.is_alive() and not instance.started and time.monotonic() < deadline:
            time.sleep(0.01)
        assert instance.started
        port = instance.servers[0].sockets[0].getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        with httpx.Client(base_url=origin, timeout=4, trust_env=False) as client:
            yield client, origin, target_responses
            client.post(VERIFICATION + "/reset", headers={"Origin": origin}).raise_for_status()
    finally:
        instance.should_exit = True
        thread.join(8)
        assert not thread.is_alive()


def wait_for_snapshot(client, predicate, *, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snapshot = client.get(VERIFICATION).raise_for_status().json()
        if predicate(snapshot):
            return snapshot
        time.sleep(0.05)
    pytest.fail(f"Policy snapshot did not reach the expected state: {snapshot}")


def test_real_verification_repeatable_with_dashboard_events(server):
    client, origin, responses = server
    headers = {"Origin": origin}
    with connect(origin.replace("http:", "ws:") + "/ws/dashboard", origin=origin, proxy=None, open_timeout=4) as dashboard:
        assert json.loads(dashboard.recv(timeout=4))["type"] == "snapshot"
        for repetition in range(2):
            start_index = len(responses)
            config = {"rate": 1, "duration": 4, "concurrency": 1}
            run = client.post(VERIFICATION + "/start", headers=headers, json=config).raise_for_status().json()
            assert run["config"] == config
            assert run["running"] and not any(event["type"] in STAGES for event in run["timeline"])
            run_id = run["run_id"]
            live = wait_for_snapshot(client, lambda data: data["running"] and data["flood"]["successful"] > 0)
            assert live["flood"]["blocked"] == 0
            assert "HTTP_TRAFFIC_OBSERVED" in [event["type"] for event in live["timeline"]]
            assert client.post(VERIFICATION + "/start", headers=headers).status_code == 409
            finished = wait_for_snapshot(client, lambda data: not data["running"])
            assert finished["outcome"] == "complete"
            assert finished["elapsed_seconds"] >= 3
            assert finished["flood"]["generated"] == finished["flood"]["received"] == 4
            assert finished["flood"]["successful"] == finished["flood"]["accepted"] == 2
            assert finished["flood"]["blocked"] == finished["flood"]["rejected"] == 2
            assert finished["flood"]["failed"] == finished["flood"]["in_flight"] == 0
            assert finished["flood"]["generated"] - finished["flood"]["in_flight"] == (
                finished["flood"]["successful"] + finished["flood"]["blocked"] + finished["flood"]["failed"]
            )
            assert finished["latency_average_ms"] > 0
            assert any(point["total_rps"] > 0 for point in finished["samples"])
            assert finished["peak_rps"] == max(point["total_rps"] for point in finished["samples"])
            assert all(point["total_rps"] == point["accepted_rps"] + point["blocked_rps"]
                       for point in finished["samples"])
            wire = responses[start_index:]
            assert [status for _, status in wire] == [200, 200, 429, 429]
            assert all(second - first >= 0.85 for (first, _), (second, _) in zip(wire, wire[1:]))
            deadline = time.monotonic() + 5
            events = []
            while time.monotonic() < deadline:
                item = json.loads(dashboard.recv(timeout=max(0.05, deadline - time.monotonic())))
                if item.get("run_id") != run_id:
                    continue
                if item["type"] in STAGES:
                    events.append(item["type"])
                if item["type"] == "HTTP_FLOOD_TELEMETRY" and any(
                    event["type"] == "HTTP_PROTECTION_VERIFIED" for event in item["timeline"]
                ):
                    assert item["profile"] == "policy-verification"
                    break
            assert events == STAGES
            assert any(event["type"] == "HTTP_SECURITY_ALERT" and event["alert_id"]
                       and "HTTP Flood Detection" in event["detection_method"] for event in finished["timeline"])
            if repetition == 1:
                assert finished["blocked"]
                expired = wait_for_snapshot(client, lambda data: not data["blocked"])
                assert any(event["type"] == "HTTP_SOURCE_UNBLOCKED" and event["reason"] == "expiry"
                           for event in expired["timeline"])
            reset = client.post(VERIFICATION + "/reset", headers=headers).raise_for_status().json()
            assert reset["run_id"] != run_id and not reset["blocked"] and not reset["flood"]["generated"]


def test_ten_second_verification_accounts_for_real_responses(server):
    client, origin, responses = server
    headers = {"Origin": origin}
    config = {"rate": 1, "duration": 10, "concurrency": 1}
    started = client.post(VERIFICATION + "/start", headers=headers, json=config).raise_for_status().json()
    assert started["config"] == config
    assert started["limits"] == {"max_rate": 1, "max_requests": 10, "max_concurrency": 1, "max_duration": 10}
    finished = wait_for_snapshot(client, lambda data: not data["running"], timeout=13)
    assert finished["outcome"] == "complete"
    assert 9 <= finished["elapsed_seconds"] <= 12
    counts = finished["flood"]
    codes = [status for _, status in responses]
    assert codes == [200, 200] + [429] * 8
    assert counts["generated"] == counts["received"] == len(codes) == 10
    assert counts["successful"] == counts["accepted"] == codes.count(200)
    assert counts["blocked"] == counts["rejected"] == codes.count(429)
    assert counts["failed"] == counts["in_flight"] == 0
    assert all(second - first >= 0.85 for (first, _), (second, _) in zip(responses, responses[1:]))
    assert [event["type"] for event in finished["timeline"] if event["type"] in STAGES] == STAGES


def test_stop_active_reset_and_local_boundary(server):
    client, origin, responses = server
    headers = {"Origin": origin}
    assert client.post(VERIFICATION + "/start").status_code == 403
    assert client.post(VERIFICATION + "/start", headers={"Origin": "http://localhost:1"}).status_code == 403
    assert client.post(VERIFICATION + "/start", headers={**headers, "Forwarded": "for=192.0.2.10"}).status_code == 404
    for config in ({"rate": 2}, {"concurrency": 2}, {"target": "http://example.invalid"},
                   {"duration": 0}, {"duration": 11}, {"duration": "2"}, {"duration": 2.5}):
        assert client.post(VERIFICATION + "/start", headers=headers, json=config).status_code == 422
    assert client.get(http_flood.TARGET).status_code == 403
    assert client.get("/dashboard").raise_for_status().text.count('href="/attack-lab"') == 1
    for path in ("/dashboard/network", "/dashboard/applications", "/dashboard/chat", "/dashboard/settings"):
        assert client.get(path).status_code == 200
    lab_page = client.get("/attack-lab").raise_for_status().text
    assert "Attack Lifecycle" in lab_page and '<nav aria-label="Sentinel navigation">' not in lab_page
    assert 'id="hf-chart"' not in lab_page
    assert 'href="/dashboard/applications#http-flood-traffic"' in lab_page
    applications = client.get("/dashboard/applications").raise_for_status().text
    assert 'id="http-flood-traffic"' in applications
    assert 'id="hf-chart" viewBox="0 0 900 230"' in applications
    assert 'id="lab-start"' not in applications
    assert 'id="hf-duration" name="duration" type="number" value="4" min="1" max="10"' in lab_page

    client.post(VERIFICATION + "/start", headers=headers, json={"duration": 10}).raise_for_status()
    wait_for_snapshot(client, lambda data: data["flood"]["successful"] == 1)
    stopped = client.post(VERIFICATION + "/stop", headers=headers).raise_for_status().json()
    assert stopped["outcome"] == "stopped" and not stopped["running"]
    time.sleep(1.1)
    assert len(responses) == 1
    client.post(VERIFICATION + "/reset", headers=headers).raise_for_status()
    config = {"rate": 1, "duration": 2, "concurrency": 1}
    short = client.post(VERIFICATION + "/start", headers=headers, json=config).raise_for_status().json()
    assert short["config"] == config
    finished = wait_for_snapshot(client, lambda data: not data["running"])
    assert finished["outcome"] == "complete"
    assert finished["elapsed_seconds"] >= 1
    assert finished["flood"]["generated"] == 2 and finished["flood"]["successful"] == 2
    assert not finished["detected"] and not any(event["type"] in STAGES[1:] for event in finished["timeline"])
    assert [status for _, status in responses] == [200, 200, 200]
    client.post(VERIFICATION + "/reset", headers=headers).raise_for_status()
    client.post(VERIFICATION + "/start", headers=headers, json={"duration": 10}).raise_for_status()
    wait_for_snapshot(client, lambda data: data["flood"]["successful"] == 1)
    reset = client.post(VERIFICATION + "/reset", headers=headers).raise_for_status().json()
    assert not reset["running"] and not reset["flood"]["generated"]
    time.sleep(1.1)
    assert len(responses) == 4


def test_port_scan_fixture_enforces_only_the_dedicated_endpoint_over_http(server, monkeypatch):
    client, origin, _ = server
    headers = {"Origin": origin}
    monitor = PortScanMonitor(ScanPolicy(distinct_ports=3, failed_ports=2))
    monkeypatch.setattr(attack_lab.network_runtime, "port_scan", monitor)
    path = "/api/attack-lab/port-scan"
    assert client.post(VERIFY_PATH).status_code == 403
    assert client.post(VERIFY_PATH, headers=headers).status_code == 200

    # Model capture input in memory. Only the enforcement and telemetry HTTP
    # requests below use sockets.
    for port in (80, 81, 82):
        common = {"source_ip": "127.0.0.1", "destination_ip": "127.0.0.1", "protocol": "TCP"}
        monitor.observe({**common, "source_port": 48500, "destination_port": port,
                         "tcp_flags": "S", "tcp_sequence": 42})
        monitor.observe({**common, "source_port": port, "destination_port": 48500,
                         "tcp_flags": "RA", "tcp_ack": 43})
    monitor.sample()

    response = client.post(VERIFY_PATH, headers=headers)
    assert response.status_code == 429
    for _ in range(30):
        snapshot = client.get(path).raise_for_status().json()
        if snapshot["sources"][0]["verified"]:
            break
        time.sleep(0.02)
    assert snapshot["active_alerts"] == snapshot["active_mitigations"] == 1
    assert snapshot["sources"][0]["alert_id"] == response.json()["alert_id"]
    assert snapshot["sources"][0]["verified"]
    assert {item["observation_id"] for item in snapshot["events"]} == {snapshot["sources"][0]["observation_id"]}
    assert {item["alert_id"] for item in snapshot["events"] if item["alert_id"]} == {response.json()["alert_id"]}
    assert snapshot["samples"][-1]["unique_ports"] == 3
    assert [item["type"] for item in snapshot["events"]] == [
        "observed", "suspicious", "detected", "alert", "mitigation", "verified",
    ]
    assert client.get("/dashboard").status_code == 200
    assert 'id="port-scan-chart"' in client.get("/dashboard/applications").raise_for_status().text
    assert 'id="port-scan-check"' in client.get("/attack-lab").raise_for_status().text
