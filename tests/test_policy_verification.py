"""Exercise the local policy check over actual HTTP and dashboard WebSocket sockets."""
import asyncio
import json
import threading
import time

import httpx
import pytest
import uvicorn
from websockets.exceptions import InvalidStatus
from websockets.sync.client import connect

from app import app
from backend import attack_lab
from backend.network.port_scan import PortScanMonitor, ScanPolicy, VERIFY_PATH
from backend.security import http_flood

VERIFICATION = "/api/attack-lab/verification"
TRAFFIC = VERIFICATION + "/traffic"
ADMIN_TOKEN = "local-policy-check-test-token"
STAGES = [
    "HTTP_TRAFFIC_OBSERVED", "HTTP_FLOOD_ATTACK_DETECTED", "HTTP_SECURITY_ALERT",
    "HTTP_MITIGATION_ACTIVATED", "HTTP_PROTECTION_VERIFIED",
]


@pytest.fixture
def delay_target_response():
    return threading.Event()


@pytest.fixture
def server(monkeypatch, delay_target_response):
    verifier = http_flood.HTTPPolicyVerification()
    monkeypatch.setattr(attack_lab, "policy_verification", verifier)
    monkeypatch.setattr(http_flood, "policy_verification", verifier)
    monkeypatch.setenv("ADMIN_TOKEN", ADMIN_TOKEN)
    target_responses = []

    async def record_responses(scope, receive, send):
        async def record(message):
            if (scope.get("path") == http_flood.TARGET and message["type"] == "http.response.start"
                    and message["status"] in (200, 429)):
                target_responses.append((time.monotonic(), message["status"]))
                if delay_target_response.is_set():
                    await asyncio.sleep(1.3)
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
            client.post(VERIFICATION + "/reset", headers=sign_in(client, origin)).raise_for_status()
    finally:
        instance.should_exit = True
        thread.join(8)
        assert not thread.is_alive()


def sign_in(client, origin):
    headers = {"Origin": origin}
    response = client.post("/api/auth/login", headers=headers, json={"token": ADMIN_TOKEN}).raise_for_status()
    return {**headers, "X-CSRF-Token": response.headers["X-CSRF-Token"]}


def wait_for_snapshot(client, predicate, *, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snapshot = client.get(VERIFICATION).raise_for_status().json()
        if predicate(snapshot):
            return snapshot
        time.sleep(0.05)
    pytest.fail(f"Policy snapshot did not reach the expected state: {snapshot}")


def assert_traffic_counts(snapshot, codes):
    buckets = snapshot["buckets"]
    assert snapshot["type"] == "HTTP_POLICY_TRAFFIC" and snapshot["window_seconds"] == 60
    start = int(snapshot["snapshot_at"]) - 60
    assert [bucket["timestamp"] for bucket in buckets] == list(range(start, start + 61))
    assert all(b["total_rps"] == b["accepted_rps"] + b["blocked_rps"] for b in buckets)
    accepted, blocked = codes.count(200), codes.count(429)
    assert snapshot["totals"] == {"total": len(codes), "accepted": accepted, "blocked": blocked}
    assert sum(b["accepted_rps"] for b in buckets) == accepted
    assert sum(b["blocked_rps"] for b in buckets) == blocked


def test_idle_ticks_and_reconnect_without_starting_a_lab_run(server):
    client, origin, responses = server
    url = origin.replace("http:", "ws:") + "/ws/dashboard?view=http-flood-traffic"
    with pytest.raises(InvalidStatus) as rejected:
        with connect(url, origin="https://other.example", proxy=None, open_timeout=4):
            pass
    assert rejected.value.response.status_code == 403
    with connect(url, origin=origin, proxy=None, open_timeout=4) as dashboard:
        first = json.loads(dashboard.recv(timeout=4))
        next_tick = json.loads(dashboard.recv(timeout=4))
        assert_traffic_counts(first, [])
        assert_traffic_counts(next_tick, [])
        assert next_tick["snapshot_at"] - first["snapshot_at"] >= 0.85
        assert next_tick["buckets"][0]["timestamp"] > first["buckets"][0]["timestamp"]
    assert_traffic_counts(client.get(TRAFFIC).raise_for_status().json(), [])
    assert client.get(TRAFFIC, headers={"Forwarded": "for=192.0.2.10"}).status_code == 404
    with connect(url, origin=origin, proxy=None, open_timeout=4) as dashboard:
        reconnected = json.loads(dashboard.recv(timeout=4))
        assert reconnected["snapshot_at"] >= next_tick["snapshot_at"]
        assert_traffic_counts(reconnected, [])
    assert responses == []


def test_exact_window_boundary_and_status_filter():
    verifier = http_flood.HTTPPolicyVerification()
    now = 100.9
    verifier.wall_clock = lambda: now
    verifier.record_traffic_response(100.25, 200)
    verifier.record_traffic_response(100.8, 429)
    verifier.record_traffic_response(100.8, 500)
    now = 160.5
    partially_expired = verifier.traffic_snapshot()
    assert_traffic_counts(partially_expired, [429])
    assert partially_expired["buckets"][0] == {
        "timestamp": 100, "total_rps": 1, "accepted_rps": 0, "blocked_rps": 1,
    }
    now = 160.9
    assert_traffic_counts(verifier.traffic_snapshot(), [])
    assert verifier.traffic_responses == []


def test_real_verification_repeatable_with_dashboard_events(server):
    client, origin, responses = server
    headers = sign_in(client, origin)
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
            assert_traffic_counts(client.get(TRAFFIC).raise_for_status().json(), [status for _, status in responses])


@pytest.mark.parametrize("request_count", [1, 5, 10, 25])
def test_selected_request_count_accounts_for_real_responses(server, request_count):
    client, origin, responses = server
    headers = sign_in(client, origin)
    config = {} if request_count == 1 else {"request_count": request_count}
    started = client.post(VERIFICATION + "/start", headers=headers, json=config).raise_for_status().json()
    assert started["config"] == {"rate": 1, "request_count": request_count, "concurrency": 1}
    assert started["request_count"] == request_count
    assert started["limits"] == {"max_rate": 1, "max_requests": 25, "max_concurrency": 1, "max_duration": 27}
    if request_count > 1:
        live = wait_for_snapshot(client, lambda data: data["running"] and data["flood"]["successful"] > 0)
        assert 0 < live["flood"]["generated"] < live["request_count"]
    if request_count == 25:
        url = origin.replace("http:", "ws:") + "/ws/dashboard?view=http-flood-traffic"
        with connect(url, origin=origin, proxy=None, open_timeout=4) as dashboard:
            in_progress = json.loads(dashboard.recv(timeout=4))
            assert 0 < in_progress["totals"]["total"] < request_count
    if request_count >= 5:
        wait_for_snapshot(client, lambda data: data["running"] and data["blocked"])
        assert client.get("/dashboard/settings").status_code == 200
        assert client.get("/chat").status_code == 200
    finished = wait_for_snapshot(client, lambda data: not data["running"], timeout=request_count + 2)
    assert finished["outcome"] == "complete"
    assert request_count - 1 <= finished["elapsed_seconds"] <= request_count + 2
    counts = finished["flood"]
    codes = [status for _, status in responses]
    traffic = client.get(TRAFFIC).raise_for_status().json()
    assert_traffic_counts(traffic, codes)
    expected_first_codes = [200] if request_count == 1 else [200, 200, 429, 429]
    assert codes[:4] == expected_first_codes
    assert counts["generated"] == counts["received"] == len(codes) == request_count
    assert counts["successful"] == counts["accepted"] == codes.count(200)
    assert counts["blocked"] == counts["rejected"] == codes.count(429)
    assert counts["failed"] == counts["in_flight"] == 0
    assert all(second - first >= 0.85 for (first, _), (second, _) in zip(responses, responses[1:]))
    events = [event["type"] for event in finished["timeline"]]
    if request_count == 1:
        assert not finished["detected"] and not any(stage in events for stage in STAGES[1:])
    else:
        assert finished["detection_rps"] >= finished["thresholds"]["block_rps"]
        assert all(stage in events for stage in STAGES)
    assert traffic["thresholds"]["block_rps"] == finished["thresholds"]["block_rps"]
    if request_count == 5:
        client.post(VERIFICATION + "/reset", headers=headers).raise_for_status()
        assert_traffic_counts(client.get(TRAFFIC).raise_for_status().json(), codes)
        client.post(VERIFICATION + "/start", headers=headers, json={"request_count": 1}).raise_for_status()
        wait_for_snapshot(client, lambda data: not data["running"])
        all_codes = [status for _, status in responses]
        assert all_codes == codes + [200]
        assert_traffic_counts(client.get(TRAFFIC).raise_for_status().json(), all_codes)
        url = origin.replace("http:", "ws:") + "/ws/dashboard?view=http-flood-traffic"
        with connect(url, origin=origin, proxy=None, open_timeout=4) as dashboard:
            initial = json.loads(dashboard.recv(timeout=4))
            continued = json.loads(dashboard.recv(timeout=4))
            assert_traffic_counts(initial, all_codes)
            assert_traffic_counts(continued, all_codes)
            assert continued["snapshot_at"] > initial["snapshot_at"]
            assert continued["buckets"][-1]["total_rps"] == 0


def test_target_timeout_is_failed_and_never_counted_as_http_rejection(server, delay_target_response):
    client, origin, _ = server
    delay_target_response.set()
    client.post(VERIFICATION + "/start", headers=sign_in(client, origin),
                json={"request_count": 5}).raise_for_status()
    finished = wait_for_snapshot(client, lambda data: not data["running"])
    assert finished["outcome"] == "error"
    assert finished["error"].startswith("ReadTimeout")
    counts = finished["flood"]
    assert counts["generated"] == counts["failed"] == 1
    assert counts["blocked"] == counts["successful"] == counts["in_flight"] == 0
    assert not finished["detected"]


def test_stop_active_reset_and_local_boundary(server):
    client, origin, responses = server
    assert client.post(VERIFICATION + "/start").status_code == 403
    assert client.post(VERIFICATION + "/start", headers={"Origin": "http://localhost:1"}).status_code == 403
    for action in ("start", "stop", "reset"):
        assert client.post(VERIFICATION + "/" + action, headers={"Origin": origin}).status_code == 401
    headers = sign_in(client, origin)
    for action in ("start", "stop", "reset"):
        assert client.post(VERIFICATION + "/" + action, headers={"Origin": origin}).status_code == 403
        assert client.post(VERIFICATION + "/" + action,
                           headers={**headers, "Forwarded": "for=192.0.2.10"}).status_code == 404
    for config in ({"rate": 2}, {"concurrency": 2}, {"target": "http://example.invalid"},
                   {"duration": 0}, {"duration": 11}, {"duration": "2"}, {"duration": 2.5},
                   {"request_count": 0}, {"request_count": -1}, {"request_count": 26},
                   {"request_count": 1.5}, {"request_count": "5"}, {"request_count": None},
                   {"request_count": 5, "duration": 4}):
        assert client.post(VERIFICATION + "/start", headers=headers, json=config).status_code == 422
    assert client.get(http_flood.TARGET).status_code == 403
    assert client.get("/dashboard").raise_for_status().text.count('href="/attack-lab"') == 1
    for path in ("/dashboard/network", "/dashboard/applications", "/dashboard/chat", "/dashboard/settings"):
        assert client.get(path).status_code == 200
    lab_page = client.get("/attack-lab").raise_for_status().text
    assert "Attack Lifecycle" in lab_page and '<nav aria-label="Sentinel navigation">' not in lab_page
    assert 'aria-label="Administrator sign-in"' in lab_page and 'src="/api/auth/ui.js"' in lab_page
    assert 'id="hf-chart"' not in lab_page
    assert 'href="/dashboard/applications#http-flood-traffic"' in lab_page
    applications = client.get("/dashboard/applications").raise_for_status().text
    assert 'id="http-flood-traffic"' in applications
    assert 'id="hf-chart" viewBox="0 0 900 230"' in applications
    assert 'id="lab-start"' not in applications
    assert 'id="hf-request-count" name="request_count" type="number" value="1" min="1" max="25"' in lab_page

    client.post(VERIFICATION + "/start", headers=headers, json={"request_count": 25}).raise_for_status()
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
