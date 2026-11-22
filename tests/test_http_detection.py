import json
from dataclasses import replace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.security.demo_access import router as auth_router
from backend.telemetry import dashboard, detection, store
from backend.telemetry.api import create_app
from backend.telemetry.replay import deliver, normal_events, replay, request, scenarios
from backend.telemetry.rules import DEFAULT_RULES, configured_rules
from backend.telemetry.schemas import INGEST_PATH
from test_telemetry_ingest import signed, batch, NOW, ORIGIN, STREAM

APP = "northfield-test"
OTHER = "northfield-prod"
KEY = b"t" * 32
OTHER_KEY = b"p" * 32


@pytest.fixture
def path(tmp_path):
    path = tmp_path / "detection.sqlite3"
    detection.initialize(path)
    return path


@pytest.fixture
def collector(path):
    with TestClient(create_app(path, {APP: KEY, OTHER: OTHER_KEY})) as client:
        yield client


def drain(path, rules=DEFAULT_RULES):
    while detection.process(path, rules):
        pass
    return detection.alert_snapshot(path, {})


def failed_login(**updates):
    fields = {"method": "POST", "status": 401, "auth": "denied", **updates}
    return request("/api/auth/login", **fields)


def test_normal_workflow_and_low_evidence_do_not_alert(collector, path):
    events = normal_events()
    events += [failed_login(auth="anonymous") for _ in range(5)]
    events += [request("/api/auth/me", status=401, auth="denied") for _ in range(5)]
    events += [request("/api/students", status=403, auth="origin_denied") for _ in range(5)]
    events += [request("/api/profile", status=422, auth="denied") for _ in range(5)]
    events += [request("/api/data", status=503) for _ in range(9)]
    deliver(collector, APP, KEY, events)
    view = drain(path)
    assert view["alerts"] == []
    assert view["health"]["processed"] == len(events)


@pytest.mark.parametrize(("scenario", "rule", "count", "severity", "route"), [
    ("demo-login-local", "login_failures", 5, "medium", "/api/auth/login"),
    ("demo-route-local", "route_burst", 31, "low", "/api/courses"),
    ("demo-denial-local", "authorization_denials", 5, "medium", None),
    ("demo-probe-local", "route_probing", 8, "low", "unmatched"),
    ("demo-error-local", "server_errors", 10, "low", None),
])
def test_each_rule_persists_evidence(collector, path, scenario, rule, count, severity, route):
    events = scenarios()[scenario]
    deliver(collector, APP, KEY, events)
    view = drain(path)
    assert view["overview"]["active"] == 1
    alert, = view["alerts"]
    assert alert["rule"] == rule and alert["severity"] == severity
    assert alert["app"] == APP and alert["environment"] == "test" and alert["status"] == "open"
    evidence = alert["evidence"]
    assert evidence["observed_count"] == evidence["threshold"] == count
    assert evidence["route"] == route and evidence["subject"] is None
    assert evidence["quality"] == "aggregate_observation"
    assert len(evidence["requests"]) == min(count, detection.EVIDENCE_LIMIT)
    assert {item["request_id"] for item in evidence["requests"]} <= {event["request_id"] for event in events}


def test_baseline_and_error_proportions_prevent_false_positives(collector, path):
    exceptional = [request(f"/api/item-{index % 10}", status=503 if index < 10 else 200) for index in range(100)]
    deliver(collector, APP, KEY, exceptional[:10] + exceptional[10:])
    # With no local baseline, volume alone cannot trigger the spike rule.
    assert drain(path)["alerts"] == []
    # Preserve all 100 observations in the baseline, then send 100 current requests.
    with store.connect(path) as db:
        db.execute("UPDATE http_detection_events SET arrived=arrived-90000")
    deliver(collector, APP, KEY, scenarios()["demo-traffic-local"])
    alert, = drain(path)["alerts"]
    assert alert["rule"] == "traffic_spike"
    assert alert["evidence"]["baseline_count"] == 100
    assert alert["evidence"]["baseline_window_average"] == 20
    assert alert["evidence"]["observed_count"] == 100


def test_authenticated_apps_and_environments_remain_isolated(collector, path):
    deliver(collector, APP, KEY, [failed_login() for _ in range(3)])
    deliver(collector, OTHER, OTHER_KEY, [failed_login() for _ in range(3)])
    assert drain(path)["alerts"] == []
    deliver(collector, OTHER, OTHER_KEY, [failed_login() for _ in range(2)])
    alert, = drain(path)["alerts"]
    assert alert["app"] == OTHER and alert["environment"] == "production"
    assert detection.alert_snapshot(path, {"app": APP})["alerts"] == []


def test_scoped_sensitive_routes_and_repeated_policy_rate_limits(path):
    route = "/api/courses/{course_id}/access"
    subject = "s1_" + "1" * 64
    other = "s1_" + "2" * 64
    rules = tuple(replace(rule, threshold=3) if rule.id == "sensitive_route_frequency" else rule
                  for rule in DEFAULT_RULES)
    normal = [dict(request(route, method="POST"), subject=subject) for _ in range(3)]
    denied = [dict(request(route, method="POST", status=429, auth="rate_limited"),
                   subject=other, mitigation_applied=True, policy_revision=2) for _ in range(3)]
    unrelated = dict(denied[0], request_id=request(route)["request_id"], mitigation_applied=False)
    staging = "northfield-staging"
    with TestClient(create_app(path, {staging: KEY, OTHER: OTHER_KEY})) as collector:
        deliver(collector, staging, KEY, normal + denied[:2] + [unrelated])
        alert, = drain(path, rules)["alerts"]
        assert alert["rule"] == "sensitive_route_frequency" and alert["evidence"]["subject"] == subject
        deliver(collector, OTHER, OTHER_KEY, denied[-1:])
        assert len(drain(path, rules)["alerts"]) == 1
        deliver(collector, staging, KEY, denied[-1:])
    alert, = [item for item in drain(path, rules)["alerts"] if item["rule"] == "repeated_policy_rate_limits"]
    assert alert["evidence"]["confidence"] == "high"
    assert alert["evidence"]["subject"] == other and alert["evidence"]["method"] == "POST"
    assert {event["request_id"] for event in alert["evidence"]["requests"]} == {
        event["request_id"] for event in denied
    }


def test_out_of_order_sender_timestamps_preserved_using_arrival_windows(collector, path):
    first = failed_login(timestamp=NOW * 1000)
    delayed = failed_login(timestamp=NOW * 1000 - 120000)
    deliver(collector, APP, KEY, [first, delayed, *[failed_login() for _ in range(3)]])
    alert, = drain(path)["alerts"]
    by_id = {item["request_id"]: item for item in alert["evidence"]["requests"]}
    assert by_id[delayed["request_id"]]["timestamp"] == delayed["timestamp"]
    assert by_id[delayed["request_id"]]["received_at"] >= by_id[first["request_id"]]["received_at"]


def test_replays_and_stage1_eviction_cannot_duplicate_processing(collector, path, monkeypatch):
    monkeypatch.setattr(store, "MAX_ROWS_PER_APP", 2)
    events = [failed_login() for _ in range(5)]
    first = signed(batch(*events), app=APP, key=KEY)
    assert collector.post(INGEST_PATH, **first).status_code == 200
    assert collector.post(INGEST_PATH, **first).status_code == 409
    assert collector.post(INGEST_PATH, **signed(batch(*events), app=APP, key=KEY)).status_code == 200
    drain(path)
    detection.initialize(path)
    view = drain(path)
    assert view["health"]["processed"] == 5
    assert view["overview"]["total"] == 1


def test_cooldown_merges_repeats_and_respects_false_positive(collector, path):
    deliver(collector, APP, KEY, [failed_login() for _ in range(5)])
    initial, = drain(path)["alerts"]
    deliver(collector, APP, KEY, [failed_login() for _ in range(2)])
    ongoing, = drain(path)["alerts"]
    assert ongoing["id"] == initial["id"] and ongoing["evidence"]["observed_count"] == 7
    assert detection.set_status(path, initial["id"], "false_positive")
    deliver(collector, APP, KEY, [failed_login() for _ in range(2)])
    closed, = drain(path)["alerts"]
    assert closed["status"] == "false_positive" and closed["evidence"]["observed_count"] == 7
    with store.connect(path) as db:
        db.execute("UPDATE http_detection_events SET arrived=arrived-180000")
        db.execute("UPDATE http_alerts SET last_signal=last_signal-180000")
    deliver(collector, APP, KEY, [failed_login() for _ in range(5)])
    assert drain(path)["overview"]["total"] == 2


def test_processing_failure_rolls_back_and_pending_survives_restart(collector, path, monkeypatch):
    deliver(collector, APP, KEY, [failed_login() for _ in range(5)])
    original = detection.record_signal

    def fail_after_write(db, event, rule, signal):
        original(db, event, rule, signal)
        if db.execute("SELECT 1 FROM http_alerts").fetchone():
            raise RuntimeError("synthetic fault")

    with monkeypatch.context() as failing:
        failing.setattr(detection, "record_signal", fail_after_write)
        with pytest.raises(RuntimeError) as error:
            detection.process(path)
        detection.record_failure(path, error.value)
        deliver(collector, APP, KEY, [request("/health-check")])
    degraded = detection.alert_snapshot(path, {})
    assert degraded["health"]["status"] == "degraded"
    assert degraded["health"]["processed"] == 0 and degraded["health"]["pending"] == 6
    assert degraded["alerts"] == []
    assert "synthetic fault" not in json.dumps(degraded)
    detection.initialize(path)
    recovered = drain(path)
    assert recovered["health"]["status"] == "running"
    assert recovered["health"]["processed"] == 6 and recovered["health"]["errors"] == 1
    assert recovered["overview"]["total"] == 1


def test_rule_configuration_can_disable_and_change_thresholds(path, collector, tmp_path, monkeypatch):
    config = tmp_path / "http.toml"
    config.write_text("[login_failures]\nenabled = false\n[route_burst]\nthreshold = 2\n", encoding="utf-8")
    monkeypatch.setenv("HTTP_DETECTION_CONFIG", str(config))
    rules = configured_rules()
    deliver(collector, APP, KEY, [failed_login() for _ in range(5)])
    alert, = drain(path, rules)["alerts"]
    assert alert["rule"] == "route_burst" and alert["evidence"]["threshold"] == 2
    config.write_text("[route_burst]\nwindow_seconds = true\n", encoding="utf-8")
    with pytest.raises(ValueError):
        configured_rules()


def test_private_dashboard_stream_filters_and_operator_actions(collector, path, monkeypatch):
    monkeypatch.setenv("HTTP_TELEMETRY_DB", str(path))
    monkeypatch.setenv("ADMIN_TOKEN", "stage2-synthetic-operator")
    monkeypatch.setattr(dashboard, "INTERVAL", 0.05)
    deliver(collector, APP, KEY, [failed_login() for _ in range(5)])
    deliver(collector, OTHER, OTHER_KEY, scenarios()["demo-probe-local"])
    alert = next(item for item in drain(path)["alerts"] if item["app"] == APP)
    action = f"/api/telemetry/alerts/{alert['id']}/acknowledge"
    ui = FastAPI()
    ui.include_router(auth_router)
    ui.include_router(dashboard.router)
    with TestClient(ui, base_url=ORIGIN, client=("127.0.0.1", 50000)) as operator:
        assert operator.post(action).status_code == 401
        with pytest.raises(WebSocketDisconnect), operator.websocket_connect(STREAM, headers={"Origin": ORIGIN}):
            pytest.fail("Anonymous socket opened")
        login = operator.post("/api/auth/login", json={"token": "stage2-synthetic-operator"}, headers={"Origin": ORIGIN})
        headers = {"Origin": ORIGIN, "X-CSRF-Token": login.headers["X-CSRF-Token"]}
        assert "Detection Mode: Alert Only" in operator.get("/dashboard/applications").text
        filters = "?app=northfield-test&rule=login_failures&severity=medium&status=open"
        with operator.websocket_connect(STREAM + filters, headers={"Origin": ORIGIN}) as ws:
            snapshot = ws.receive_json()["detection"]
            assert snapshot["mode"] == "alert_only" and snapshot["overview"]["total"] == 2
            assert snapshot["alerts"] == [alert]
        assert operator.post(action, headers={"Origin": ORIGIN}).status_code == 403
        assert operator.post(action, headers={**headers, "Origin": "https://outside.invalid"}).status_code == 404
        assert operator.post(action, headers=headers).json() == {"status": "acknowledged"}
        resolve = f"/api/telemetry/alerts/{alert['id']}/resolve"
        assert operator.post(resolve, headers=headers).json() == {"status": "resolved"}
        with operator.websocket_connect(STREAM + "?status=resolved", headers={"Origin": ORIGIN}) as ws:
            resolved, = ws.receive_json()["detection"]["alerts"]
            assert resolved["id"] == alert["id"]
        probe = next(item for item in detection.alert_snapshot(path, {})["alerts"] if item["app"] == OTHER)
        assert operator.post(f"/api/telemetry/alerts/{probe['id']}/false-positive", headers=headers).status_code == 200
        assert detection.alert_snapshot(path, {})["overview"]["active"] == 0


def test_replay_proves_normal_and_synthetic_behavior_with_private_data_rejected(tmp_path, path, collector):
    demo = tmp_path / "demo.sqlite3"
    replay(demo)
    with pytest.raises(FileExistsError):
        replay(demo)
    candidate = failed_login()
    candidate["subject"] = "private-user@example.invalid"
    response = collector.post(INGEST_PATH, **signed(batch(candidate), app=APP, key=KEY))
    assert response.status_code == 422 and "private-user" not in response.text
    assert drain(path)["health"]["processed"] == 0


def test_processed_evidence_expires_while_unprocessed_events_remain(path, collector):
    deliver(collector, APP, KEY, [failed_login() for _ in range(5)])
    drain(path)
    deliver(collector, APP, KEY, [request("/pending")])
    with store.connect(path) as db:
        db.execute("UPDATE http_detection_events SET arrived=arrived-?", (detection.QUEUE_HISTORY_MS + 5000,))
        db.execute("UPDATE http_alerts SET last_seen=last_seen-?", (detection.ALERT_HISTORY_MS + 5000,))
        db.execute("UPDATE http_detection_state SET last_cleanup=NULL")
    assert detection.alert_snapshot(path, {})["health"]["pending"] == 1
    view = drain(path, tuple(replace(rule, enabled=False) for rule in DEFAULT_RULES))
    assert view["health"]["processed"] == 6
    assert view["alerts"] == []
