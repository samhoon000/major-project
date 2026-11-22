import json
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.security.demo_access import router as auth_router
from backend.telemetry import dashboard, detection, protection, store
from backend.telemetry.api import create_app
from backend.telemetry.protection_policy import Exemptions, Policy
from backend.telemetry.replay import deliver, normal_events, replay, request
from test_telemetry_ingest import ORIGIN, STREAM, batch, signed
from backend.telemetry.schemas import INGEST_PATH


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "shadow.sqlite3"
    protection.initialize(path)
    return path


def drain(path, policy=None, now=None):
    policy = policy or Policy()
    clock = detection.now_ms if now is None else lambda: now
    while protection.process(path, policy, clock=clock):
        pass
    return protection.snapshot(path, now=clock())


def alert(db, app, rule, now, route, count, *, sample_route=None):
    severity = "medium" if rule in {"login_failures", "authorization_denials"} else "low"
    record = {
        "route": route, "observed_count": count, "window_seconds": 60, "quality": "aggregate_observation",
        "requests": [{"route": sample_route or route, "request_id": str(uuid4()), "received_at": now - delay}
                     for delay in (0, 1000, 2000, 3000, 4000)],
    }
    alert_id = str(uuid4())
    with store.connect(db) as connection:
        connection.execute("""
            INSERT INTO http_alerts VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)
        """, (alert_id, app, rule, route or "", severity, now - 4000, now, now, now, json.dumps(record)))
    return alert_id


def triad(db, start, apps=("northfield-local",) * 3):
    login, authorization, probe = apps
    alert(db, login, "login_failures", start, "/api/auth/login", 8)
    alert(db, authorization, "authorization_denials", start + 1, None, 5, sample_route="/api/students")
    alert(db, probe, "route_probing", start + 2, "unmatched", 8)


def test_default_alert_only_and_reserved_modes_cannot_be_enabled(db):
    now = detection.now_ms()
    triad(db, now)
    assert not protection.change_mode(db, "block", "test")
    assert not protection.change_mode(db, "challenge", "test")
    view = drain(db, now=now + 100)
    assert view["mode"] == "alert_only" and view["decisions"] == []
    assert view["health"]["processed"] == 3


def test_signed_replay_exercises_normal_six_rules_and_combined_proposals(tmp_path):
    path = tmp_path / "replayed.sqlite3"
    replay(path, shadow=True)
    view = protection.snapshot(path)
    assert view["mode"] == "shadow"
    assert not any(item["app"] == "demo-normal-local" for item in view["decisions"])
    assert {item["action"] for item in view["decisions"]} == {"MONITOR", "RATE_LIMIT", "BLOCK"}
    assert {item["app"] for item in view["decisions"] if item["action"] == "MONITOR"} >= {
        "demo-login-local", "demo-route-local", "demo-denial-local", "demo-probe-local",
        "demo-error-local", "demo-traffic-local",
    }
    for item in view["decisions"]:
        assert not item["enforced"] and not item["evidence"]["subject_available"]
        assert item["trigger_request_id"] and item["evidence"]["signals"]
    block, = [item for item in view["decisions"] if item["action"] == "BLOCK"]
    assert {signal["rule"] for signal in block["evidence"]["signals"]} == {
        "login_failures", "authorization_denials", "route_probing"
    }
    assert block["expires"] - block["created"] == 120_000


def test_scope_isolation_exemptions_admin_and_nonsecurity_volume(db):
    now = detection.now_ms()
    assert protection.change_mode(db, "shadow", "test", clock=lambda: now)
    triad(db, now + 1, ("first-local", "second-local", "third-local"))
    triad(db, now + 10, ("allowed-local",) * 3)
    triad(db, now + 20, ("exempt-local",) * 3)
    alert(db, "volume-local", "route_burst", now + 30, "/api/courses", 150)
    alert(db, "volume-local", "traffic_spike", now + 31, None, 200, sample_route="/api/courses")
    alert(db, "operator-local", "route_burst", now + 35, "/api/telemetry/alerts", 150)
    policy = Policy(applications={"allowed-local": Exemptions(allowlisted=True),
                                  "exempt-local": Exemptions(rules=["route_probing"])})
    view = drain(db, policy, now + 100)
    assert not any(item["action"] in {"BLOCK", "RATE_LIMIT"} for item in view["decisions"])
    assert {item["action"] for item in view["decisions"] if item["app"] == "allowed-local"} == {"ALLOW"}
    assert {item["action"] for item in view["decisions"] if item["app"] == "volume-local"} == {"MONITOR"}
    assert any(item["app"] == "operator-local" and item["action"] == "ALLOW" for item in view["decisions"])


def test_route_rate_limit_requires_same_route_sustained_denial_corroboration(db):
    now = detection.now_ms()
    protection.change_mode(db, "shadow", "test", clock=lambda: now)
    alert(db, "cross-route-local", "route_burst", now, "/api/courses", 42)
    alert(db, "cross-route-local", "authorization_denials", now + 1, None, 5, sample_route="/api/students")
    alert(db, "same-route-local", "route_burst", now, "/api/students", 42)
    alert(db, "same-route-local", "authorization_denials", now + 1, None, 5, sample_route="/api/students")
    view = drain(db, now=now + 10)
    limit, = [item for item in view["decisions"] if item["action"] == "RATE_LIMIT"]
    assert limit["app"] == "same-route-local" and limit["route"] == "/api/students"
    assert limit["evidence"]["proposed_requests_per_minute"] == 60


def test_proposal_expiry_no_extension_and_durable_emergency(db):
    now = detection.now_ms()
    protection.change_mode(db, "shadow", "test", clock=lambda: now)
    triad(db, now + 1)
    block, = [item for item in drain(db, now=now + 20)["decisions"] if item["action"] == "BLOCK"]
    triad(db, now + 1000)
    view = drain(db, now=now + 2000)
    assert view["totals"]["proposed_blocks"] == 1
    assert next(item for item in view["decisions"] if item["id"] == block["id"])["expires"] == block["expires"]
    expired = protection.snapshot(db, now=block["expires"])
    assert expired["totals"]["expired_block_proposals"] == 1
    assert not protection.dismiss(db, block["id"], "test", clock=lambda: block["expires"])
    assert protection.change_mode(db, "emergency-disable", "test", clock=lambda: now + 3000)
    protection.initialize(db)
    assert not protection.change_mode(db, "shadow", "test")
    triad(db, now + 4000)
    view = drain(db, now=now + 5000)
    assert view["mode"] == "alert_only" and view["emergency"]
    assert next(item for item in view["decisions"] if item["id"] == block["id"])["status"] == "dismissed"
    assert {item["operation"] for item in view["audit"]} >= {"shadow", "emergency-disable", "policy_configured"}
    assert protection.change_mode(db, "reset-emergency", "test", clock=lambda: now + 6000)
    assert protection.snapshot(db)["mode"] == "alert_only"


def test_worker_rollback_recovers_pending_and_keeps_stage2_alerts(db, monkeypatch):
    now = detection.now_ms()
    protection.change_mode(db, "shadow", "test", clock=lambda: now)
    triad(db, now + 1)
    original = protection.record

    def fail(*args):
        original(*args)
        raise RuntimeError("synthetic transaction failure")

    with monkeypatch.context() as patch:
        patch.setattr(protection, "record", fail)
        with pytest.raises(RuntimeError):
            drain(db, now=now + 20)
    assert protection.snapshot(db)["health"]["pending"] == 3
    assert detection.alert_snapshot(db, {})["overview"]["total"] == 3
    protection.initialize(db)
    assert drain(db, now=now + 30)["totals"]["proposed_blocks"] == 1


def test_migration_keeps_stage1_and_stage2_history_without_backfill(tmp_path):
    path = tmp_path / "existing.sqlite3"
    app, key = "northfield-local", b"m" * 32
    detection.initialize(path)
    with TestClient(create_app(path, {app: key})) as collector:
        events = [request("/api/auth/login", method="POST", status=401, auth="denied") for _ in range(5)]
        deliver(collector, app, key, events)
    assert detection.process(path) == 5
    before = detection.alert_snapshot(path, {})["alerts"]
    protection.initialize(path)
    assert protection.change_mode(path, "shadow", "test")
    assert drain(path)["decisions"] == []
    assert detection.alert_snapshot(path, {})["alerts"] == before
    assert len(store.snapshot(path, detection.now_ms() // 1000)[0]["events"]) == 5


def test_spoofed_origin_metadata_duplicate_and_out_of_order_telemetry(db):
    app, key = "northfield-local", b"a" * 32
    protection.change_mode(db, "shadow", "test")
    events = normal_events()
    events[1]["timestamp"] -= 120_000
    with TestClient(create_app(db, {app: key})) as collector:
        deliver(collector, app, key, events)
        duplicate = signed(batch(*events), app=app, key=key)
        duplicate["headers"]["x-forwarded-for"] = "192.0.2.22"
        assert collector.post(INGEST_PATH, **duplicate).json()["duplicates"] == 3
        spoof = request("/api/students")
        spoof["client_ip"] = "192.0.2.22"
        assert collector.post(INGEST_PATH, **signed(batch(spoof), app=app, key=key)).status_code == 422
    assert detection.process(db) == 3
    assert drain(db)["decisions"] == []


def test_operator_mode_controls_require_session_csrf_and_local_origin(db, monkeypatch):
    monkeypatch.setenv("HTTP_TELEMETRY_DB", str(db))
    monkeypatch.setenv("ADMIN_TOKEN", "stage3-test-operator")
    ui = FastAPI()
    ui.include_router(auth_router)
    ui.include_router(dashboard.router)
    with TestClient(ui, base_url=ORIGIN, client=("127.0.0.1", 50001)) as client:
        url = "/api/telemetry/protection/mode/shadow"
        assert client.post(url).status_code == 401
        login = client.post("/api/auth/login", headers={"Origin": ORIGIN}, json={"token": "stage3-test-operator"})
        headers = {"Origin": ORIGIN, "X-CSRF-Token": login.headers["x-csrf-token"]}
        assert client.post(url, headers={"Origin": ORIGIN}).status_code == 403
        assert client.post(url, headers={**headers, "Origin": "https://outside.invalid"}).status_code == 404
        assert client.post(url, headers=headers).status_code == 200
        assert client.post("/api/telemetry/protection/mode/block", headers=headers).status_code == 404
        now = detection.now_ms()
        triad(db, now)
        block = next(item for item in drain(db, now=now + 20)["decisions"] if item["action"] == "BLOCK")
        with client.websocket_connect(STREAM, headers={"Origin": ORIGIN}) as socket:
            view = socket.receive_json()["protection"]
            assert view["mode"] == "shadow" and view["totals"]["enforced_blocks"] == 0
        assert client.post(f"/api/telemetry/protection/decisions/{block['id']}/dismiss", headers=headers).status_code == 200
        assert protection.snapshot(db)["audit"][0]["operation"] == "proposal_dismissed"
