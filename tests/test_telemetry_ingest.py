import json
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest
import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.security.demo_access import router as auth_router
from backend.telemetry import dashboard, store
from backend.telemetry.api import create_app, signature
from backend.telemetry.proxy import create_proxy
from backend.telemetry.schemas import INGEST_PATH, MAX_BYTES

APP = "northfield-test"
KEY = bytes.fromhex("41" * 32)
NOW = int(time.time())
ORIGIN = "http://localhost"
STREAM = "ws://localhost/ws/monitored-applications"


def event(**updates):
    return {"request_id": str(uuid4()), "timestamp": NOW * 1000,
            "route": "/api/courses/{course_id}/enroll", "method": "POST",
            "status": 201, "duration_ms": 15.5, "auth": "authenticated", **updates}


def batch(*events, **updates):
    return {"version": 1, "events": list(events),
            "delivery": {"queued": 0, "sent": 0, "dropped": 0, "retries": 0, "failed_batches": 0}, **updates}


def signed(payload, *, app=APP, key=KEY, timestamp=NOW, nonce=None):
    data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    nonce = nonce or str(uuid4())
    timestamp = str(timestamp)
    return {"content": data, "headers": {
        "content-type": "application/json", "x-telemetry-app": app,
        "x-telemetry-timestamp": timestamp, "x-telemetry-nonce": nonce,
        "x-telemetry-signature": signature(key, app, timestamp, nonce, data),
    }}


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "events.sqlite3"


@pytest.fixture
def collector(db_path):
    with TestClient(create_app(db_path, {APP: KEY, "another-app": b"b"*32}, clock=lambda: NOW)) as client:
        yield client


def test_authentication_rejects_unsigned_tampered_and_stale(collector):
    assert collector.post(INGEST_PATH, json=batch()).status_code == 401
    assert collector.post(INGEST_PATH, **signed(batch(), timestamp=NOW - 121)).status_code == 401
    assert collector.post(INGEST_PATH, **signed(batch(), timestamp=NOW + 121)).status_code == 401
    assert collector.post(INGEST_PATH, **signed(batch(), app="another-app")).status_code == 401
    tampered = signed(batch())
    tampered["content"] += b" "
    assert collector.post(INGEST_PATH, **tampered).status_code == 401
    for method in ("GET", "HEAD", "OPTIONS", "PUT"):
        assert collector.request(method, INGEST_PATH).status_code == 404
    for path in ("/dashboard", "/chat", "/attack-lab", "/api/admin", "/predict", "/docs", "/openapi.json"):
        assert collector.get(path).status_code == 404


def test_nonce_replay_persists_and_retry_deduplicates(db_path):
    payload = batch(event())
    request = signed(payload)
    app = create_app(db_path, {APP: KEY}, clock=lambda: NOW)
    with TestClient(app) as client:
        assert client.post(INGEST_PATH, **request).json() == {"accepted": 1, "duplicates": 0}
    with TestClient(app) as client:
        assert client.post(INGEST_PATH, **request).status_code == 409
        assert client.post(INGEST_PATH, **signed(payload)).json() == {"accepted": 0, "duplicates": 1}
    assert len(store.snapshot(db_path, NOW)[0]["events"]) == 1


def test_dashboard_reads_collector_database_before_totals_migration(collector, db_path):
    item = event()
    assert collector.post(INGEST_PATH, **signed(batch(item))).status_code == 200
    with store.connect(db_path) as db:
        db.execute("DROP TABLE observed_totals")

    (application,) = store.snapshot(db_path, NOW)
    assert application["total_observed"] == 1
    assert application["events"][0]["request_id"] == item["request_id"]
    with store.connect(db_path) as db:
        assert db.execute("SELECT 1 FROM sqlite_master WHERE name='observed_totals'").fetchone() is None


@pytest.mark.parametrize("payload", [
    batch(version=2), batch(version=True),
    batch(event(route="/api/courses?q=private")),
    batch(event(route="/api/contact/private@example.test")),
    batch(event(token="must not echo")),
    batch(event(timestamp=1)), batch(event(status=999)), batch(event(auth="private")),
    batch(*[event() for _ in range(33)]),
])
def test_schema_rejects_invalid_data(collector, payload):
    response = collector.post(INGEST_PATH, **signed(payload))
    assert response.status_code == 422
    assert "must not echo" not in response.text


def test_size_cap(collector):
    assert collector.post(INGEST_PATH, **signed(b" " * (MAX_BYTES + 1))).status_code == 413


def test_tunnel_proxy_forwards_only_exact_allowed_request():
    forwarded = []

    def accept(request):
        forwarded.append(request)
        return httpx.Response(429, headers={"Retry-After": "5", "Set-Cookie": "internal=only"})

    with TestClient(create_proxy(httpx.MockTransport(accept))) as client:
        for method, path in [("GET", INGEST_PATH), ("OPTIONS", INGEST_PATH),
                             ("POST", INGEST_PATH + "/"), ("POST", INGEST_PATH + "?query=private"),
                             ("GET", "/dashboard"), ("POST", "/chat"), ("GET", "/api/admin")]:
            assert client.request(method, path).status_code == 404
        assert client.post(INGEST_PATH, content=b"x" * (MAX_BYTES + 1)).status_code == 413
        assert not forwarded
        wire = signed(batch(event()))
        wire["headers"]["Cookie"] = "private=unforwarded"
        wire["headers"]["X-Forwarded-For"] = "192.0.2.1"
        response = client.post(INGEST_PATH, **wire)
        assert response.status_code == 429 and response.headers["retry-after"] == "5"
        assert "set-cookie" not in response.headers
        assert forwarded[0].content == wire["content"]
        assert forwarded[0].url == "http://127.0.0.1:8091" + INGEST_PATH
        assert forwarded[0].headers["x-telemetry-signature"] == wire["headers"]["x-telemetry-signature"]
        assert "cookie" not in forwarded[0].headers and "x-forwarded-for" not in forwarded[0].headers


def test_event_ids_and_health_are_scoped_to_authenticated_application(collector, db_path):
    payload = batch(event())
    for app, key in ((APP, KEY), ("another-app", b"b" * 32)):
        assert collector.post(INGEST_PATH, **signed(payload, app=app, key=key)).json()["accepted"] == 1
    snapshots = {item["id"]: item for item in store.snapshot(db_path, NOW)}
    assert set(snapshots) == {APP, "another-app"}
    assert all(item["events"] == payload["events"] for item in snapshots.values())


def test_storage_retention_and_per_app_limits(collector, db_path, monkeypatch):
    monkeypatch.setattr(store, "MAX_ROWS_PER_APP", 2)
    monkeypatch.setattr(store, "NONCE_LIMIT", 2)
    assert collector.post(INGEST_PATH, **signed(batch(event(), event(), event()))).status_code == 200
    assert collector.post(INGEST_PATH, **signed(batch())).status_code == 200
    assert collector.post(INGEST_PATH, **signed(batch())).status_code == 429
    assert len(store.snapshot(db_path, NOW)[0]["events"]) == 2
    store.maintain(db_path, NOW + store.RETENTION_SECONDS + 1)
    with store.connect(db_path) as db:
        for table in ("events", "nonces", "delivery"):
            assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_dashboard_stream_requires_session_and_picks_up_committed_events(collector, db_path, monkeypatch):
    monkeypatch.setenv("HTTP_TELEMETRY_DB", str(db_path))
    monkeypatch.setenv("ADMIN_TOKEN", "synthetic-operator-token")
    monkeypatch.setattr(dashboard, "INTERVAL", 0.05)
    monkeypatch.setattr(dashboard, "VIEWERS", 1)
    monkeypatch.setattr(dashboard, "time", SimpleNamespace(time=lambda: NOW))
    ui = FastAPI()
    ui.include_router(auth_router)
    ui.include_router(dashboard.router)
    with TestClient(ui, base_url=ORIGIN, client=("127.0.0.1", 50000)) as operator:
        with pytest.raises(WebSocketDisconnect), operator.websocket_connect(
            STREAM, headers={"Origin": ORIGIN}
        ):
            pytest.fail("Anonymous socket opened")
        login = operator.post("/api/auth/login", json={"token": "synthetic-operator-token"},
                              headers={"Origin": ORIGIN})
        assert login.status_code == 200
        assert "Monitored Applications" in operator.get("/dashboard/applications").text
        for headers in ({"Origin": "https://outside.example"},
                        {"Origin": ORIGIN, "X-Forwarded-For": "192.0.2.10"}):
            with pytest.raises(WebSocketDisconnect), operator.websocket_connect(
                STREAM, headers=headers
            ):
                pytest.fail("Untrusted socket opened")
        with operator.websocket_connect(STREAM, headers={"Origin": ORIGIN}) as ws:
            assert ws.receive_json()["applications"] == []
            with pytest.raises(WebSocketDisconnect), operator.websocket_connect(STREAM, headers={"Origin": ORIGIN}):
                pytest.fail("Stream exceeded its viewer limit")
            request = event(status=401, auth="denied")
            assert collector.post(INGEST_PATH, **signed(batch(request))).status_code == 200
            for _ in range(4):
                applications = ws.receive_json()["applications"]
                if applications:
                    break
            assert applications
            snapshot = applications[0]
            assert snapshot["events"] == [request]
            assert snapshot["requests_per_minute"] == snapshot["auth_failures"] == 1
            assert snapshot["statuses"] == {"401": 1}
            dashboard.demo_security.sessions.clear()
            with pytest.raises(WebSocketDisconnect):
                ws.receive_json()
