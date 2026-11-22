"""Opt-in cross-repository integration for the Northfield staging checkout."""

import asyncio
import importlib
import importlib.util
import json
import os
import socket
import sys
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from threading import Thread
from uuid import uuid4

import httpx
import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.security.demo_access import router as auth_router
from backend.telemetry import dashboard, detection, protection, staging_policy, store
from backend.telemetry.api import create_app as create_collector
from backend.telemetry.policy_api import create_app as create_policy_service
from backend.telemetry.policy_wire import MAX_BYTES, SYNC_PATH, Snapshot, Sync, sign
from backend.telemetry.protection_policy import Policy
from backend.telemetry.replay import deliver, request
from backend.telemetry.rules import DEFAULT_RULES
from backend.telemetry.schemas import INGEST_PATH
from test_telemetry_ingest import batch, signed

APP = "northfield-staging"
KEY = b"c" * 32
TELEMETRY = b"t" * 32
SUBJECT = b"s" * 32
URL = "http://127.0.0.1:8093" + SYNC_PATH
ORIGIN = "http://localhost"
ROUTE = "/api/courses/{course_id}/access"


@pytest.fixture(scope="module")
def northfield():
    checkout = Path(os.getenv("NORTHFIELD_STAGING_CHECKOUT", ".northfield-local")).resolve()
    app = checkout / "backend" / "app"
    if not (app / "policy_wire.py").is_file():
        pytest.skip("Northfield staging checkout is required")
    if dependency_path := os.getenv("NORTHFIELD_STAGING_DEPS"):
        sys.path.append(dependency_path)
    pytest.importorskip("email_validator")
    assert (app / "policy_wire.py").read_text(encoding="utf-8") == (
        Path(__file__).resolve().parents[1] / "backend/telemetry/policy_wire.py"
    ).read_text(encoding="utf-8")
    namespace = "northfield_staging_test_app"
    spec = importlib.util.spec_from_file_location(namespace, app / "__init__.py", submodule_search_locations=[str(app)])
    package = importlib.util.module_from_spec(spec)
    sys.modules[namespace] = package
    spec.loader.exec_module(package)
    return {name: importlib.import_module(f"{namespace}.{name}")
            for name in ("config", "db", "main", "models", "protection", "security", "telemetry")}


def settings(module, path, **overrides):
    values = dict(app_env="test", jwt_secret="staging-integration-test-jwt-secret-32",
                  sqlite_path=path, telemetry_app_id=APP,
                  telemetry_collector_url="http://127.0.0.1:8091/v1/http-events",
                  telemetry_hmac_key=TELEMETRY.hex(), protection_url=URL,
                  protection_hmac_key=KEY.hex(), protection_subject_key=SUBJECT.hex())
    return module["config"].Settings(_env_file=None, **{**values, **overrides})


@contextmanager
def loopback(app):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app, ws="none", log_level="error", proxy_headers=False))
        thread = Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 6
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.02)
            assert server.started
            yield f"http://127.0.0.1:{port}"
        finally:
            server.should_exit = True
            thread.join(6)
            assert not thread.is_alive()


def drain(path, policy):
    while detection.process(path):
        pass
    while protection.process(path, policy):
        pass


def propose(collector, path, subject, deny_count):
    def event(status, auth):
        return {**request(ROUTE, method="POST", status=status, auth=auth), "subject": subject}

    earlier = [event(204, "authenticated") for _ in range(40)] + [event(403, "denied") for _ in range(4)]
    deliver(collector, APP, TELEMETRY, earlier)
    with store.connect(path) as db:
        db.execute("""
            UPDATE http_detection_events SET arrived=arrived-4000
            WHERE app=? AND json_extract(payload,'$.subject')=? AND status IN (204,403)
        """, (APP, subject))
    recent = [event(403, "denied") for _ in range(deny_count - 4)] + [event(204, "authenticated")]
    deliver(collector, APP, TELEMETRY, recent)
    drain(path, Policy(proposed_requests_per_minute=1))
    action = "BLOCK" if deny_count >= 8 else "RATE_LIMIT"
    return next(item for item in protection.snapshot(path)["decisions"]
                if item["action"] == action and item["evidence"].get("subject") == subject)


def send_sync(client, envelope, key=KEY):
    body = envelope.model_dump_json().encode()
    return client.post(SYNC_PATH, content=body, headers={
        "content-type": "application/json", "x-policy-signature": sign(key, "sync", envelope.nonce, body),
    })


def test_policy_channel_authentication_replay_boundaries_and_size(tmp_path):
    path = tmp_path / "policies.sqlite3"
    with TestClient(create_policy_service(path, {APP: KEY}), client=("127.0.0.1", 50000)) as client:
        envelope = Sync(version=1, app=APP, environment="staging", nonce=str(uuid4()),
                        timestamp=int(time.time()), receipts=[])
        assert client.post(SYNC_PATH).status_code == 401
        assert send_sync(client, envelope, b"x" * 32).status_code == 401
        response = send_sync(client, envelope)
        assert response.status_code == 200
        assert response.headers["x-policy-signature"] == sign(KEY, "snapshot", envelope.nonce, response.content)
        assert send_sync(client, envelope).status_code == 409
        assert send_sync(client, envelope.model_copy(update={"app": "other-staging", "nonce": str(uuid4())})).status_code == 401
        assert send_sync(client, envelope.model_copy(update={"environment": "production", "nonce": str(uuid4())})).status_code == 401
        assert send_sync(client, envelope.model_copy(update={"timestamp": 0, "nonce": str(uuid4())})).status_code == 401
        assert client.post(SYNC_PATH, headers={"X-Forwarded-For": "192.0.2.3"}).status_code == 404
        assert client.post(SYNC_PATH, content=b"x" * (MAX_BYTES + 1), headers={
            "Content-Type": "application/json", "X-Policy-Signature": "a" * 64,
        }).status_code == 413
        assert client.get("/dashboard").status_code == client.post("/v1/http-events").status_code == 404
        issued = Snapshot.model_validate_json(response.content)
        later = envelope.model_copy(update={"timestamp": issued.expires, "nonce": str(uuid4())})
        renewed, status = staging_policy.exchange(path, later, issued.expires)
        assert status == 200 and renewed.revision == issued.revision + 1
        assert not renewed.enabled and renewed.rules == []


@pytest.mark.parametrize("rate_recovery", ["revoke", "expiry"])
def test_request_path_enforces_only_approved_staging_subjects(northfield, tmp_path, monkeypatch, rate_recovery):
    db = tmp_path / "sentinel.sqlite3"
    portal_path = tmp_path / "portal.sqlite3"
    config = settings(northfield, portal_path)
    engine = northfield["db"].make_engine(portal_path)
    models = northfield["models"]
    models.Base.metadata.create_all(engine)
    with northfield["db"].make_sessions(engine).begin() as session:
        session.add(models.Course(id=1, title="Staging Course", description="Isolated test",
                                  category="Test", instructor="Synthetic Tutor", duration=4, status="open"))
    engine.dispose()
    async def idle(self):
        await asyncio.Event().wait()
    monkeypatch.setattr(northfield["telemetry"].TelemetrySender, "run", idle)
    monkeypatch.setattr(northfield["protection"].StagingProtection, "run", idle)
    emitted = []
    monkeypatch.setattr(northfield["telemetry"].TelemetrySender, "submit", lambda self, event: emitted.append(event))
    portal = northfield["main"].create_app(config)
    agent = portal.state.protection
    monkeypatch.setenv("HTTP_TELEMETRY_DB", str(db))
    monkeypatch.setenv("ADMIN_TOKEN", "synthetic-stage-policy-operator")
    operator_app = FastAPI()
    operator_app.include_router(auth_router)
    operator_app.include_router(dashboard.router)

    with (
        loopback(create_policy_service(db, {APP: KEY})) as policy_origin,
        TestClient(create_collector(db, {APP: TELEMETRY})) as collector,
        loopback(portal) as portal_origin,
        httpx.Client(base_url=portal_origin, trust_env=False, timeout=5) as first,
        httpx.Client(base_url=portal_origin, trust_env=False, timeout=5) as second,
        TestClient(operator_app, base_url=ORIGIN, client=("127.0.0.1", 50101)) as operator,
    ):
        agent.url = policy_origin + SYNC_PATH
        def register(client, suffix):
            pw = "staging-synthetic-password-long"
            result = client.post("/api/auth/register", json={
                "email": f"synthetic-{suffix}@example.com", "student_id": f"STAGE-{suffix}",
                "full_name": "Synthetic Test Learner", "password": pw, "confirm_password": pw})
            assert result.status_code == 201
            login = client.post("/api/auth/login", json={"email": f"synthetic-{suffix}@example.com", "password": pw})
            assert login.status_code == 200
            headers = {"X-CSRF-Token": login.json()["csrf_token"]}
            assert client.post("/api/courses/1/enroll", headers=headers).status_code == 201
            assert client.post("/api/courses/1/access", headers=headers).status_code == 204
            return headers, emitted[-1]["subject"]

        h1, subject1 = register(first, "ONE")
        h2, subject2 = register(second, "TWO")
        assert subject1 != subject2
        assert "subject" not in next(event for event in emitted if event["route"] == "/api/auth/login")
        assert all(value not in json.dumps(emitted) for value in ("@example.com", "Synthetic Test Learner", "password-long"))
        operator_session = operator.post("/api/auth/login", headers={"Origin": ORIGIN},
                                         json={"token": "synthetic-stage-policy-operator"})
        op_headers = {"Origin": ORIGIN, "X-CSRF-Token": operator_session.headers["x-csrf-token"]}

        def command(action, identifier=None):
            endpoint = f"/api/telemetry/staging-policy/{APP}/{action}"
            if identifier:
                endpoint += "/" + identifier
            return operator.post(endpoint, headers=op_headers)

        def forward(outbound):
            received = httpx.post(policy_origin + SYNC_PATH, content=outbound.content, headers=dict(outbound.headers),
                                  trust_env=False, timeout=5)
            return httpx.Response(received.status_code, headers=received.headers, content=received.content)

        async def pull(target=agent, handler=None):
            target.url = policy_origin + SYNC_PATH
            transport = httpx.MockTransport(handler) if handler else None
            async with httpx.AsyncClient(transport=transport, trust_env=False, timeout=5) as client:
                await target.poll(client)

        assert operator.post(f"/api/telemetry/staging-policy/{APP}/enable", headers={"Origin": ORIGIN}).status_code == 403
        assert protection.change_mode(db, "shadow", "test")
        assert command("enable").status_code == 200
        asyncio.run(pull())
        if agent.snapshot:
            assert not agent.snapshot.rules

        rate = propose(collector, db, subject1, 5)
        assert first.post("/api/courses/1/access", headers=h1).status_code == 204
        assert command("approve", rate["id"]).status_code == 200
        assert command("approve", rate["id"]).status_code == 409
        asyncio.run(pull())
        assert first.post("/api/courses/1/access", headers=h1).status_code == 204
        limited = first.post("/api/courses/1/access", headers=h1)
        assert limited.status_code == 429 and int(limited.headers["retry-after"]) > 0
        legitimate = second.post("/api/courses/1/access", headers=h2)
        assert legitimate.status_code == 204
        assert second.post("/api/courses/1/access", headers={
            **h2, "X-Policy-Subject": subject1, "X-Forwarded-For": "192.0.2.42",
        }).status_code == 204
        assert first.post("/api/courses/1/access").json()["detail"] == "Invalid request token"
        asyncio.run(pull())
        if rate_recovery == "expiry":
            rule = next(rule for rule in agent.snapshot.rules if rule.id == rate["id"])
            wall_clock = agent.clock
            try:
                agent.clock = lambda: rule.expires
                recovered = first.post("/api/courses/1/access", headers=h1)
            finally:
                agent.clock = wall_clock
        else:
            recovered = None
        assert command("revoke", rate["id"]).status_code == 200
        asyncio.run(pull())
        if recovered is None:
            recovered = first.post("/api/courses/1/access", headers=h1)
        assert recovered.status_code == 204
        legitimate_after = second.post("/api/courses/1/access", headers=h2)
        assert legitimate_after.status_code == 204

        responses = {
            limited.headers["x-request-id"]: (429, subject1),
            legitimate.headers["x-request-id"]: (204, subject2),
            recovered.headers["x-request-id"]: (204, subject1),
            legitimate_after.headers["x-request-id"]: (204, subject2),
        }
        # Response delivery can complete just before the middleware queues telemetry.
        deadline = time.monotonic() + 2
        while True:
            observations = {event["request_id"]: event for event in emitted if event["request_id"] in responses}
            if len(observations) == len(responses) or time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        assert observations.keys() == responses.keys()
        deliver(collector, APP, TELEMETRY, list(observations.values()))
        retried = collector.post(INGEST_PATH, **signed(batch(*observations.values()), app=APP, key=TELEMETRY))
        assert retried.json() == {"accepted": 0, "duplicates": len(observations)}
        with operator.websocket_connect("ws://localhost/ws/monitored-applications", headers={"Origin": ORIGIN}) as ws:
            payload = ws.receive_json()
            app = next(item for item in payload["applications"] if item["id"] == APP)
            persisted = {event["request_id"]: event for event in app["events"]}
            for request_id, (status, subject) in responses.items():
                event = persisted[request_id]
                assert (event["status"], event["subject"], event["method"], event["route"]) == (status, subject, "POST", ROUTE)
                assert event["duration_ms"] >= 0
            channel, = payload["staging"]["channels"]
            receipt, = [item for item in channel["receipts"] if item["outcome"] == "rate_limited"]
            assert receipt["request_id"] == limited.headers["x-request-id"]

        block = propose(collector, db, subject2, 8)
        assert command("approve", block["id"]).status_code == 200
        asyncio.run(pull())
        denied = second.post("/api/courses/1/access", headers=h2)
        assert denied.status_code == 403 and denied.json()["detail"] == "This action is temporarily unavailable."
        assert first.post("/api/courses/1/access", headers=h1).status_code == 204
        assert second.get("/health").status_code == 200
        assert second.get("/api/auth/me").status_code == 200

        def tamper(outbound):
            response = forward(outbound)
            return httpx.Response(200, headers={"X-Policy-Signature": "0" * 64}, content=response.content)

        with pytest.raises(ValueError, match="signature"):
            asyncio.run(pull(handler=tamper))
        asyncio.run(pull())
        restarted = northfield["protection"].StagingProtection(config)
        asyncio.run(pull(restarted))
        assert restarted.snapshot is None
        before = staging_policy.snapshot(db)["channels"][0]
        receipt_ids = {row["request_id"] for row in before["receipts"] if row["request_id"]}
        assert {denied.headers["x-request-id"], limited.headers["x-request-id"]} <= receipt_ids
        assert before["confirmed"] == {"blocked": 1, "rate_limited": 1}
        assert before["acknowledgment"] == "applied"
        with operator.websocket_connect("ws://localhost/ws/monitored-applications", headers={"Origin": ORIGIN}) as ws:
            streamed, = ws.receive_json()["staging"]["channels"]
            assert streamed["acknowledgment"] == "applied"
            assert streamed["confirmed"] == before["confirmed"]
            assert receipt_ids <= {row["request_id"] for row in streamed["receipts"]}

        async def outage():
            def unavailable(request):
                raise httpx.ConnectError("isolated policy channel outage", request=request)
            async with httpx.AsyncClient(transport=httpx.MockTransport(unavailable)) as client:
                assert not await agent.sync_once(client)

        asyncio.run(outage())
        assert second.post("/api/courses/1/access", headers=h2).status_code == 204
        asyncio.run(pull())
        assert agent.snapshot is None
        assert command("refresh").status_code == 200
        asyncio.run(pull())
        assert agent.snapshot and agent.snapshot.rules
        assert staging_policy.snapshot(db)["channels"][0]["receiver_errors"] == 1

        future = agent.snapshot.expires
        original_clock = agent.clock
        agent.clock = lambda: future
        assert second.post("/api/courses/1/access", headers=h2).status_code == 204
        agent.clock = original_clock
        agent.kill_switch.touch()
        assert second.post("/api/courses/1/access", headers=h2).status_code == 204
        agent.kill_switch.unlink()
        assert second.post("/api/courses/1/access", headers=h2).status_code == 204
        assert protection.change_mode(db, "emergency-disable", "test")
        asyncio.run(pull())
        asyncio.run(pull())
        assert staging_policy.snapshot(db)["channels"][0]["acknowledgment"] == "disabled"
        assert command("enable").status_code == 409


def test_production_cannot_enable_staging_and_stale_policy_is_rejected(northfield, tmp_path):
    with pytest.raises(ValueError, match="matching telemetry environment"):
        settings(northfield, tmp_path / "portal.sqlite3", app_env="production",
                 allowed_origins="https://example.com", telemetry_collector_url="https://example.com/v1/http-events")
    config = settings(northfield, tmp_path / "staged.sqlite3")
    agent = northfield["protection"].StagingProtection(config)
    now = int(time.time())
    base = Snapshot(version=1, app=APP, environment="staging", id=str(uuid4()), revision=1,
                    created=now - 3, expires=now - 1, enabled=False, rules=[])
    assert not agent.install(base)
    assert not agent.install(base.model_copy(update={"app": "another-staging", "expires": now + 1}))
    assert agent.snapshot is None

    async def wrong_targets():
        future = base.model_copy(update={"expires": now + 60})
        for update in ({"environment": "production"}, {"app": "another-staging"}):
            body = future.model_copy(update=update).model_dump_json().encode()
            def reply(outgoing):
                nonce = json.loads(outgoing.content)["nonce"]
                return httpx.Response(200, headers={"X-Policy-Signature": sign(KEY, "snapshot", nonce, body)},
                                      content=body)
            async with httpx.AsyncClient(transport=httpx.MockTransport(reply)) as client:
                assert not await agent.sync_once(client)
            assert agent.snapshot is None
    asyncio.run(wrong_targets())


def test_production_policy_delivery_has_independent_opt_ins(northfield, tmp_path):
    production = "northfield-prod"
    path = tmp_path / "policies.sqlite3"
    portal = tmp_path / "portal.sqlite3"
    config = dict(app_env="production", telemetry_app_id=production, allowed_origins="https://example.com",
                  telemetry_collector_url="https://telemetry.example.com/v1/http-events")
    assert settings(northfield, portal, **config, protection_url="", protection_hmac_key="").protection_subject_key
    receiver = dict(protection_url="https://policy.example.com/v1/policy/sync",
                    protection_state_path=tmp_path / "watermark.sqlite3")
    with pytest.raises(ValueError, match="explicit opt-in"):
        settings(northfield, portal, **config, **receiver)
    receiver_settings = settings(northfield, portal, **config, **receiver, protection_sync_only=True)
    settings(northfield, portal, **config, **receiver, protection_production_enabled=True)
    for allowed in (True, False):
        service = create_policy_service(path, {production: KEY}, public_host="policy.example.com", allow_production=allowed)
        with TestClient(service, client=("127.0.0.1", 50000)) as ops:
            host = {"Host": "policy.example.com"}
            assert ops.post(SYNC_PATH, headers=host).status_code == 401
            assert ops.get(SYNC_PATH, headers=host).status_code == 404
            assert ops.post("/api/admin", headers=host).status_code == 404
            assert protection.change_mode(path, "shadow", "test")
            assert staging_policy.command(path, production, "enable") is None
            envelope = Sync(version=1, app=production, environment="production", nonce=str(uuid4()),
                            timestamp=int(time.time()), receipts=[])
            assert send_sync(ops, envelope).status_code == 404
            body = envelope.model_dump_json().encode()
            response = ops.post(SYNC_PATH, content=body, headers={
                **host, "Content-Type": "application/json",
                "X-Policy-Signature": sign(KEY, "sync", envelope.nonce, body),
            })
            issued = Snapshot.model_validate_json(response.content)
            assert not issued.enabled and not issued.rules
            assert staging_policy.command(path, production, "enable-production") is None

            async def sync_disabled():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=service, client=("127.0.0.1", 50000))) as client:
                    agent = northfield["protection"].StagingProtection(receiver_settings)
                    assert await agent.sync_once(client)
                    assert agent.snapshot.model_dump() == issued.model_dump()
                    # Restart with the same sidecar. The disabled revision can be acknowledged again.
                    agent = northfield["protection"].StagingProtection(receiver_settings)
                    assert await agent.sync_once(client)
                    assert agent.snapshot.model_dump() == issued.model_dump()
                    assert await agent.sync_once(client)

            asyncio.run(sync_disabled())
            channel, = staging_policy.snapshot(path)["channels"]
            assert channel["acknowledgment"] == "disabled"
            assert channel["can_enable"] == allowed
            assert staging_policy.command(path, production, "enable-production", clock=lambda: time.time() + 11) is None
            enabled = staging_policy.command(path, production, "enable-production")
            assert bool(enabled) == allowed
            if enabled:
                assert not enabled.rules
                assert not northfield["protection"].StagingProtection(receiver_settings).install(
                    northfield["protection"].Snapshot.model_validate(enabled.model_dump()))
                assert protection.change_mode(path, "alert-only", "test")
                channel, = staging_policy.snapshot(path)["channels"]
                assert not channel["enabled"] and not channel["rules"]


def test_production_format_telemetry_only_proposes_from_fresh_attributed_evidence(tmp_path):
    path = tmp_path / "sentinel.sqlite3"
    production = "northfield-prod"
    protection.initialize(path)
    staging_policy.initialize(path, [production])
    assert protection.change_mode(path, "shadow", "test")
    now = int(time.time() * 1000)
    with TestClient(create_collector(path, {production: TELEMETRY})) as collector:
        for subject, lag in (("s1_" + "a" * 64, 0), ("s1_" + "b" * 64, 25_000)):
            events = [dict(request(ROUTE, method="POST", status=204 if index < 30 else 404,
                                   auth="authenticated" if index < 30 else "authorization_denied"),
                           subject=subject, timestamp=now - lag - (39 - index) * 110) for index in range(40)]
            for group in (events[:20], events[20:]):
                body = batch(*group)
                assert collector.post(INGEST_PATH, **signed(body, app=production, key=TELEMETRY,
                                                          timestamp=int(time.time()))).json()["accepted"] == len(group)
                assert collector.post(INGEST_PATH, **signed(body, app=production, key=TELEMETRY,
                                                          timestamp=int(time.time()))).json()["duplicates"] == len(group)
    drain(path, Policy())
    proposal, = [item for item in protection.snapshot(path)["decisions"] if item["action"] == "RATE_LIMIT"]
    assert proposal["app"] == production and proposal["route"] == ROUTE
    assert proposal["evidence"]["subject"] == "s1_" + "a" * 64
    assert proposal["status"] == "proposed" and not proposal["enforced"]
    assert {signal["rule"]: signal["count"] for signal in proposal["evidence"]["signals"]} == {
        "route_burst": 40, "authorization_denials": 10,
    }
    assert staging_policy.command(path, production, "approve", proposal["id"]) is None
    channel, = staging_policy.snapshot(path)["channels"]
    assert not channel["enabled"] and not channel["rules"] and not channel["can_enable"]


@pytest.fixture
def e2e_database_url(northfield, tmp_path):
    url = os.getenv("NORTHFIELD_TEST_DATABASE_URL", "")
    if not url:
        yield ""
        return
    from sqlalchemy import text
    from sqlalchemy.engine import make_url

    address = make_url(url)
    if address.host not in {"127.0.0.1", "localhost", "::1"}:
        pytest.fail("Use a disposable loopback database for Northfield staging")
    schema = "sentinel_e2e_" + uuid4().hex
    engine = northfield["db"].make_engine(tmp_path / "unused.sqlite3", url)
    try:
        with engine.begin() as db:
            db.execute(text(f"CREATE SCHEMA {schema}"))
        yield address.update_query_dict({"options": f"-csearch_path={schema}"}).render_as_string(hide_password=False)
    finally:
        with engine.begin() as db:
            db.execute(text(f"DROP SCHEMA IF EXISTS {schema} CASCADE"))
        engine.dispose()


def test_real_northfield_http_drives_signed_detection_approval_and_recovery(northfield, tmp_path, monkeypatch,
                                                                          e2e_database_url):
    db = tmp_path / "sentinel.sqlite3"
    portal_path = tmp_path / "portal.sqlite3"
    engine = northfield["db"].make_engine(portal_path, e2e_database_url)
    models = northfield["models"]
    models.Base.metadata.create_all(engine)
    with northfield["db"].make_sessions(engine).begin() as session:
        for course_id in (1, 2):
            session.add(models.Course(id=course_id, title=f"Course {course_id}", description="Isolated test",
                                      category="Test", instructor="Staging Tutor", duration=4, status="open"))
    engine.dispose()
    rules = tuple(replace(rule, threshold={"route_burst": 4, "authorization_denials": 2}.get(rule.id, rule.threshold))
                  for rule in DEFAULT_RULES)
    policy = Policy(staging_minimum_burst=4, staging_minimum_authorization_denials=2,
                    minimum_burst_duration_seconds=1, proposed_requests_per_minute=1)
    operator_token = "real-loopback-demo-operator"
    monkeypatch.setenv("HTTP_TELEMETRY_DB", str(db))
    monkeypatch.setenv("ADMIN_TOKEN", operator_token)
    operator_app = FastAPI()
    operator_app.include_router(auth_router)
    operator_app.include_router(dashboard.router)

    def wait_for(observe, description, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if result := observe():
                return result
            time.sleep(0.08)
        pytest.fail(description)

    def stream_event_ids():
        apps = store.snapshot(db, int(time.time()))
        return {event["request_id"]: event for app in apps if app["id"] == APP for event in app["events"]}

    def enroll(client, suffix):
        password = "staging-synthetic-password-long"
        email = f"loopback-{suffix}@example.com"
        assert client.post("/api/auth/register", json={
            "email": email, "student_id": f"STAGE-{suffix}", "full_name": "Test Learner",
            "password": password, "confirm_password": password,
        }).status_code == 201
        login = client.post("/api/auth/login", json={"email": email, "password": password})
        assert login.status_code == 200
        headers = {"X-CSRF-Token": login.json()["csrf_token"]}
        assert client.post("/api/courses/1/enroll", headers=headers).status_code == 201
        return headers

    with loopback(create_policy_service(db, {APP: KEY})) as policy_origin, loopback(
        create_collector(db, {APP: TELEMETRY})
    ) as collector_origin:
        assert protection.change_mode(db, "shadow", "test")
        portal = northfield["main"].create_app(settings(northfield, portal_path,
            database_url=e2e_database_url, telemetry_collector_url=collector_origin + INGEST_PATH,
            protection_url=policy_origin + SYNC_PATH))
        with (
            loopback(portal) as portal_origin,
            httpx.Client(base_url=portal_origin, trust_env=False, timeout=5) as target,
            httpx.Client(base_url=portal_origin, trust_env=False, timeout=5) as other,
            TestClient(operator_app, base_url=ORIGIN, client=("127.0.0.1", 50102)) as operator,
        ):
            a, b = enroll(target, "ONE"), enroll(other, "TWO")
            session = operator.post("/api/auth/login", headers={"Origin": ORIGIN}, json={"token": operator_token})
            op = {"Origin": ORIGIN, "X-CSRF-Token": session.headers["x-csrf-token"]}

            def command(action):
                response = operator.post(f"/api/telemetry/staging-policy/{APP}/{action}", headers=op)
                assert response.status_code == 200, response.text
                return response.json()["revision"]

            def acknowledgment(revision, state):
                return any(ch["revision"] == revision and ch["acknowledgment"] == state
                           for ch in staging_policy.snapshot(db)["channels"])

            def access(client, headers, course=1):
                return client.post(f"/api/courses/{course}/access", headers=headers)

            observed = []
            for course, status in ((1, 204), (1, 204), (2, 404), (2, 404)):
                response = access(target, a, course)
                assert response.status_code == status
                observed.append(response.headers["x-request-id"])
                wait_for(lambda: observed[-1] in stream_event_ids(), "Northfield sender did not deliver the request")
                time.sleep(0.4)

            def proposal():
                detection.process(db, rules)
                protection.process(db, policy)
                return next((row for row in protection.snapshot(db)["decisions"] if row["action"] == "RATE_LIMIT"), None)

            decision = wait_for(proposal, "Observed requests produced no scoped proposal")
            signals = {item["rule"]: set(item["request_ids"]) for item in decision["evidence"]["signals"]}
            assert signals == {"route_burst": set(observed), "authorization_denials": set(observed[-2:])}
            assert decision["route"] == ROUTE and decision["evidence"]["method"] == "POST"
            events = stream_event_ids()
            assert all(events[identifier]["subject"] == decision["evidence"]["subject"] for identifier in observed)
            assert [events[identifier]["auth"] for identifier in observed] == [
                "authenticated", "authenticated", "authorization_denied", "authorization_denied",
            ]
            assert all(value not in json.dumps(events) for value in ("@example.com", "Test Learner", "password-long"))
            assert not staging_policy.snapshot(db)["channels"][0]["enabled"]
            assert access(target, a).status_code == 204
            command("enable")
            revision = command("approve/" + decision["id"])
            wait_for(lambda: acknowledgment(revision, "applied"), "Approved rule was not acknowledged")
            assert access(target, a).status_code == 204
            limited = access(target, a)
            assert limited.status_code == 429 and int(limited.headers["retry-after"]) > 0
            assert access(other, b).status_code == 204
            assert target.get("/api/auth/me").status_code == 200
            identifier = limited.headers["x-request-id"]
            wait_for(lambda: identifier in stream_event_ids(), "Rate-limited request did not arrive")
            wait_for(lambda: any(receipt["request_id"] == identifier
                for receipt in staging_policy.snapshot(db)["channels"][0]["receipts"]), "Signed enforcement receipt missing")
            with operator.websocket_connect("ws://localhost/ws/monitored-applications", headers={"Origin": ORIGIN}) as ws:
                payload = ws.receive_json()
                app = next(item for item in payload["applications"] if item["id"] == APP)
                assert app["status"] == "receiving" and not app["delivery"]["failed_batches"]
                event, = [event for event in app["events"] if event["request_id"] == identifier]
                assert event["status"] == 429 and event["auth"] == "rate_limited" and event["mitigation_applied"]
                assert payload["staging"]["channels"][0]["confirmed"] == {"rate_limited": 1}
                assert not payload["staging"]["channels"][0]["recoveries"]
            revision = command("revoke/" + decision["id"])
            wait_for(lambda: acknowledgment(revision, "applied"), "Revocation was not acknowledged")
            recovered = access(target, a)
            assert recovered.status_code == access(other, b).status_code == 204
            with operator.websocket_connect("ws://localhost/ws/monitored-applications", headers={"Origin": ORIGIN}) as ws:
                for _ in range(5):
                    payload = ws.receive_json()
                    evidence = payload["staging"]["channels"][0]["recoveries"]
                    if evidence:
                        break
                item, = evidence
                assert item["request_id"] == recovered.headers["x-request-id"]
                assert item["enforcement_request_id"] == identifier and item["revision"] == revision
