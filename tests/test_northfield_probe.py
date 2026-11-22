import asyncio
import os
import time

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend import attack_lab
from backend.network import northfield_probe as probe
from backend.network.runtime import NetworkRuntime
from backend.security.demo_access import router as auth_router
from test_staging_mitigation import loopback, northfield


def test_probe_routes_require_local_operator_and_accept_no_target(monkeypatch):
    app = FastAPI()
    app.include_router(auth_router)
    app.include_router(attack_lab.router)
    origin = "http://127.0.0.1"
    api = "/api/attack-lab/northfield-probe"
    monkeypatch.setenv("ADMIN_TOKEN", "disposable-probe-operator")
    monkeypatch.delenv("SENTINEL_NORTHFIELD_PROBE", raising=False)
    with TestClient(app, base_url=origin, client=("127.0.0.1", 50000)) as client:
        assert client.get(api).status_code == 404
        monkeypatch.setenv("SENTINEL_NORTHFIELD_PROBE", "1")
        assert client.get(api).status_code == 401
        login = client.post("/api/auth/login", json={"token": "disposable-probe-operator"}, headers={"Origin": origin})
        assert login.status_code == 200
        assert client.get("/attack-lab?view=northfield").status_code == 200
        assert client.get(api, headers={"X-Forwarded-For": "198.51.100.2"}).status_code == 404
        assert client.post(api + "/start", headers={"Origin": origin}).status_code == 403
        headers = {"Origin": origin, "X-CSRF-Token": login.headers["x-csrf-token"]}
        assert client.post(api + "/start", json={"target": "invalid.example"}, headers=headers).status_code == 422
        assert client.post(api + "/start?requests=500", headers=headers).status_code == 422


def test_probe_timeout_cancellation_and_reset_do_not_remove_cooldown(monkeypatch):
    received = []
    app = FastAPI()

    @app.get("/health")
    async def health():
        received.append(1)
        await asyncio.sleep(2)
        return {"status": "ok"}

    async def checks():
        instance = probe.NorthfieldProbe()
        assert instance.start()
        assert instance.start() is None
        await instance.task
        assert instance.runs[0]["result"] == "timed_out"
        assert received == [1]
        await instance.reset()
        assert not instance.runs and instance.start() is None
        second = probe.NorthfieldProbe()
        assert second.start()
        await second.stop()
        assert second.runs[0]["result"] == "cancelled"
        assert received == [1]

    with loopback(app) as origin:
        monkeypatch.setattr(probe, "HEALTH_URL", origin + "/health")
        monkeypatch.setattr(probe, "DEADLINE", 1.5)
        asyncio.run(checks())


def test_probe_correlates_only_the_exact_tcp_endpoints_and_run_window():
    run = {"client": ("127.0.0.1", 51000), "server": ("127.0.0.1", 8000),
           "started_at": 10.0, "finished_at": 11.0}
    flow = {"source_ip": "127.0.0.1", "destination_ip": "127.0.0.1", "source_port": 8000,
            "destination_port": 51000, "protocol": "TCP", "start_time": 10.5}
    assert probe.matches_flow(run, flow)
    assert not probe.matches_flow(run, {**flow, "destination_port": 51001})
    assert not probe.matches_flow(run, {**flow, "protocol": "UDP"})
    assert not probe.matches_flow(run, {**flow, "start_time": 9.99})
    assert not probe.matches_flow(run, {**flow, "start_time": 11.01})


@pytest.mark.skipif(os.getenv("SENTINEL_TEST_NPCAP") != "1", reason="Needs an accessible Windows Npcap loopback device")
def test_real_northfield_response_correlates_with_live_npcap_flow_and_gatv2(northfield, tmp_path, monkeypatch):
    portal_db = tmp_path / "portal.sqlite3"
    engine = northfield["db"].make_engine(portal_db)
    models = northfield["models"]
    models.Base.metadata.create_all(engine)
    password = "disposable-probe-student-password"
    with northfield["db"].make_sessions(engine).begin() as session:
        session.add(models.User(email="network.student@example.com", full_name="Demo Student",
                                student_id="NF-NETWORK", role="student",
                                password_hash=northfield["security"].passwords.hash(password)))
    engine.dispose()
    settings = northfield["config"].Settings(_env_file=None, database_url="", app_env="test", sqlite_path=portal_db,
                                              jwt_secret="synthetic-northfield-probe-jwt-test")
    app = northfield["main"].create_app(settings)

    async def verify(origin):
        instance = probe.NorthfieldProbe()
        runtime = NetworkRuntime()

        async def analyzed(run):
            for _ in range(120):
                flows = runtime.status()["completed_flows"]
                if match := next((item for item in flows if item.get("network_inference") and probe.matches_flow(run, item)), None):
                    return match
                await asyncio.sleep(.1)
            seen = [(flow["source_port"], flow["destination_port"], flow["start_time"], flow.get("gatv2_status"))
                    for flow in flows]
            pytest.fail(f"No analyzed flow for {run.get('client')} to {run.get('server')}. Captured: {seen}")

        try:
            await runtime.start()
            for _ in range(150):
                if runtime.capture and runtime.capture.status != "starting":
                    break
                await asyncio.sleep(.1)
            assert runtime.status()["capture"] == "running", runtime.status()["capture_error"]
            async with httpx.AsyncClient(base_url=origin, trust_env=False, headers={"Connection": "close"}) as student:
                login = await student.post("/api/auth/login", json={"email": "network.student@example.com", "password": password})
                assert login.status_code == 200
                baseline = {"started_at": time.time()}
                async with student.stream("GET", "/api/dashboard/stats") as response:
                    assert response.status_code == 200
                    stream = response.extensions.get("network_stream")
                    baseline["client"] = probe.socket_address(stream, "client_addr")
                    baseline["server"] = probe.socket_address(stream, "server_addr")
                    await response.aread()
                baseline["finished_at"] = time.time()
                baseline_flow = await analyzed(baseline)

                assert instance.start()
                await instance.task
                run = instance.runs[0]
                assert run["status"] == 200
                assert run["client"][0] == run["server"][0] == "127.0.0.1"
                await analyzed(run)
                snapshot = instance.snapshot(runtime.status())
                flow, = snapshot["runs"][0]["flows"]
                assert (await student.get("/api/dashboard/stats")).status_code == 200
            inference = flow["network_inference"]
            assert flow["total_packets"] > 0 and flow["total_bytes"] > 0 and flow["duration"] > 0
            assert inference["source"] == "GATv2" and inference["graph_id"]
            assert inference["nodes"] >= 1 and inference["edges"] >= 1
            assert 0 <= inference["anomaly_probability"] <= 1
            assert inference["prediction"] == ("ATTACK" if inference["anomaly_probability"] >= inference["threshold"] else "BENIGN")
            print({"baseline_http": 200, "packets": baseline_flow["total_packets"], "bytes": baseline_flow["total_bytes"],
                   "features": baseline_flow["features"], "inference": baseline_flow["network_inference"]})
            print({"http": run["status"], "latency_ms": run["latency_ms"], "packets": flow["total_packets"],
                   "bytes": flow["total_bytes"], "duration_s": flow["duration"], "features": flow["features"],
                   "flow": flow["flow_id"], "interface": snapshot["interface"], "inference": inference})
        finally:
            await runtime.stop()

    with loopback(app) as origin:
        port = httpx.URL(origin).port
        monkeypatch.setattr(probe, "HEALTH_URL", origin + "/health")
        monkeypatch.setenv("NETWORK_INTERFACE", r"\Device\NPF_Loopback")
        monkeypatch.setenv("NETWORK_CAPTURE_FILTER", f"ip and tcp and host 127.0.0.1 and port {port}")
        monkeypatch.setenv("FLOW_IDLE_TIMEOUT", "2")
        monkeypatch.setenv("GATV2_INFERENCE_WINDOW_SECONDS", "1")
        monkeypatch.setenv("NETWORK_AUTO_QUARANTINE", "false")
        asyncio.run(verify(origin))
