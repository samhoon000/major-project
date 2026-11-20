"""Deterministic policy tests and real TCP/HTTP integration (no attack on external hosts)."""
import asyncio
import json
import os
import socket
import threading
import time
import unittest
from contextlib import asynccontextmanager
from unittest.mock import patch, AsyncMock

import httpx
import uvicorn
from fastapi import FastAPI
from pydantic import ValidationError
from websockets.sync.client import connect

from backend.security.http_flood import (
    DetectorConfig, HTTPFloodGuard, HTTPFloodSimulator, RunConfig, HEADER, TARGET, validate_base_url,
)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.lab = HTTPFloodSimulator(DetectorConfig(2, 2, 4, 3),
                                      clock=lambda:self.now, wall_clock=lambda:self.now)

    def test_normal_traffic_and_idle_rate_decay(self):
        self.assertFalse(self.lab.observe("flood"))
        self.assertFalse(self.lab.get_state()["detected"])
        self.now += 3
        state = self.lab.get_state()
        self.assertEqual(state["total_rps"], 0)
        self.assertEqual(len(self.lab.source_windows["flood"]), 0)

    def test_detection_is_observed_without_start_command(self):
        # The detector also works when no generator/start event has occurred.
        for _ in range(7):
            self.assertFalse(self.lab.observe("flood"))
        self.assertTrue(self.lab.observe("flood"))
        state = self.lab.get_state()
        self.assertTrue(state["detected"])
        self.assertTrue(state["blocked"])
        self.assertEqual(state["detection_rps"], 4)
        types = [e["type"] for e in state["timeline"]]
        self.assertLess(types.index("HTTP_RATE_WARNING"), types.index("HTTP_FLOOD_ATTACK_DETECTED"))
        self.assertIn("HTTP_MITIGATION_ACTIVATED", types)

    def test_correct_source_and_accounting(self):
        for _ in range(12):
            self.lab.observe("flood")
        for _ in range(3):
            self.assertFalse(self.lab.observe("legitimate"))
        state = self.lab.get_state()
        self.assertEqual(state["flood"]["accepted"], 7)
        self.assertEqual(state["flood"]["rejected"], 5)
        self.assertEqual(state["legitimate"]["rejected"], 0)
        self.assertEqual(state["accepted_rps"]+state["blocked_rps"], state["total_rps"])
        self.assertEqual(len(state["recent_rejections"]),5)

    def test_expiry_and_recovery(self):
        for _ in range(8):
            self.lab.observe("flood")
        self.lab.ended = self.now
        self.now += 4
        state = self.lab.get_state()
        self.assertFalse(state["blocked"])
        self.assertTrue(state["recovered"])
        self.assertFalse(self.lab.observe("flood"))
        self.assertEqual(sum(e["type"]=="HTTP_SOURCE_UNBLOCKED" for e in state["timeline"]),1)

    def test_memory_and_secrets_are_bounded(self):
        for _ in range(5000):
            self.lab.observe("flood")
        state = self.lab.get_state()
        self.assertLessEqual(len(self.lab.traffic),4096)
        self.assertLessEqual(len(state["timeline"]),200)
        self.assertLessEqual(len(state["recent_rejections"]),200)
        self.assertIn("HTTP_FLOOD_ATTACK_DETECTED",[e["type"] for e in state["timeline"]])
        self.assertLessEqual(len(self.lab.pending_events),500)
        for capability in self.lab.keys.values():
            self.assertNotIn(capability,json.dumps(state))

    def test_configuration_limits(self):
        for config in ({"rate":0},{"rate":51},{"duration":21},{"duration":float("nan")},
                       {"concurrency":9},{"rate":True},{"target":"http://example.com"}):
            with self.subTest(config=config), self.assertRaises(ValidationError):
                RunConfig(**config)
        for values in ((0,1,2,3),(2,4,2,3),(2,1,2,0),(2,1,float("inf"),3)):
            with self.assertRaises(ValueError):
                DetectorConfig(*values)

    def test_external_dns_redirect_and_arbitrary_target_rejection(self):
        for url in ("http://example.com:80", "http://8.8.8.8:8000", "https://x.trycloudflare.com",
                    "http://192.168.1.1:8000", "http://localhost:8000", "http://127.0.0.1:8000/chat",
                    "http://user:password@127.0.0.1:8000", "https://127.0.0.1:8000",
                    "http://127.0.0.1:8000?target=x", "http://127.0.0.1:8000#x"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_base_url(url)
        self.assertEqual(validate_base_url("http://127.0.0.1:8000/"),"http://127.0.0.1:8000")

    def test_gat_evidence_requires_tuple_time_and_model_result(self):
        from backend.network.runtime import network_runtime
        self.lab.started = 100
        self.lab.detected_at = 101
        self.lab.endpoints.add(("127.0.0.1",51000,"127.0.0.1",8000))
        flow = dict(source_ip="127.0.0.1",source_port=51000,destination_ip="127.0.0.1",
                    destination_port=8000,protocol="TCP",start_time=100,gatv2_status="analyzed",
                    gatv2_prediction="ATTACK",gatv2_anomaly_probability=.9,flow_id="test-evidence")
        with patch.object(network_runtime,"completed_flows",[dict(flow,start_time=99),dict(flow,source_port=51001)]):
            self.assertEqual(self.lab.get_state()["gatv2"]["evidence"],[])
            self.assertEqual(self.lab.get_state()["detection_method"],"Rule-Based HTTP Flood Detection")
        with patch.object(network_runtime,"completed_flows",[flow]):
            self.assertEqual(self.lab.get_state()["detection_method"],"Rule-Based HTTP Flood Detection")
            self.assertEqual(self.lab.get_state()["gatv2"]["status"],"associated")

    def test_tunnel_status_caches_and_does_not_queue_native_discovery(self):
        from backend.network.tunnel import TunnelManager
        manager=TunnelManager(token="",local_port=8001)
        with patch("backend.network.tunnel.get_lan_ipv4",return_value="192.168.1.5") as lookup:
            self.assertEqual(manager.status_dict()["local_ip"],"192.168.1.5")
            self.assertEqual(manager.status_dict()["local_url"],"http://192.168.1.5:8001")
            lookup.assert_called_once()
            manager._local_ip_checked=0
            manager._local_ip_refresh_lock.acquire()
            try:
                self.assertEqual(manager.status_dict()["local_ip"],"192.168.1.5")
                lookup.assert_called_once()
            finally:
                manager._local_ip_refresh_lock.release()


class AsyncLabTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.lab=HTTPFloodSimulator(DetectorConfig(1,2,4,1))
        self.probe = patch.object(self.lab,"_probe_origin",new_callable=AsyncMock)
        self.probe.start()

    async def asyncTearDown(self):
        await self.lab.close()
        self.probe.stop()

    async def test_manual_unblock(self):
        for _ in range(4): self.lab.observe("flood")
        self.assertFalse((await self.lab.unblock())["blocked"])
        self.assertFalse(self.lab.observe("flood"))

    async def test_concurrent_start_and_immediate_cancellation(self):
        results=await asyncio.gather(self.lab.start("http://127.0.0.1:1"),
                                     self.lab.start("http://127.0.0.1:1"),return_exceptions=True)
        self.assertEqual(sum(isinstance(x,ValueError) for x in results),1)
        state=await self.lab.stop()
        self.assertFalse(state["running"])
        self.assertIsNotNone(state["stopped_at"])

    async def test_reset_cannot_race_active_run_and_rotates_capabilities(self):
        before=dict(self.lab.keys)
        await self.lab.start("http://127.0.0.1:1")
        with self.assertRaises(ValueError): await self.lab.reset()
        with self.assertRaises(ValueError): await self.lab.unblock()
        await self.lab.stop()
        state=await self.lab.reset()
        self.assertEqual(state["status"],"ready")
        self.assertEqual(state["flood"]["generated"],0)
        self.assertNotEqual(before,self.lab.keys)
        self.assertFalse(state["monitoring"])

    async def test_shutdown_cancels_every_background_task(self):
        await self.lab.start("http://127.0.0.1:1")
        tasks=[self.lab.task,self.lab.monitor_task,self.lab.publisher_task]
        await self.lab.close()
        self.assertTrue(all(t.done() for t in tasks))
        with self.assertRaises(ValueError): await self.lab.prepare("http://127.0.0.1:1")

    async def test_target_capability_boundary_and_429(self):
        from starlette.responses import JSONResponse
        async def target(scope,receive,send):
            await JSONResponse({"status":"ok"})(scope,receive,send)
        guard=HTTPFloodGuard(target,self.lab)
        transport=httpx.ASGITransport(app=guard,client=("127.0.0.1",51000))
        async with httpx.AsyncClient(transport=transport,base_url="http://localhost") as client:
            self.assertEqual((await client.get(TARGET)).status_code,403)
            headers={HEADER:self.lab.keys["flood"]}
            self.assertEqual((await client.get(TARGET,headers={**headers,"cf-connecting-ip":"1.2.3.4"})).status_code,403)
            codes=[(await client.get(TARGET,headers=headers)).status_code for _ in range(6)]
            self.assertEqual(codes,[200,200,200,429,429,429])
            response=await client.get(TARGET,headers=headers)
            self.assertIn("Retry-After",response.headers)
            self.assertEqual((await client.get(TARGET,headers={HEADER:self.lab.keys["legitimate"]})).status_code,200)
        transport=httpx.ASGITransport(app=guard,client=("192.168.1.50",51000))
        async with httpx.AsyncClient(transport=transport,base_url="http://localhost") as client:
            self.assertEqual((await client.get(TARGET,headers=headers)).status_code,403)

    async def test_network_failure_is_counted_honestly(self):
        async with httpx.AsyncClient(base_url="http://127.0.0.1:1",trust_env=False,timeout=.1) as client:
            await self.lab._request(client,"flood")
        state=self.lab.get_state()
        self.assertEqual(state["flood"]["generated"],1)
        self.assertEqual(state["flood"]["failed"],1)
        self.assertFalse(state["detected"])
        self.assertIsNotNone(state["error"])

    async def test_broadcast_uses_existing_dashboard_mechanism(self):
        from backend.chat_service import state
        self.lab.observe("flood")
        with patch.object(state,"broadcast_dashboard",new_callable=AsyncMock) as broadcast:
            await self.lab._publish()
        snapshot=broadcast.call_args.args[0]
        self.assertEqual(snapshot["type"],"HTTP_FLOOD_TELEMETRY")
        self.assertEqual(snapshot["flood"]["received"],1)
        self.assertEqual(snapshot["samples"][-1]["total_rps"],1)

    async def test_wrong_local_listener_cannot_receive_a_flood(self):
        self.probe.stop()
        observed=[]
        def unrelated(request):
            observed.append(request)
            return httpx.Response(200,json={"status":"ok","run_id":"another-app"})
        with patch.object(self.lab,"_client",side_effect=lambda _:httpx.AsyncClient(
                base_url="http://127.0.0.1:1234",transport=httpx.MockTransport(unrelated))):
            with self.assertRaises(ValueError):
                await self.lab.start("http://127.0.0.1:1234")
        self.assertEqual(len(observed),1)
        self.assertIsNone(self.lab.task)
        self.assertEqual(self.lab.counts["flood"]["generated"],0)

    async def test_slow_tunnel_discovery_does_not_block_http_or_event_loop(self):
        from app import app
        from backend.network.tunnel import tunnel_manager
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        def slow_status():
            entered.set()
            release.wait(3)
            finished.set()
            return {"status":"disabled"}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="http://localhost") as client:
            with patch.object(tunnel_manager,"status_dict",side_effect=slow_status):
                pending=asyncio.create_task(client.get("/api/tunnel/state"))
                try:
                    self.assertTrue(await asyncio.to_thread(entered.wait,2))
                    response=await client.get("/api/attack-lab/http-flood/state")
                    self.assertEqual(response.status_code,200)
                    self.assertFalse(finished.is_set(),"Telemetry must respond while adapter discovery is still blocked")
                    self.assertFalse(pending.done())
                finally:
                    release.set()
                self.assertEqual((await pending).status_code,200)


class RealSocketTests(unittest.TestCase):
    """Actual loopback Uvicorn + httpx sockets, existing routers and WebSocket bus."""
    @classmethod
    def setUpClass(cls):
        from backend import attack_lab
        from backend.chat_service import router
        cls.lab=HTTPFloodSimulator(DetectorConfig(1,3,8,2))
        cls.patch=patch.object(attack_lab,"http_flood_simulator",cls.lab)
        cls.patch.start()
        cls.env=patch.dict(os.environ,{"ADMIN_TOKEN":"http-lab-test-secret","HTTP_FLOOD_BASE_URL":""})
        cls.env.start()
        @asynccontextmanager
        async def lifespan(app):
            yield
            await cls.lab.close()
        app=FastAPI(lifespan=lifespan)
        app.include_router(attack_lab.router)
        app.include_router(router)
        app.add_middleware(HTTPFloodGuard,controller=cls.lab)
        cls.sock=socket.socket()
        cls.sock.bind(("127.0.0.1",0))
        cls.sock.listen(128)
        cls.port=cls.sock.getsockname()[1]
        cls.server=uvicorn.Server(uvicorn.Config(
            app,log_level="error",access_log=False,timeout_graceful_shutdown=3))
        cls.thread=threading.Thread(target=cls.server.run,kwargs={"sockets":[cls.sock]},daemon=True)
        cls.thread.start()
        deadline=time.monotonic()+10
        while not cls.server.started and time.monotonic()<deadline: time.sleep(.02)
        if not cls.server.started: raise RuntimeError("Local test server failed to start")
        cls.client=httpx.Client(base_url=f"http://127.0.0.1:{cls.port}",trust_env=False,timeout=4)
        cls.headers={"X-Admin-Token":"http-lab-test-secret"}

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        cls.server.should_exit=True
        cls.thread.join(10)
        cls.sock.close()
        cls.patch.stop(); cls.env.stop()
        if cls.thread.is_alive(): raise AssertionError("Test server failed to stop")

    def setUp(self):
        self.client.post("/api/attack-lab/http-flood/stop",headers=self.headers)
        self.client.post("/api/attack-lab/http-flood/reset",headers=self.headers)

    def command(self,action,**kwargs):
        return self.client.post("/api/attack-lab/http-flood/"+action,headers=self.headers,**kwargs)

    def state(self):
        return self.client.get("/api/attack-lab/http-flood/state").json()

    def test_controls_require_direct_local_admin(self):
        for action in ("start","stop","reset","monitor","unblock","authorize"):
            self.assertEqual(self.client.post("/api/attack-lab/http-flood/"+action,json={}).status_code,403)
            self.assertEqual(self.client.post("/api/attack-lab/http-flood/"+action,
                headers={**self.headers,"cf-connecting-ip":"203.0.113.3"},json={}).status_code,403)
        self.assertEqual(self.client.post("/api/attack-lab/burst").status_code,403)
        self.assertEqual(self.client.get(TARGET).status_code,403)
        self.assertEqual(self.command("start",json={"rate":51}).status_code,422)
        self.assertEqual(self.command("start",json={"target":"https://example.com"}).status_code,422)

    def test_actual_traffic_detection_block_recovery_and_websocket(self):
        from backend.network.enforcement import WindowsFirewall
        with patch.object(WindowsFirewall,"block") as firewall:
            self.assertEqual(self.command("monitor").status_code,200)
            time.sleep(1.1)
            self.assertGreater(self.state()["legitimate"]["successful"],0)
            with connect(f"ws://127.0.0.1:{self.port}/ws/dashboard",origin=f"http://127.0.0.1:{self.port}") as ws:
                self.assertEqual(json.loads(ws.recv(timeout=3))["type"],"snapshot")
                self.assertEqual(self.command("start",json={"rate":25,"duration":2,"concurrency":3}).status_code,200)
                self.assertEqual(self.command("start",json={}).status_code,409)
                deadline=time.monotonic()+5
                received=[]
                while time.monotonic()<deadline:
                    event=json.loads(ws.recv(timeout=3)); received.append(event)
                    if event["type"]=="HTTP_FLOOD_TELEMETRY" and event["flood"]["blocked"]>0: break
                self.assertTrue(any(e["type"]=="HTTP_FLOOD_ATTACK_DETECTED" for e in received))
                deadline=time.monotonic()+5
                while self.state()["running"] and time.monotonic()<deadline: time.sleep(.1)
                state=self.state()
                flood=state["flood"]
                self.assertFalse(state["running"])
                # Slow sockets can fill the concurrency limit and skip a dispatch slot.
                self.assertLessEqual(flood["generated"],50)
                self.assertEqual(flood["failed"],0)
                self.assertEqual(flood["generated"],flood["successful"]+flood["blocked"])
                self.assertEqual(flood["received"],flood["generated"])
                self.assertGreater(flood["blocked"],0)
                self.assertEqual(state["legitimate"]["failed"],0)
                self.assertEqual(state["legitimate"]["blocked"],0)
                self.assertEqual(self.client.get("/chat").status_code,200)
                self.assertTrue(any(p["blocked_rps"]>0 for p in state["samples"]))
                self.assertTrue(self.lab.endpoints,"Actual TCP client/server endpoints must be recorded")
                deadline=time.monotonic()+4
                while not self.state()["recovered"] and time.monotonic()<deadline: time.sleep(.1)
                self.assertTrue(self.state()["recovered"])
            firewall.assert_not_called()

    def test_stop_manual_unblock_reset_and_repeat(self):
        self.command("start",json={"rate":30,"duration":10,"concurrency":2})
        deadline=time.monotonic()+3
        while not self.state()["detected"] and time.monotonic()<deadline: time.sleep(.05)
        self.assertTrue(self.state()["detected"])
        self.assertEqual(self.command("reset").status_code,409)
        self.assertEqual(self.command("stop").status_code,200)
        count=self.state()["flood"]["generated"]
        time.sleep(.2)
        self.assertEqual(self.state()["flood"]["generated"],count)
        self.assertFalse(self.command("unblock").json()["blocked"])
        self.assertTrue(self.state()["recovered"])
        self.assertEqual(self.command("reset").json()["status"],"ready")
        self.assertEqual(self.command("start",json={"rate":2,"duration":1,"concurrency":1}).status_code,200)
        time.sleep(1.2)
        self.assertFalse(self.state()["detected"])


if __name__=="__main__":
    unittest.main()
