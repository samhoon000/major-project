"""Trusted-proxy emulation and real-loopback transport tests; not public Cloudflare proof."""
import asyncio
import json
import io
import os
import socket
import threading
import time
import unittest
from unittest.mock import MagicMock
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch

import httpx
import uvicorn
from fastapi import FastAPI
from websockets.sync.client import connect

from backend import attack_lab, chat_service
from backend.security import demo_access
from backend.security.demo_access import COOKIE, DemoExposure, DemoSecurity
from backend.security.http_flood import HTTPFloodGuard, HTTPFloodSimulator, DetectorConfig
from backend.network.tunnel import tunnel_manager

TOKEN="remote-demo-test-secret"
EDGE={"host":"demo.example","cf-connecting-ip":"203.0.113.20",
      "x-forwarded-proto":"https","origin":"https://demo.example"}


def demo_app(lab, lifespan=None):
    app=FastAPI(lifespan=lifespan)
    app.include_router(attack_lab.router)
    app.include_router(chat_service.router)
    app.include_router(demo_access.router)
    app.add_middleware(HTTPFloodGuard,controller=lab)
    app.add_middleware(DemoExposure)
    return app


class RemoteAuthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.now=100.0
        self.security=DemoSecurity(clock=lambda:self.now)
        self.lab=HTTPFloodSimulator()
        self.patches=[patch.dict(os.environ,{"ADMIN_TOKEN":TOKEN,"HTTP_FLOOD_REMOTE_ENABLED":"true",
                       "CLOUDFLARE_PUBLIC_HOSTNAME":"demo.example"}),
                      patch.object(demo_access,"demo_security",self.security),
                      patch.object(chat_service,"demo_security",self.security),
                      patch.object(tunnel_manager,"mode","named"),
                      patch.object(attack_lab,"http_flood_simulator",self.lab)]
        for item in self.patches:item.start()
        self.app=demo_app(self.lab)
        async def local_listener(scope,receive,send):
            # ASGITransport otherwise derives server from the public URL. A real
            # trusted tunnel leaves the actual listening socket in server scope.
            await self.app({**scope,"server":("127.0.0.1",8001)},receive,send)
        self.client=httpx.AsyncClient(base_url="https://demo.example",headers=EDGE,
            transport=httpx.ASGITransport(app=local_listener,client=("127.0.0.1",51000)))

    async def asyncTearDown(self):
        await self.client.aclose()
        await self.lab.close()
        for item in reversed(self.patches):item.stop()

    async def login(self):
        response=await self.client.post("/api/auth/login",json={"token":TOKEN})
        self.assertEqual(response.status_code,200,response.text)
        return response.headers["x-csrf-token"]

    async def test_unauthenticated_controls_and_sensitive_telemetry_are_rejected(self):
        for path in ("/api/chat/state","/api/network/state","/api/attack-lab/http-flood/state","/api/attack-lab/status"):
            response=await self.client.get(path)
            self.assertEqual(response.status_code,401)
            self.assertEqual(response.headers["cache-control"],"no-store")
        for action in ("start","stop","reset","unblock","monitor"):
            self.assertEqual((await self.client.post("/api/attack-lab/http-flood/"+action,json={})).status_code,403)
        for path in ("/docs","/redoc","/openapi.json","/api/upload","/api/predict","/api/dataset","/api/graph"):
            self.assertEqual((await self.client.get(path)).status_code,404)

    async def test_cookie_flags_and_secret_non_disclosure(self):
        await self.login()
        response=await self.client.post("/api/auth/login",json={"token":TOKEN})
        cookie=response.headers["set-cookie"].lower()
        self.assertIn("secure",cookie);self.assertIn("httponly",cookie);self.assertIn("samesite=strict",cookie)
        self.assertNotIn(TOKEN,response.text)
        self.assertNotIn(COOKIE,response.text)
        self.assertNotIn(TOKEN,(await self.client.get("/attack-lab")).text)
        self.assertEqual((await self.client.get("/api/attack-lab/http-flood/state")).status_code,200)

    async def test_authenticated_remote_start_stop_reset_unblock(self):
        csrf=await self.login()
        for action in ("start","stop","reset","unblock","monitor"):
            with patch.object(self.lab,"prepare" if action=="monitor" else action,
                              new_callable=AsyncMock,return_value={"status":"verified"}) as method:
                response=await self.client.post("/api/attack-lab/http-flood/"+action,
                    headers={"X-CSRF-Token":csrf},json={} if action=="start" else None)
                self.assertEqual(response.status_code,200,response.text)
                method.assert_awaited_once()
                if action in ("start","monitor"):
                    self.assertEqual(method.call_args.args[0],"http://127.0.0.1:8001")

    async def test_csrf_and_cross_origin_requests_are_rejected(self):
        csrf=await self.login()
        self.assertEqual((await self.client.post("/api/attack-lab/http-flood/stop")).status_code,403)
        self.assertEqual((await self.client.post("/api/attack-lab/http-flood/stop",headers={"X-CSRF-Token":"wrong"})).status_code,403)
        self.assertEqual((await self.client.post("/api/attack-lab/http-flood/stop",
            headers={"X-CSRF-Token":csrf,"Origin":"https://evil.example"})).status_code,403)
        self.assertEqual((await self.client.get("/api/chat/state",headers={"Origin":"https://evil.example"})).status_code,401)

    async def test_untrusted_peer_cannot_spoof_cloudflare_headers(self):
        async with httpx.AsyncClient(base_url="https://demo.example",headers=EDGE,
                transport=httpx.ASGITransport(app=self.app,client=("198.51.100.44",51000))) as client:
            self.assertEqual((await client.post("/api/auth/login",json={"token":TOKEN})).status_code,403)
            self.assertEqual((await client.post("/api/attack-lab/http-flood/start",json={},
                headers={"X-Admin-Token":TOKEN})).status_code,403)

    async def test_https_host_and_proxy_boundary_are_all_required(self):
        for override in ({"x-forwarded-proto":"http"},{"host":"evil.example"},
                         {"cf-connecting-ip":"not-an-ip"},{"origin":"https://evil.example"}):
            response=await self.client.post("/api/auth/login",headers=override,json={"token":TOKEN})
            self.assertEqual(response.status_code,403)

    async def test_remote_opt_in_and_local_header_compatibility(self):
        with patch.dict(os.environ,{"HTTP_FLOOD_REMOTE_ENABLED":"false"}):
            self.assertEqual((await self.client.post("/api/auth/login",json={"token":TOKEN})).status_code,403)
            async with httpx.AsyncClient(base_url="http://127.0.0.1:8001",
                    transport=httpx.ASGITransport(app=self.app,client=("127.0.0.1",51000))) as client:
                self.assertEqual((await client.post("/api/attack-lab/http-flood/stop",headers={"X-Admin-Token":TOKEN})).status_code,200)
                self.assertEqual((await client.get("/api/attack-lab/http-flood/state")).status_code,200)

    async def test_login_throttling_and_expiry(self):
        for _ in range(8):
            response=await self.client.post("/api/auth/login",json={"token":"wrong"})
            self.assertEqual(response.status_code,403)
        response=await self.client.post("/api/auth/login",json={"token":TOKEN})
        self.assertEqual(response.status_code,429)
        self.assertEqual(response.headers["retry-after"],"60")
        self.now+=61
        await self.login()

    async def test_session_expiry_and_admin_token_rotation(self):
        await self.login(); self.now+=1801
        self.assertEqual((await self.client.get("/api/chat/state")).status_code,401)
        await self.login()
        with patch.dict(os.environ,{"ADMIN_TOKEN":"rotated-secret"}):
            self.assertEqual((await self.client.get("/api/chat/state")).status_code,401)

    async def test_logout_revokes_session(self):
        csrf=await self.login()
        self.assertEqual((await self.client.post("/api/auth/logout",headers={"X-CSRF-Token":csrf})).status_code,200)
        self.assertEqual((await self.client.get("/api/chat/state")).status_code,401)

    async def test_dashboard_websocket_requires_session_and_matching_origin(self):
        from fastapi.testclient import TestClient
        from starlette.websockets import WebSocketDisconnect
        client=TestClient(self.app,client=("127.0.0.1",51000))
        with self.assertRaises(WebSocketDisconnect):
            with client.websocket_connect("wss://demo.example/ws/dashboard",headers=dict(EDGE)):pass
        csrf=await self.login()
        headers={**EDGE,"cookie":f"{COOKIE}={self.client.cookies[COOKIE]}"}
        with self.assertRaises(WebSocketDisconnect):
            with client.websocket_connect("wss://demo.example/ws/dashboard",
                    headers={**headers,"origin":"https://evil.example"}):pass
        with client.websocket_connect("wss://demo.example/ws/dashboard",headers=headers) as ws:
            self.assertEqual(ws.receive_json()["type"],"snapshot")
            await self.client.post("/api/auth/logout",headers={"X-CSRF-Token":csrf})
            ws.send_text("check-session")
            with self.assertRaises(WebSocketDisconnect):ws.receive_json()

    async def test_cors_rejects_arbitrary_origins(self):
        from app import app
        async with httpx.AsyncClient(base_url="http://127.0.0.1:8001",
                transport=httpx.ASGITransport(app=app,client=("127.0.0.1",51000))) as client:
            headers={"origin":"https://evil.example","access-control-request-method":"POST"}
            response=await client.options("/api/auth/login",headers=headers)
            self.assertNotIn("access-control-allow-origin",response.headers)
            self.assertEqual(response.status_code,400)

    async def test_public_connectivity_is_sanitized_and_legacy_attacks_are_private(self):
        response=await self.client.get("/api/tunnel/state")
        self.assertEqual(response.status_code,200)
        self.assertIsNone(response.json()["local_ip"])
        self.assertNotIn("events",response.json())
        self.assertEqual(response.json()["active_joining_url"],"https://demo.example/chat")
        self.assertEqual((await self.client.post("/api/attack-lab/burst",headers={"X-Admin-Token":TOKEN})).status_code,404)
        self.assertEqual((await self.client.post("/api/attack-lab/http-flood/authorize",headers={"X-Admin-Token":TOKEN})).status_code,403)

    async def test_sessions_are_bounded_and_external_target_is_rejected(self):
        csrf=await self.login()
        response=await self.client.post("/api/attack-lab/http-flood/start",headers={"X-CSRF-Token":csrf},
                                        json={"target":"https://demo.example"})
        self.assertEqual(response.status_code,422)
        self.assertIsNone(self.lab.task)
        from starlette.requests import Request
        request=Request(dict(type="http",scheme="https",method="POST",path="/api/auth/login",
            headers=[(k.encode(),v.encode()) for k,v in EDGE.items()],client=("127.0.0.1",51000),server=("127.0.0.1",8001)))
        for _ in range(140): self.security.login(request,TOKEN)
        self.assertLessEqual(len(self.security.sessions),128)


class RemoteSocketTests(unittest.TestCase):
    """Emulate cloudflared's trusted HTTP hop over actual local TCP sockets."""
    @classmethod
    def setUpClass(cls):
        cls.lab=HTTPFloodSimulator(DetectorConfig(1,3,8,2))
        cls.security=DemoSecurity()
        cls.patches=[patch.dict(os.environ,{"ADMIN_TOKEN":TOKEN,"HTTP_FLOOD_REMOTE_ENABLED":"true",
            "CLOUDFLARE_PUBLIC_HOSTNAME":"demo.example","HTTP_FLOOD_BASE_URL":""}),
            patch.object(demo_access,"demo_security",cls.security),patch.object(chat_service,"demo_security",cls.security),
            patch.object(tunnel_manager,"mode","named"),
            patch.object(attack_lab,"http_flood_simulator",cls.lab)]
        for item in cls.patches:item.start()
        @asynccontextmanager
        async def lifespan(app):
            yield
            await cls.lab.close()
        app=demo_app(cls.lab,lifespan)
        cls.sock=socket.socket();cls.sock.bind(("127.0.0.1",0));cls.sock.listen(128)
        cls.port=cls.sock.getsockname()[1]
        cls.server=uvicorn.Server(uvicorn.Config(
            app,log_level="error",access_log=False,proxy_headers=False,timeout_graceful_shutdown=3))
        cls.thread=threading.Thread(target=cls.server.run,kwargs={"sockets":[cls.sock]},daemon=True)
        cls.thread.start()
        deadline=time.monotonic()+10
        while not cls.server.started and time.monotonic()<deadline:time.sleep(.02)
        if not cls.server.started:raise RuntimeError("Local proxy-boundary test server did not start")
        cls.client=httpx.Client(base_url=f"http://127.0.0.1:{cls.port}",headers=EDGE,trust_env=False,timeout=4)
        response=cls.client.post("/api/auth/login",json={"token":TOKEN})
        if response.status_code!=200:raise AssertionError(response.text)
        cls.cookie=f"{COOKIE}={response.cookies[COOKIE]}"
        cls.headers={"Cookie":cls.cookie,"X-CSRF-Token":response.headers["X-CSRF-Token"]}

    @classmethod
    def tearDownClass(cls):
        cls.client.close();cls.server.should_exit=True;cls.thread.join(10);cls.sock.close()
        for item in reversed(cls.patches):item.stop()
        if cls.thread.is_alive():raise AssertionError("Local server did not stop")

    def command(self,action,**kwargs):
        return self.client.post("/api/attack-lab/http-flood/"+action,headers=self.headers,**kwargs)

    def viewer(self):
        # URI supplies the real public Host while sock confines transport to loopback.
        sock=socket.create_connection(("127.0.0.1",self.port),timeout=3)
        headers={k:EDGE[k] for k in ("cf-connecting-ip","x-forwarded-proto")}
        headers["Cookie"]=self.cookie
        return connect("ws://demo.example/ws/dashboard",sock=sock,proxy=None,
                       origin="https://demo.example",additional_headers=headers)

    def test_authenticated_proxy_controls_local_generator_and_two_viewers_reconnect(self):
        self.assertEqual(self.command("monitor").status_code,200)
        with self.viewer() as first,self.viewer() as second:
            self.assertEqual(json.loads(first.recv(timeout=3))["type"],"snapshot")
            self.assertEqual(json.loads(second.recv(timeout=3))["type"],"snapshot")
            self.assertEqual(self.command("start",json={"rate":25,"duration":2,"concurrency":3}).status_code,200)
            self.assertEqual(self.command("start",json={}).status_code,409)
            run_ids=[]
            for viewer in (first,second):
                deadline=time.monotonic()+5
                while time.monotonic()<deadline:
                    event=json.loads(viewer.recv(timeout=3))
                    if event["type"]=="HTTP_FLOOD_TELEMETRY" and event["flood"]["blocked"]>0:
                        run_ids.append(event["run_id"]);break
            self.assertEqual(run_ids,[self.lab.run_id,self.lab.run_id])
        with self.viewer() as reconnected:
            self.assertEqual(json.loads(reconnected.recv(timeout=3))["type"],"snapshot")
            state=self.client.get("/api/attack-lab/http-flood/state",headers=self.headers).json()
            self.assertEqual(state["run_id"],self.lab.run_id)
        deadline=time.monotonic()+5
        while self.lab.task and not self.lab.task.done() and time.monotonic()<deadline:time.sleep(.05)
        state=self.client.get("/api/attack-lab/http-flood/state",headers=self.headers).json()
        self.assertEqual(state["target_origin"],f"http://127.0.0.1:{self.port}")
        self.assertFalse(state["running"])
        self.assertLessEqual(state["flood"]["generated"],50)
        self.assertEqual(state["flood"]["generated"],
                         state["flood"]["successful"]+state["flood"]["blocked"])
        self.assertEqual(state["flood"]["failed"],0)
        self.assertGreater(state["flood"]["blocked"],0)
        self.assertEqual(state["legitimate"]["blocked"],0)
        self.assertEqual(state["legitimate"]["failed"],0)
        self.assertEqual(state["legitimate"]["success_rate"],1.0)
        self.assertEqual(state["detection_method"],"Rule-Based HTTP Flood Detection")
        self.assertEqual(self.command("stop").status_code,200)
        self.assertFalse(self.command("unblock").json()["blocked"])
        self.assertEqual(self.command("reset").json()["status"],"ready")


class TunnelLifecycleTests(unittest.TestCase):
    def test_quick_tunnel_needs_no_token_and_pins_its_own_hostname(self):
        from backend.network.tunnel import TunnelManager
        manager=TunnelManager(token="",mode="quick",local_port=8001)
        process=MagicMock();process.poll.return_value=None
        process.stdout=io.StringIO("https://first-demo.trycloudflare.com\nRegistered tunnel connection connIndex=0\nhttps://other-demo.trycloudflare.com\n")
        with patch.object(manager,"find_cloudflared_executable",return_value="cloudflared"), \
                patch("backend.network.tunnel.subprocess.Popen",return_value=process) as launch:
            self.assertTrue(manager.start());manager._monitor_thread.join(1)
            self.assertEqual(launch.call_args.args[0],
                ["cloudflared","tunnel","--url","http://127.0.0.1:8001","--no-autoupdate"])
            self.assertNotIn("TUNNEL_TOKEN",launch.call_args.kwargs["env"])
            self.assertEqual(manager.public_hostname,"first-demo.trycloudflare.com")
            self.assertTrue(manager.edge_connected)
            self.assertFalse(manager.public_hostname_verified)
            manager.stop()

    def test_quick_origin_and_cors_follow_only_manager_assigned_hostname(self):
        middleware=demo_access.DemoCORSMiddleware(None,allow_origins=[])
        with patch.object(tunnel_manager,"mode","quick"), \
                patch.object(tunnel_manager,"public_hostname",None), \
                patch.dict(os.environ,{"CLOUDFLARE_PUBLIC_HOSTNAME":"untrusted.example"}):
            self.assertIsNone(demo_access.public_origin())
            self.assertFalse(middleware.is_allowed_origin("https://untrusted.example"))
            tunnel_manager.public_hostname="first-demo.trycloudflare.com"
            self.assertEqual(demo_access.public_origin(),"https://first-demo.trycloudflare.com")
            self.assertTrue(middleware.is_allowed_origin("https://first-demo.trycloudflare.com"))
            self.assertFalse(middleware.is_allowed_origin("https://other-demo.trycloudflare.com"))

    def test_tunnel_secret_is_passed_in_environment_only(self):
        from backend.network.tunnel import TunnelManager
        manager=TunnelManager(token="test-secret",public_hostname="demo.example")
        process=MagicMock();process.poll.return_value=None;process.stdout=io.StringIO("")
        with patch.object(manager,"find_cloudflared_executable",return_value="cloudflared"), \
                patch("backend.network.tunnel.subprocess.Popen",return_value=process) as launch:
            self.assertTrue(manager.start())
            manager._monitor_thread.join(1)
            self.assertNotIn("test-secret",str(launch.call_args.args))
            self.assertEqual(launch.call_args.kwargs["env"]["TUNNEL_TOKEN"],"test-secret")
            self.assertNotIn("ADMIN_TOKEN",launch.call_args.kwargs["env"])
            manager.stop()

    def test_disconnection_and_reconnection_report_actual_edge_state(self):
        from backend.network.tunnel import TunnelManager
        manager=TunnelManager(token="test-tunnel-secret",public_hostname="demo.example",local_port=8001)
        process=MagicMock();process.poll.return_value=None
        observed=[]
        def lines():
            yield "INF Registered tunnel connection connIndex=0\n"
            observed.append((manager.status,manager.edge_connected))
            yield "ERR Connection terminated connIndex=0\n"
            observed.append((manager.status,manager.edge_connected))
            yield "INF Registered tunnel connection connIndex=0\n"
            observed.append((manager.status,manager.edge_connected))
            yield ""
        process.stdout.readline.side_effect=iter(lines())
        manager.process=process
        manager._monitor_output()
        self.assertEqual(observed,[("running",True),("reconnecting",False),("running",True)])
        with patch("backend.network.tunnel.get_lan_ipv4",return_value="192.168.1.5"):
            state=manager.status_dict()
        self.assertEqual(state["attack_lab_url"],"https://demo.example/attack-lab")
        self.assertEqual(state["dashboard_websocket_url"],"wss://demo.example/ws/dashboard")
        self.assertFalse(state["public_hostname_verified"])

    def test_one_edge_loss_does_not_mark_other_connections_offline_and_logs_redact_secret(self):
        from backend.network.tunnel import TunnelManager
        manager=TunnelManager(token="test-secret",public_hostname="demo.example")
        process=MagicMock();process.poll.return_value=None
        process.stdout.readline.side_effect=iter([
            "Registered tunnel connection connIndex=0\n","Registered tunnel connection connIndex=1\n",
            "Unregistered tunnel connection connIndex=0 test-secret\n",""])
        manager.process=process;manager._monitor_output()
        self.assertTrue(manager.edge_connected)
        self.assertEqual(manager.status,"running")
        self.assertNotIn("test-secret","".join(manager._recent_logs))


if __name__=="__main__":unittest.main()
