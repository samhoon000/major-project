"""Targeted automated tests for secure remote operator access via Cloudflare."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app import app
from backend.network.tunnel import tunnel_manager
from backend.security import demo_access
from backend.security.demo_access import COOKIE, DemoSecurity

ADMIN_TOKEN = "xjhDJRyueegte9K_WVxtJbhGF26s6D08QdaPfCcg0s8"
PUBLIC_HOST = "sentinel-operator.example.com"
EDGE_HEADERS = {
    "host": PUBLIC_HOST,
    "cf-connecting-ip": "198.51.100.25",
    "x-forwarded-proto": "https",
    "origin": f"https://{PUBLIC_HOST}",
}


class TestRemoteOperatorAccess(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.patches = [
            patch.dict(os.environ, {
                "ADMIN_TOKEN": ADMIN_TOKEN,
                "DASHBOARD_REMOTE_ENABLED": "true",
                "HTTP_FLOOD_REMOTE_ENABLED": "false",
                "CLOUDFLARE_PUBLIC_HOSTNAME": PUBLIC_HOST,
            }),
            patch.object(tunnel_manager, "mode", "named"),
            patch.object(tunnel_manager, "public_hostname", PUBLIC_HOST),
            patch.object(tunnel_manager, "status", "running"),
        ]
        for p in self.patches:
            p.start()

        async def local_listener(scope, receive, send):
            await app({**scope, "server": ("127.0.0.1", 8001)}, receive, send)

        self.client = httpx.AsyncClient(
            base_url=f"https://{PUBLIC_HOST}",
            headers=EDGE_HEADERS,
            transport=httpx.ASGITransport(app=local_listener, client=("127.0.0.1", 51234)),
            follow_redirects=False,
        )

    async def asyncTearDown(self):
        await self.client.aclose()
        for p in reversed(self.patches):
            p.stop()
        demo_access.demo_security.sessions.clear()

    async def test_unauthenticated_operator_pages_redirect_to_signin(self):
        pages = [
            "/dashboard",
            "/dashboard/applications",
            "/attack-lab",
            "/dashboard/network",
            "/dashboard/chat",
            "/dashboard/settings",
        ]
        for route in pages:
            res = await self.client.get(route)
            self.assertEqual(res.status_code, 303, f"{route} did not redirect (status: {res.status_code})")
            location = res.headers.get("location", "")
            self.assertIn("/operator/sign-in", location, f"{route} redirect target was {location}")
            self.assertIn(f"next={route}", location.replace("%2F", "/"))

    async def test_unauthenticated_root_redirects_to_dashboard(self):
        res = await self.client.get("/")
        self.assertEqual(res.status_code, 307)
        self.assertEqual(res.headers.get("location"), "/dashboard")

    async def test_unauthenticated_chat_remains_open(self):
        res = await self.client.get("/chat")
        self.assertEqual(res.status_code, 200)
        self.assertIn("<!doctype html>", res.text.lower())
        self.assertIn("chat", res.text.lower())

    async def test_unauthenticated_sensitive_apis_return_401(self):
        sensitive_apis = [
            "/api/network/state",
            "/api/chat/state",
            "/api/attack-lab/status",
        ]
        for api in sensitive_apis:
            res = await self.client.get(api)
            self.assertEqual(res.status_code, 401, f"{api} returned {res.status_code}")
            self.assertEqual(res.headers.get("cache-control"), "no-store")

    async def test_unauthenticated_public_tunnel_metadata_sanitized(self):
        res = await self.client.get("/api/tunnel/state")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("public_url"), f"https://{PUBLIC_HOST}")
        self.assertIsNone(data.get("local_ip"))
        self.assertIsNone(data.get("local_url"))

    async def test_unauthenticated_private_admin_apis_hidden_with_404(self):
        hidden_apis = [
            "/api/upload",
            "/api/predict",
            "/api/dataset",
            "/api/graph",
            "/docs",
            "/redoc",
            "/openapi.json",
        ]
        for api in hidden_apis:
            res = await self.client.get(api)
            self.assertEqual(res.status_code, 404, f"{api} returned {res.status_code}")

    async def test_authenticated_operator_access_to_all_pages_and_apis(self):
        # 1. Sign in
        login_res = await self.client.post("/api/auth/login", json={"token": ADMIN_TOKEN})
        self.assertEqual(login_res.status_code, 200)
        csrf_token = login_res.headers.get("x-csrf-token")
        self.assertTrue(csrf_token)
        self.assertIn(COOKIE, login_res.cookies)

        # 2. Check session endpoint
        session_res = await self.client.get("/api/auth/session")
        self.assertEqual(session_res.status_code, 200)
        self.assertTrue(session_res.json().get("authenticated"))
        self.assertTrue(session_res.json().get("remote_console"))

        # 3. Access all 6 operator dashboard pages
        pages = [
            ("/dashboard", "Overview"),
            ("/dashboard/applications", "Monitored Applications"),
            ("/attack-lab", "Attack Lab"),
            ("/dashboard/network", "Network Analysis"),
            ("/dashboard/chat", "Chat Security"),
            ("/dashboard/settings", "Settings"),
        ]
        for route, expected_title in pages:
            res = await self.client.get(route)
            self.assertEqual(res.status_code, 200, f"Access to {route} failed with {res.status_code}")
            self.assertIn(expected_title, res.text)
            self.assertEqual(res.headers.get("cache-control"), "no-store")

        # 4. Access sensitive APIs with authenticated session
        for api in ["/api/network/state", "/api/chat/state", "/api/attack-lab/status"]:
            res = await self.client.get(api)
            self.assertEqual(res.status_code, 200, f"API {api} failed with {res.status_code}")
            self.assertEqual(res.headers.get("cache-control"), "no-store")

        # 5. Authenticated tunnel state returns full details
        tunnel_res = await self.client.get("/api/tunnel/state")
        self.assertEqual(tunnel_res.status_code, 200)
        self.assertEqual(tunnel_res.json().get("status"), "running")

    async def test_websocket_endpoints_require_authentication_over_tunnel(self):
        client = TestClient(app, client=("127.0.0.1", 51234))

        # Unauthenticated /ws/dashboard rejected
        with self.assertRaises(WebSocketDisconnect) as ctx:
            with client.websocket_connect(
                f"wss://{PUBLIC_HOST}/ws/dashboard",
                headers=dict(EDGE_HEADERS),
            ):
                pass
        self.assertEqual(ctx.exception.code, 1008)

        # Unauthenticated /ws/monitored-applications rejected
        with self.assertRaises(WebSocketDisconnect) as ctx:
            with client.websocket_connect(
                f"wss://{PUBLIC_HOST}/ws/monitored-applications",
                headers=dict(EDGE_HEADERS),
            ):
                pass
        self.assertEqual(ctx.exception.code, 1008)

        # Authenticate
        login_res = await self.client.post("/api/auth/login", json={"token": ADMIN_TOKEN})
        cookie_val = self.client.cookies[COOKIE]
        auth_headers = {
            **EDGE_HEADERS,
            "cookie": f"{COOKIE}={cookie_val}",
        }

        # Authenticated /ws/dashboard?view=chat-security connects
        with client.websocket_connect(
            f"wss://{PUBLIC_HOST}/ws/dashboard?view=chat-security",
            headers=auth_headers,
        ) as ws:
            data = ws.receive_json()
            self.assertEqual(data.get("type"), "chat_security")

        # Authenticated /ws/monitored-applications connects
        with client.websocket_connect(
            f"wss://{PUBLIC_HOST}/ws/monitored-applications",
            headers=auth_headers,
        ) as ws:
            data = ws.receive_json()
            self.assertEqual(data.get("type"), "snapshot")


if __name__ == "__main__":
    unittest.main()
