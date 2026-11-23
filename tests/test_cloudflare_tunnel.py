"""Unit and Integration Tests for Phase 4: Cloudflare Tunnel, QR Attendance & Security Remediation.

Tests:
1. TunnelManager initialization without token defaults to 'disabled' with clear message.
2. Local LAN URL resolution produces valid IPv4 and port.
3. Hostname cleaning strips prefixes and slashes properly.
4. Active joining URL falls back to local LAN when tunnel is disabled or unconfigured.
5. Missing cloudflared executable sets status='error' and preserves local LAN fallback.
6. Successful cloudflared tunnel registration transitions status to 'running'.
7. When running, public_url, is_public_ready, and active_joining_url resolve to public HTTPS.
8. Status dictionary never exposes secret tunnel token or private credentials.
9. Stop lifecycle terminates subprocess cleanly.
10. Readiness reporting (F-04): edge_connected is distinct from public_hostname_verified.
11. QR code generator creates valid SVG XML with correct dimensions for LAN URL.
12. QR code generator creates valid SVG XML for Public HTTPS URL.
13. API endpoint /api/tunnel/state returns valid status payload.
14. API endpoint /api/tunnel/qr.svg returns standalone image/svg+xml.
15. Client IP resolution (F-01): CF-Connecting-IP honored only from trusted loopback proxy.
16. Client IP resolution (F-01): Missing forwarded header falls back to peer.
17. Client IP resolution (F-01): Invalid IP syntax falls back safely.
18. Client IP resolution (F-01): Direct LAN spoofed headers ignored.
19. Client IP resolution (F-01): Untrusted proxy spoofed headers ignored.
20. WebSocket Origin validation (F-02): Localhost origins permitted.
21. WebSocket Origin validation (F-02): Local LAN origins permitted.
22. WebSocket Origin validation (F-02): Configured public hostname permitted.
23. WebSocket Origin validation (F-02): Untrusted external origins rejected.
24. WebSocket Origin validation (F-02): Malformed origins rejected.
25. WebSocket Origin validation (F-02): Missing origin policy verified.
26. Administrative endpoint protection (F-03): /api/upload requires ADMIN_TOKEN.
27. Administrative endpoint protection (F-03): /api/predict requires ADMIN_TOKEN.
28. Ordinary chat routes remain unrestricted for public attendees (F-03).
"""
from __future__ import annotations

import io
import os
import subprocess
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app import app
from backend.chat_service import is_origin_allowed, resolve_client_ip
from backend.network.qr_generator import generate_qr_matrix, generate_qr_svg
from backend.network.tunnel import TunnelManager, get_lan_ipv4


class TestCloudflareTunnelManager(unittest.TestCase):
    """Verifies TunnelManager behavior, configuration, and security guarantees."""

    def test_init_without_token_is_disabled(self):
        mgr = TunnelManager(token="", public_hostname="demo.example.com", local_port=8001, mode="named")
        self.assertEqual(mgr.status, "disabled")
        self.assertFalse(mgr.is_public_ready)
        self.assertFalse(mgr.edge_connected)
        self.assertFalse(mgr.public_hostname_verified)
        self.assertIsNone(mgr.public_url)
        self.assertEqual(mgr.joining_mode, "local_lan")
        self.assertIn("/chat", mgr.active_joining_url)
        self.assertIn("8001", mgr.active_joining_url)
        self.assertIn("not configured", mgr.error or "")

    def test_local_ip_and_url_resolution(self):
        ip = get_lan_ipv4()
        self.assertTrue(bool(ip))
        parts = ip.split(".")
        self.assertEqual(len(parts), 4, f"Invalid IPv4 address: {ip}")
        for p in parts:
            self.assertTrue(0 <= int(p) <= 255)

        mgr = TunnelManager(token=None, local_port=8001)
        self.assertIn(f":{mgr.local_port}", mgr.local_url)
        self.assertTrue(mgr.local_url.startswith("http://"))

    def test_hostname_sanitization(self):
        cases = [
            ("https://chat.example.com/", "chat.example.com"),
            ("http://sub.domain.org", "sub.domain.org"),
            ("  SECURE-ROOM.EXAMPLE.NET/  ", "SECURE-ROOM.EXAMPLE.NET"),
            ("", None),
            (None, None),
        ]
        for raw, expected in cases:
            cleaned = TunnelManager._clean_hostname(raw)
            self.assertEqual(cleaned, expected)

    def test_missing_cloudflared_executable_sets_error_gracefully(self):
        mgr = TunnelManager(
            token="eyJhIjoiZGVtbyJ9",
            public_hostname="demo.example.com",
            local_port=8001,
            cloudflared_path="nonexistent_binary_xyz_12345",
        )
        with patch.object(mgr, "find_cloudflared_executable", return_value=None):
            started = mgr.start()
            self.assertFalse(started)
            self.assertEqual(mgr.status, "error")
            self.assertFalse(mgr.is_public_ready)
            self.assertIsNone(mgr.public_url)
            # Safe joining URL must seamlessly fall back to local LAN
            self.assertEqual(mgr.joining_mode, "local_lan")
            self.assertEqual(mgr.active_joining_url, f"{mgr.local_url}/chat")
            self.assertIn("cloudflared executable was not found", mgr.error)

    def test_mocked_cloudflared_connects_to_edge(self):
        mgr = TunnelManager(
            token="mock-valid-token-12345",
            public_hostname="sentinel.acme.org",
            local_port=8001,
        )

        fake_process = MagicMock(spec=subprocess.Popen)
        fake_process.pid = 99999
        fake_process.poll.return_value = None
        # Simulate cloudflared output line confirming connection to Cloudflare edge
        fake_process.stdout = io.StringIO(
            "2026-11-14T17:00:00Z INF Starting tunnel tunnelID=abc\n"
            "2026-11-14T17:00:01Z INF Registered tunnel connection connIndex=0 event=0 ip=198.41.200.1\n"
        )

        with patch.object(mgr, "find_cloudflared_executable", return_value="C:\\fake\\cloudflared.exe"), \
             patch("subprocess.Popen", return_value=fake_process):
            started = mgr.start()
            self.assertTrue(started)
            if mgr._monitor_thread:
                mgr._monitor_thread.join(timeout=1.0)

            self.assertEqual(mgr.status, "running")
            self.assertTrue(mgr.is_public_ready)
            self.assertTrue(mgr.edge_connected)
            # F-04: Public hostname verified must remain distinct from edge connectivity
            self.assertFalse(mgr.public_hostname_verified)
            self.assertIn("unverified", mgr.readiness_note.lower())
            self.assertEqual(mgr.public_url, "https://sentinel.acme.org")
            self.assertEqual(mgr.active_joining_url, "https://sentinel.acme.org/chat")
            self.assertEqual(mgr.joining_mode, "public_https")

            # Clean shutdown test
            stopped = mgr.stop()
            self.assertTrue(stopped)
            fake_process.terminate.assert_called()

    def test_status_dict_never_exposes_token(self):
        secret_token = "EY_SUPER_SECRET_CLOUDFLARE_TOKEN_ABC123"
        mgr = TunnelManager(
            token=secret_token,
            public_hostname="demo.sentinel.dev",
            local_port=8001,
        )
        status = mgr.status_dict()
        self.assertTrue(status["enabled"])
        self.assertIn("readiness_note", status)
        self.assertIn("edge_connected", status)
        self.assertIn("public_hostname_verified", status)
        for key, val in status.items():
            self.assertNotIn(secret_token, str(val), f"Secret token leaked in status key '{key}'")
            self.assertNotIn("secret", str(key).lower())

    def test_joining_mode_fallback_when_tunnel_stops(self):
        mgr = TunnelManager(
            token="test-token",
            public_hostname="public.example.com",
            local_port=8001,
        )
        mgr.status = "running"
        self.assertEqual(mgr.joining_mode, "public_https")
        self.assertEqual(mgr.active_joining_url, "https://public.example.com/chat")

        mgr.stop()
        self.assertNotEqual(mgr.status, "running")
        self.assertEqual(mgr.joining_mode, "local_lan")
        self.assertEqual(mgr.active_joining_url, f"{mgr.local_url}/chat")


class TestQRCodeGenerator(unittest.TestCase):
    """Verifies QR Code Model 2 SVG generation."""

    def test_generate_qr_matrix_shapes(self):
        url = "http://192.168.1.5:8001/chat"
        matrix = generate_qr_matrix(url)
        self.assertIsInstance(matrix, list)
        dim = len(matrix)
        self.assertIn(dim, [21, 25, 29, 33, 37, 41])
        for row in matrix:
            self.assertEqual(len(row), dim)
            for cell in row:
                self.assertIn(cell, [0, 1])

    def test_generate_qr_svg_produces_valid_xml(self):
        url = "https://sentinel-security.example.org/chat"
        svg = generate_qr_svg(url, size=220)
        self.assertTrue(svg.startswith("<svg"))
        self.assertTrue(svg.endswith("</svg>"))
        self.assertIn('viewBox="0 0 ', svg)
        self.assertIn('width="220"', svg)
        self.assertIn('height="220"', svg)
        self.assertIn("<rect", svg)
        self.assertIn('aria-label="Join QR Code"', svg)

    def test_qr_svg_is_reused_for_an_unchanged_url(self):
        url = "https://cached-demo.trycloudflare.com/chat"
        self.assertIs(generate_qr_svg(url), generate_qr_svg(url))


class TestChatInvitationHealth(unittest.IsolatedAsyncioTestCase):
    async def test_keeps_verified_link_through_failures_and_expires_persistent_outage(self):
        from unittest.mock import AsyncMock
        from backend.network.chat_invitation import ChatInvitation

        now = 100.0
        invite = ChatInvitation(clock=lambda: now)
        url = "https://stable-demo.trycloudflare.com/chat"
        with patch.object(invite, "public_candidate", return_value=url), \
                patch.object(invite, "connector_stopped", return_value=False), \
                patch.object(invite, "verify_public", new_callable=AsyncMock) as probe:
            probe.return_value = "retry"
            invite.sync_candidate()
            invite.confirm_public(url)
            original = invite.snapshot(allow_lan=False)
            self.assertEqual(original["sharing_state"], "connected")
            for now in (110.0, 115.0, 120.0):
                invite.snapshot(allow_lan=False)
                await invite.probe_task
                pending = invite.snapshot(allow_lan=False)
                self.assertEqual(pending["sharing_state"], "reconnecting")
                self.assertEqual(pending["qr_url"], original["qr_url"])
            now = 145.0
            disconnected = invite.snapshot(allow_lan=False)
            self.assertEqual(disconnected["sharing_state"], "disconnected")
            self.assertIsNone(disconnected["qr_url"])
            await invite.probe_task
            probe.return_value = "connected"
            now = 150.0
            invite.snapshot(allow_lan=False)
            await invite.probe_task
            recovered = invite.snapshot(allow_lan=False)
            self.assertEqual(recovered["sharing_state"], "connected")
            self.assertEqual(recovered["qr_url"], original["qr_url"])

    async def test_old_probe_cannot_overwrite_newer_proof_or_start_another_probe(self):
        import asyncio
        from backend.network.chat_invitation import ChatInvitation

        now = 100.0
        invite = ChatInvitation(clock=lambda: now)
        first = "https://old-demo.trycloudflare.com/chat"
        second = "https://new-demo.trycloudflare.com/chat"
        release = asyncio.Event()
        calls = []

        async def slow_probe(candidate):
            calls.append(candidate)
            await release.wait()
            return "invalid"

        with patch.object(invite, "public_candidate", return_value=first) as current, \
                patch.object(invite, "connector_stopped", return_value=False), \
                patch.object(invite, "verify_public", slow_probe):
            invite.sync_candidate()
            invite.confirm_public(first)
            now = 110.0
            invite.snapshot(allow_lan=False)
            task = invite.probe_task
            invite.snapshot(allow_lan=False)
            self.assertIs(invite.probe_task, task)
            current.return_value = second
            self.assertEqual(invite.snapshot(allow_lan=False)["active_joining_url"], first)
            invite.confirm_public(second)
            release.set()
            await task
            self.assertEqual(calls, [first])
            latest = invite.snapshot(allow_lan=False)
            self.assertEqual(latest["sharing_state"], "connected")
            self.assertEqual(latest["active_joining_url"], second)

    async def test_explicit_invalid_response_retires_qr_without_waiting_for_grace(self):
        from unittest.mock import AsyncMock
        from backend.network.chat_invitation import ChatInvitation

        now = 100.0
        invite = ChatInvitation(clock=lambda: now)
        url = "https://gone-demo.trycloudflare.com/chat"
        with patch.object(invite, "public_candidate", return_value=url), \
                patch.object(invite, "connector_stopped", return_value=False), \
                patch.object(invite, "verify_public", new_callable=AsyncMock, return_value="invalid"):
            invite.sync_candidate()
            invite.confirm_public(url)
            now = 110.0
            invite.snapshot(allow_lan=False)
            await invite.probe_task
            self.assertIsNone(invite.snapshot(allow_lan=False)["qr_url"])

    async def test_late_failure_does_not_discard_new_proof_for_the_same_url(self):
        import asyncio
        from backend.network.chat_invitation import ChatInvitation

        now = 100.0
        invite = ChatInvitation(clock=lambda: now)
        url = "https://same-host.trycloudflare.com/chat"
        release = asyncio.Event()

        async def delayed_failure(_):
            await release.wait()
            return "invalid"

        with patch.object(invite, "public_candidate", return_value=url), \
                patch.object(invite, "connector_stopped", return_value=False), \
                patch.object(invite, "verify_public", delayed_failure):
            invite.sync_candidate()
            invite.confirm_public(url)
            now = 110.0
            invite.snapshot(allow_lan=False)
            await asyncio.sleep(0)
            invite.confirm_public(url)
            release.set()
            await invite.probe_task
            self.assertEqual(invite.snapshot(allow_lan=False)["sharing_state"], "connected")

    async def test_connector_reconnect_retains_qr_and_confirmed_stop_clears_it(self):
        from backend.network.chat_invitation import ChatInvitation, tunnel_manager

        invite = ChatInvitation(clock=lambda: 100.0)
        with patch.object(tunnel_manager, "mode", "quick"), patch.object(tunnel_manager, "status", "running"), \
                patch.object(tunnel_manager, "process", None), \
                patch.object(tunnel_manager, "public_hostname", "managed-demo.trycloudflare.com"):
            candidate = invite.sync_candidate()
            invite.confirm_public(candidate)
            qr_url = invite.snapshot(allow_lan=False)["qr_url"]
            tunnel_manager.status = "reconnecting"
            waiting = invite.snapshot(allow_lan=False)
            self.assertEqual(waiting["sharing_state"], "reconnecting")
            self.assertEqual(waiting["qr_url"], qr_url)
            tunnel_manager.status = "stopped"
            self.assertIsNone(invite.snapshot(allow_lan=False)["qr_url"])


class TestClientIPResolution(unittest.TestCase):
    """Verifies proxy-aware client IP resolution, anti-spoofing, and validation (F-01)."""

    def test_valid_cloudflare_client_ip_from_trusted_loopback(self):
        headers = {"cf-connecting-ip": "203.0.113.195"}
        resolved = resolve_client_ip("127.0.0.1", headers)
        self.assertEqual(resolved, "203.0.113.195")

    def test_missing_forwarded_header_falls_back_to_peer(self):
        resolved = resolve_client_ip("127.0.0.1", {})
        self.assertEqual(resolved, "127.0.0.1")

    def test_invalid_forwarded_ip_syntax_falls_back_to_peer(self):
        headers = {"cf-connecting-ip": "malformed_ip_syntax; drop tables"}
        resolved = resolve_client_ip("127.0.0.1", headers)
        self.assertEqual(resolved, "127.0.0.1")

    def test_direct_lan_client_with_spoofed_headers_ignored(self):
        headers = {"cf-connecting-ip": "8.8.8.8", "x-forwarded-for": "1.1.1.1"}
        resolved = resolve_client_ip("192.168.1.150", headers)
        self.assertEqual(resolved, "192.168.1.150")

    def test_untrusted_proxy_spoof_attempt_ignored(self):
        headers = {"cf-connecting-ip": "100.64.0.1"}
        resolved = resolve_client_ip("198.51.100.99", headers)
        self.assertEqual(resolved, "198.51.100.99")


class TestWebSocketOriginValidation(unittest.TestCase):
    """Verifies WebSocket Origin header validation against CSWSH (F-02)."""

    def test_valid_localhost_origins(self):
        self.assertTrue(is_origin_allowed("http://localhost:8001"))
        self.assertTrue(is_origin_allowed("http://127.0.0.1:8001"))
        self.assertTrue(is_origin_allowed("https://localhost"))

    def test_valid_lan_origins(self):
        self.assertTrue(is_origin_allowed("http://192.168.1.3:8001"))
        self.assertTrue(is_origin_allowed("http://10.0.0.15:8000"))
        self.assertTrue(is_origin_allowed("http://172.16.0.2:8001"))

    def test_valid_configured_public_hostname(self):
        with patch.dict(os.environ, {"CLOUDFLARE_PUBLIC_HOSTNAME": "sentinel-chat.example.org"}):
            self.assertTrue(is_origin_allowed("https://sentinel-chat.example.org"))
            self.assertTrue(is_origin_allowed("https://sentinel-chat.example.org:443"))

    def test_untrusted_external_origin_rejected(self):
        self.assertFalse(is_origin_allowed("https://evil-attacker.com"))
        self.assertFalse(is_origin_allowed("http://malicious-site.net:8080"))

    def test_malformed_origins_rejected(self):
        self.assertFalse(is_origin_allowed("javascript:alert(1)"))
        self.assertFalse(is_origin_allowed("ftp://evil.org"))
        self.assertFalse(is_origin_allowed("not_a_valid_url"))

    def test_missing_origin_policy(self):
        self.assertTrue(is_origin_allowed(None))
        self.assertTrue(is_origin_allowed(""))

        with patch.dict(os.environ, {"ALLOW_MISSING_ORIGIN": "false"}):
            self.assertFalse(is_origin_allowed(None))
            self.assertFalse(is_origin_allowed(""))

    def test_cloudflare_quick_tunnel_origin_allowed(self):
        """Verifies that Cloudflare Quick Tunnel origins (*.trycloudflare.com) are accepted."""
        self.assertTrue(is_origin_allowed("https://snowboard-luggage-elements-ozone.trycloudflare.com"))
        self.assertTrue(is_origin_allowed("https://snowboard-luggage-elements-ozone.trycloudflare.com:443"))
        self.assertTrue(is_origin_allowed("https://random-words-1234.trycloudflare.com"))
        self.assertTrue(is_origin_allowed("https://trycloudflare.com"))

    def test_cloudflare_quick_tunnel_with_request_host(self):
        """Verifies same-origin match vs cross-subdomain hijack prevention for trycloudflare."""
        # Legitimate same-origin Quick Tunnel connection
        self.assertTrue(
            is_origin_allowed(
                "https://snowboard-luggage-elements-ozone.trycloudflare.com",
                request_host="snowboard-luggage-elements-ozone.trycloudflare.com",
            )
        )
        # Legitimate local reverse-proxy forward from cloudflared (Host: localhost:8000)
        self.assertTrue(
            is_origin_allowed(
                "https://snowboard-luggage-elements-ozone.trycloudflare.com",
                request_host="localhost:8000",
            )
        )
        # Malicious cross-subdomain trycloudflare hijack attempt rejected
        self.assertFalse(
            is_origin_allowed(
                "https://evil-attacker.trycloudflare.com",
                request_host="snowboard-luggage-elements-ozone.trycloudflare.com",
            )
        )
        # Malicious third-party origin rejected
        self.assertFalse(
            is_origin_allowed(
                "https://evil-attacker.com",
                request_host="snowboard-luggage-elements-ozone.trycloudflare.com",
            )
        )

    def test_dynamic_tunnel_manager_hostname(self):
        """Verifies that dynamically registered TunnelManager hostname is accepted."""
        from backend.network.tunnel import tunnel_manager
        original_host = tunnel_manager.public_hostname
        try:
            tunnel_manager.public_hostname = "dynamic-app.example.com"
            self.assertTrue(is_origin_allowed("https://dynamic-app.example.com"))
            self.assertTrue(is_origin_allowed("https://dynamic-app.example.com:443"))
        finally:
            tunnel_manager.public_hostname = original_host

    def test_websocket_connect_with_cloudflare_quick_tunnel_origin(self):
        """Verifies end-to-end WebSocket handshake over Cloudflare Quick Tunnel origin."""
        client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
        with client.websocket_connect(
            "/ws/chat/cftunneluser",
            headers={
                "origin": "https://snowboard-luggage-elements-ozone.trycloudflare.com",
                "host": "snowboard-luggage-elements-ozone.trycloudflare.com",
            },
        ) as ws:
            data = ws.receive_json()
            self.assertEqual(data.get("type"), "users")
            self.assertIn("cftunneluser", data.get("users", []))

    def test_websocket_connect_with_lan_origin(self):
        """Verifies end-to-end WebSocket handshake over local LAN origin (ws://)."""
        client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
        with client.websocket_connect(
            "/ws/chat/lanuser1",
            headers={
                "origin": "http://192.168.1.3:8000",
                "host": "192.168.1.3:8000",
            },
        ) as ws:
            data = ws.receive_json()
            self.assertEqual(data.get("type"), "users")
            self.assertIn("lanuser1", data.get("users", []))

    def test_websocket_connect_with_untrusted_origin_rejected(self):
        """Verifies that untrusted third-party Origin is closed with Policy Violation (1008)."""
        from starlette.websockets import WebSocketDisconnect
        client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
        with self.assertRaises(WebSocketDisconnect) as ctx:
            with client.websocket_connect(
                "/ws/chat/eviloriginuser",
                headers={
                    "origin": "https://evil-attacker.com",
                    "host": "snowboard-luggage-elements-ozone.trycloudflare.com",
                },
            ):
                pass
        self.assertEqual(ctx.exception.code, 1008)

    def test_frontend_templates_use_wss_for_https_and_ws_for_http(self):
        """Verifies frontend HTML templates construct WSS for HTTPS and WS for LAN HTTP."""
        client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
        chat_res = client.get("/chat")
        self.assertEqual(chat_res.status_code, 200)
        self.assertIn("location.protocol === 'https:' ? 'wss:' : 'ws:'", chat_res.text)
        self.assertIn("/ws/chat/", chat_res.text)

        dash_res = client.get("/dashboard?view=legacy")
        self.assertEqual(dash_res.status_code, 200)
        self.assertIn("(location.protocol==='https:'?'wss':'ws')", dash_res.text)
        monitor_res = client.get("/dashboard/chat")
        self.assertEqual(monitor_res.status_code, 200)
        self.assertIn("location.protocol === 'https:' ? 'wss:' : 'ws:'", monitor_res.text)
        self.assertIn("/ws/dashboard?view=chat-security", monitor_res.text)
        self.assertIn("/ws/dashboard", dash_res.text)


class TestAdministrativeEndpointProtection(unittest.TestCase):
    """Verifies that sensitive/admin routes are protected with ADMIN_TOKEN (F-03)."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))

    def test_upload_dataset_rejects_missing_admin_token(self):
        res = self.client.post("/api/upload", files={"file": ("test.csv", b"col1,col2\n1,2")})
        self.assertEqual(res.status_code, 403)
        self.assertIn("Admin token", res.json().get("detail", ""))

    def test_upload_dataset_rejects_invalid_admin_token(self):
        res = self.client.post(
            "/api/upload",
            files={"file": ("test.csv", b"col1,col2\n1,2")},
            headers={"X-Admin-Token": "wrong-token-abc"},
        )
        self.assertEqual(res.status_code, 403)

    def test_upload_dataset_allows_valid_admin_token(self):
        admin_token = os.getenv("ADMIN_TOKEN") or "test_admin_token_123"
        with patch.dict(os.environ, {"ADMIN_TOKEN": admin_token}):
            res = self.client.post(
                "/api/upload",
                files={"file": ("test.csv", b"col1,col2\n1,2")},
                headers={"X-Admin-Token": admin_token},
            )
            self.assertEqual(res.status_code, 200)

    def test_predict_rejects_missing_admin_token(self):
        res = self.client.post("/api/predict")
        self.assertEqual(res.status_code, 403)

    def test_predict_rejects_invalid_admin_token(self):
        res = self.client.post("/api/predict", headers={"X-Admin-Token": "bad-token"})
        self.assertEqual(res.status_code, 403)

    def test_public_chat_remains_unrestricted(self):
        res = self.client.get("/chat")
        self.assertEqual(res.status_code, 200)

    def test_public_tunnel_state_remains_accessible_without_admin_token(self):
        res = self.client.get("/api/tunnel/state")
        self.assertEqual(res.status_code, 200)


class TestTunnelEndpoints(unittest.TestCase):
    """Verifies FastAPI API endpoints for tunnel state and QR SVG delivery."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))

    def test_api_tunnel_state(self):
        res = self.client.get("/api/tunnel/state")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("enabled", data)
        self.assertIn("status", data)
        self.assertIn("edge_connected", data)
        self.assertIn("public_hostname_verified", data)
        self.assertIn("readiness_note", data)
        self.assertIn("local_url", data)
        self.assertIn("active_joining_url", data)
        self.assertIn("joining_mode", data)
        self.assertIn("is_public_ready", data)
        self.assertNotIn("token", data)

    def test_api_tunnel_qr_svg(self):
        from backend.network.chat_invitation import MAX_UNVERIFIED, ChatInvitation

        now = 100.0
        invite = ChatInvitation(clock=lambda: now)
        first = "https://first-tunnel-demo.trycloudflare.com/chat"
        second = "https://second-tunnel-demo.trycloudflare.com/chat"
        invite.confirm_public(first)
        with patch("backend.chat_service.chat_invitation", invite), \
                patch.object(invite, "public_candidate", return_value=first) as candidate, \
                patch.object(invite, "schedule_probe"):
            state = self.client.get("/api/tunnel/state").json()
            self.assertEqual(state["active_joining_url"], first)
            self.assertEqual(state["joining_mode"], "public_https")
            first_qr = self.client.get(state["qr_url"])
            self.assertEqual(first_qr.status_code, 200)
            self.assertIn("image/svg+xml", first_qr.headers.get("content-type", ""))
            self.assertEqual(first_qr.text, generate_qr_svg(first))
            candidate.return_value = second
            pending = self.client.get("/api/tunnel/state").json()
            self.assertEqual(pending["active_joining_url"], first)
            self.assertEqual(pending["sharing_state"], "reconnecting")
            self.assertEqual(self.client.get(state["qr_url"]).status_code, 200)
            invite.confirm_public(second)
            rotated = self.client.get("/api/tunnel/state").json()
            self.assertNotEqual(state["qr_url"], rotated["qr_url"])
            self.assertEqual(self.client.get(state["qr_url"]).status_code, 404)
            self.assertEqual(self.client.get(rotated["qr_url"]).text, generate_qr_svg(second))
            now += MAX_UNVERIFIED
            self.assertIsNone(self.client.get("/api/tunnel/state").json()["active_joining_url"])
            self.assertEqual(self.client.get(rotated["qr_url"]).status_code, 404)

    def test_lan_qr_requires_a_separate_direct_client(self):
        from backend.network.chat_invitation import ChatInvitation

        invite = ChatInvitation()
        with patch("backend.chat_service.chat_invitation", invite), patch.object(invite, "public_candidate", return_value=None):
            self.assertIsNone(self.client.get("/api/tunnel/state").json()["active_joining_url"])
            self.assertEqual(self.client.get("/api/tunnel/qr.svg").status_code, 404)
            lan = TestClient(app, base_url="http://192.168.1.7:8001", client=("192.168.1.8", 50000))
            self.assertEqual(lan.get("/chat", headers={"X-Forwarded-For": "192.168.1.8"}).status_code, 200)
            self.assertIsNone(self.client.get("/api/tunnel/state").json()["active_joining_url"])
            self.assertEqual(lan.get("/chat").status_code, 200)
            verified = self.client.get("/api/tunnel/state").json()
            self.assertEqual(verified["active_joining_url"], "http://192.168.1.7:8001/chat")
            self.assertEqual(verified["joining_mode"], "local_lan")


if __name__ == "__main__":
    unittest.main()
