import os
import unittest
from contextlib import asynccontextmanager
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import app
from backend.chat_service import ChatState, threat_engine
from backend.security.blocking import BlockingManager


@asynccontextmanager
async def isolated_lifespan(_app):
    yield


class ChatIPBlockingTests(unittest.TestCase):
    def test_public_chat_blocks_new_names_from_the_same_ip_until_admin_unblocks(self):
        host = "sentinel-moderation.test"
        origin = f"https://{host}"
        token = "isolated-admin-token"
        first_ip = "203.0.113.10"
        other_ip = "198.51.100.10"
        manager = BlockingManager()
        self.enterContext(patch.dict(os.environ, {
            "CLOUDFLARE_PUBLIC_HOSTNAME": host,
            "DASHBOARD_REMOTE_ENABLED": "true",
            "ADMIN_TOKEN": token,
        }))
        self.enterContext(patch("backend.network.tunnel.tunnel_manager.mode", "disabled"))
        self.enterContext(patch("backend.chat_service.state", ChatState()))
        self.enterContext(patch("backend.chat_service.blocking_manager", manager))
        self.enterContext(patch("backend.security.threat_engine.blocking_manager", manager))
        self.enterContext(patch.object(threat_engine, "user_cumulative_risk", {}))
        self.enterContext(patch.object(app.router, "lifespan_context", isolated_lifespan))

        def headers(ip):
            return {"Origin": origin, "X-Forwarded-Proto": "https", "CF-Connecting-IP": ip}

        with TestClient(app, base_url=origin, client=("127.0.0.1", 45678)) as client:
            with patch("backend.chat_service.behavior_risk", return_value=(1.0, {"risk": "BLOCK"})):
                with client.websocket_connect(f"wss://{host}/ws/chat/Original", headers=headers(first_ip)) as chat:
                    self.assertEqual(chat.receive_json()["users"], ["Original"])
                    chat.send_json({"recipient": "test-recipient", "text": "Hello."})
                    self.assertIn("IP address has been blocked", chat.receive_json()["message"])

            with client.websocket_connect(f"wss://{host}/ws/chat/NewName", headers=headers(first_ip)) as chat:
                self.assertIn("IP address has been blocked", chat.receive_json()["message"])
            with client.websocket_connect(f"wss://{host}/ws/chat/AnotherName",
                                          headers=headers(f"::ffff:{first_ip}")) as chat:
                self.assertEqual(chat.receive_json()["type"], "blocked")
            with client.websocket_connect(f"wss://{host}/ws/chat/ORIGINAL", headers=headers(other_ip)) as chat:
                self.assertIn("username has been blocked", chat.receive_json()["message"])
            with client.websocket_connect(f"wss://{host}/ws/chat/OtherPerson", headers=headers(other_ip)) as chat:
                self.assertEqual(chat.receive_json()["users"], ["OtherPerson"])

            unblock = "/api/admin/unblock/Original"
            self.assertEqual(client.post(unblock, headers=headers(other_ip)).status_code, 403)
            session = client.post("/api/auth/login", headers=headers(other_ip), json={"token": token})
            self.assertEqual(session.status_code, 200)
            state = client.get("/api/chat/state", headers=headers(other_ip)).json()
            self.assertEqual(state["blocked_client_ips"], {"Original": first_ip})
            admin_headers = {**headers(other_ip), "X-CSRF-Token": session.headers["X-CSRF-Token"]}
            self.assertEqual(client.post(unblock, headers=admin_headers).status_code, 200)
            with client.websocket_connect(f"wss://{host}/ws/chat/Original", headers=headers(first_ip)) as chat:
                self.assertEqual(chat.receive_json()["users"], ["Original"])

    def test_releasing_one_username_preserves_other_blocks_for_the_same_ip(self):
        manager = BlockingManager()
        manager.block_user("First", "2001:db8::5")
        manager.block_user("Second", "2001:0db8:0:0:0:0:0:5")
        manager.unblock_user("First")
        self.assertTrue(manager.is_ip_blocked("2001:db8::5"))
        manager.unblock_user("Second")
        self.assertFalse(manager.is_ip_blocked("2001:db8::5"))
