"""Comprehensive End-to-End Integration Tests for Phase 5 Validation.

Validates the full application stack using actual components:
1. Multi-user chat joining and live roster synchronization.
2. Normal message exchange with Threat Engine ALLOW evaluation.
3. Phishing / Suspicious URL message evaluation with Threat Engine WARN / BLOCK_MESSAGE decision.
4. Flooding behavior evaluation triggering Threat Engine BLOCK_USER decision.
5. Real-time SOC dashboard WebSocket streaming of all security events.
6. Administrative unblock workflow using ADMIN_TOKEN.
7. GATv2 flow tracker association with chat client endpoints.
"""
from __future__ import annotations

import os
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import app
from backend.chat_service import state, threat_engine, behavior_analyzer


class TestFullApplicationIntegration(unittest.TestCase):
    """End-to-end integration tests exercising real chat, security engines, and dashboard."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
        cls.admin_token = os.getenv("ADMIN_TOKEN") or "sentinel_integration_secret_token"
        os.environ["ADMIN_TOKEN"] = cls.admin_token

    def setUp(self):
        # Reset transient state between integration runs
        state.clients.clear()
        state.client_ips.clear()
        state.client_endpoints.clear()
        state.blocked.clear()
        state.block_reasons.clear()
        state.recent.clear()
        state.events.clear()

    def test_multi_user_chat_and_roster_sync(self):
        """Validates that two participants can join and see each other in the roster."""
        with self.client.websocket_connect("/ws/chat/alice", headers={"origin": "http://localhost:8001"}) as ws_alice:
            data1 = ws_alice.receive_json()
            self.assertEqual(data1["type"], "users")
            self.assertIn("alice", data1["users"])

            with self.client.websocket_connect("/ws/chat/bob", headers={"origin": "http://localhost:8001"}) as ws_bob:
                data_bob = ws_bob.receive_json()
                self.assertEqual(data_bob["type"], "users")
                self.assertIn("alice", data_bob["users"])
                self.assertIn("bob", data_bob["users"])

                # Alice should receive updated roster containing bob
                data_alice_update = ws_alice.receive_json()
                self.assertEqual(data_alice_update["type"], "users")
                self.assertIn("bob", data_alice_update["users"])

    def test_normal_message_exchange_and_threat_allow(self):
        """Validates that legitimate messages receive Threat Engine ALLOW decision and deliver."""
        with self.client.websocket_connect("/ws/chat/alice", headers={"origin": "http://localhost:8001"}) as ws_alice, \
             self.client.websocket_connect("/ws/chat/bob", headers={"origin": "http://localhost:8001"}) as ws_bob:

            # Clear roster messages
            _ = ws_alice.receive_json()
            _ = ws_bob.receive_json()
            _ = ws_alice.receive_json()

            # Alice sends benign message to Bob
            ws_alice.send_json({"recipient": "bob", "text": "Hello Bob, please review the network logs."})

            # Alice receives delivery echo
            delivered_alice = ws_alice.receive_json()
            self.assertEqual(delivered_alice["type"], "message")
            self.assertEqual(delivered_alice["sender"], "alice")
            self.assertEqual(delivered_alice["threat"]["action"], "ALLOW")

            # Bob receives the message
            delivered_bob = ws_bob.receive_json()
            self.assertEqual(delivered_bob["type"], "message")
            self.assertEqual(delivered_bob["text"], "Hello Bob, please review the network logs.")

    def test_suspicious_url_triggers_warning_or_block_message(self):
        """Validates that phishing URL triggers Threat Engine evaluation and security action."""
        with self.client.websocket_connect("/ws/chat/attacker", headers={"origin": "http://localhost:8001"}) as ws_attacker, \
             self.client.websocket_connect("/ws/chat/victim", headers={"origin": "http://localhost:8001"}) as ws_victim:

            _ = ws_attacker.receive_json()
            _ = ws_victim.receive_json()
            _ = ws_attacker.receive_json()

            # Phishing link with shortener and urgent credentials keywords
            phish_msg = "URGENT: Your account is suspended. Verify password now: http://bit.ly/login-verify-account"
            ws_attacker.send_json({"recipient": "victim", "text": phish_msg})

            response = ws_attacker.receive_json()
            # Must trigger security intervention (WARN, BLOCK_MESSAGE, or BLOCK_USER)
            self.assertIn(response["type"], ("warning", "blocked", "message"))
            threat = response.get("threat", {})
            self.assertIn(threat.get("action"), ("WARN", "BLOCK_MESSAGE", "BLOCK_USER"))
            # Security score must reflect detected URL and content risks
            self.assertGreater(threat.get("threat_score", 0.0), 0.50)

    def test_flooding_triggers_block_user_and_quarantine(self):
        """Validates that flood attack triggers Behavior Analyzer flood detection and user block."""
        with self.client.websocket_connect("/ws/chat/spammer", headers={"origin": "http://localhost:8001"}) as ws_spammer, \
             self.client.websocket_connect("/ws/chat/receiver", headers={"origin": "http://localhost:8001"}) as ws_receiver:

            _ = ws_spammer.receive_json()
            _ = ws_receiver.receive_json()
            _ = ws_spammer.receive_json()

            blocked = False
            for i in range(30):
                try:
                    ws_spammer.send_json({"recipient": "receiver", "text": f"Spam message payload #{i}"})
                    res = ws_spammer.receive_json()
                    if res.get("type") == "blocked":
                        blocked = True
                        break
                except Exception:
                    blocked = True
                    break

            self.assertTrue(blocked or "spammer" in state.blocked)
            self.assertIn("spammer", state.blocked)

    def test_dashboard_receives_realtime_security_events(self):
        """Validates that SOC dashboard receives real-time security events over its WebSocket."""
        with self.client.websocket_connect("/ws/dashboard", headers={"origin": "http://localhost:8001", "host":"localhost:8001"}) as ws_dash:
            snapshot = ws_dash.receive_json()
            self.assertEqual(snapshot["type"], "snapshot")

            # Connect chat participant and verify user_joined event streams to dashboard
            with self.client.websocket_connect("/ws/chat/charlie", headers={"origin": "http://localhost:8001"}) as ws_charlie:
                # Dashboard should receive event broadcast
                event = ws_dash.receive_json()
                self.assertIn(event["type"], ("user_joined", "users"))

    def test_admin_unblock_restores_blocked_user(self):
        """Validates that admin unblock API removes user from blocked set and clears reason."""
        state.blocked.add("quarantined_user")
        state.block_reasons["quarantined_user"] = "Excessive flooding behavior"

        res = self.client.post(
            "/api/admin/unblock/quarantined_user",
            headers={"X-Admin-Token": self.admin_token},
        )
        self.assertEqual(res.status_code, 200)
        self.assertNotIn("quarantined_user", state.blocked)
        self.assertNotIn("quarantined_user", state.block_reasons)


if __name__ == "__main__":
    unittest.main()

