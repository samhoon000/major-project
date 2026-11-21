import os
import subprocess
import time
import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient

from backend.chat_service import ChatState
from backend.network.enforcement import QuarantineManager, WindowsFirewall, protected_server_ips, get_default_gateways
from backend.network.runtime import NetworkRuntime
from app import app


class FakeFirewall:
    def __init__(self):
        self.added = []
        self.removed = []

    def block(self, ip):
        self.added.append(ip)
        return f"test-rule-{ip}"

    def unblock(self, name):
        self.removed.append(name)


class EnforcementTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.firewall = FakeFirewall()
        self.manager = QuarantineManager(
            self.firewall,
            duration_seconds=20,
            protected_ips={"127.0.0.1", "192.168.1.20", "192.168.1.1"},
            admin_ips={"192.168.1.10"},
            clock=lambda: self.now,
            platform_name="Windows",
            auto_quarantine=True,
        )
        self.attack = {
            "flow_id": "flow-1",
            "source_ip": "192.168.1.45",
            "prediction": "ATTACK",
            "anomaly_probability": 0.91,
            "threshold": 0.53,
        }

    def test_safe_default_auto_quarantine_is_disabled(self):
        # Default with no environment or explicit flag must be False
        with patch.dict(os.environ, {}, clear=True):
            safe_manager = QuarantineManager(
                self.firewall,
                clock=lambda: self.now,
                platform_name="Windows",
            )
            self.assertFalse(safe_manager.auto_quarantine)
            block, reason = safe_manager.handle_attack(self.attack)
            self.assertIsNone(block)
            self.assertEqual(reason, "AUTO_QUARANTINE_DISABLED")
            self.assertEqual(len(self.firewall.added), 0)

    def test_attack_applies_source_ip_block_and_records_reason(self):
        block, action = self.manager.handle_attack(self.attack)
        self.assertEqual(action, "BLOCK_APPLIED")
        self.assertEqual(block.source_ip, "192.168.1.45")
        self.assertIn("GATv2 ATTACK", block.reason)
        self.assertEqual((block.flow_id, block.anomaly_probability, block.blocked_until), ("flow-1", 0.91, 120.0))
        self.assertEqual(self.firewall.added, ["192.168.1.45"])

    def test_benign_or_below_threshold_does_not_block(self):
        for prediction, probability in (("BENIGN", 0.99), ("ATTACK", 0.52)):
            event = {**self.attack, "prediction": prediction, "anomaly_probability": probability}
            self.assertEqual(self.manager.handle_attack(event)[1], "NO_BLOCK_BENIGN_OR_BELOW_THRESHOLD")
        self.assertEqual(self.firewall.added, [])

    def test_duplicate_block_prevention(self):
        self.manager.handle_attack(self.attack)
        _, action = self.manager.handle_attack(self.attack)
        self.assertEqual(action, "DUPLICATE_BLOCK_PREVENTED")
        self.assertEqual(len(self.firewall.added), 1)

    def test_block_expiry_removes_firewall_rule(self):
        block, _ = self.manager.handle_attack(self.attack)
        self.now = block.blocked_until
        expired = self.manager.expire()
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0].status, "EXPIRED")
        self.assertEqual(self.firewall.removed, [block.rule_name])

    def test_admin_unblock_removes_firewall_rule(self):
        block, _ = self.manager.handle_attack(self.attack)
        result = self.manager.unblock("192.168.1.45")
        self.assertIsNotNone(result)
        self.assertEqual(result.status, "ADMIN_UNBLOCKED")
        self.assertEqual(self.firewall.removed, [block.rule_name])

    def test_normal_shutdown_removes_non_expired_rule(self):
        block, _ = self.manager.handle_attack(self.attack)
        closed = self.manager.close()
        self.assertEqual(len(closed), 1)
        self.assertEqual(closed[0].status, "SHUTDOWN_CLEANUP")
        self.assertEqual(self.firewall.removed, [block.rule_name])

    def test_server_and_admin_addresses_cannot_be_blocked(self):
        for source, action in (
            ("127.0.0.1", "SELF_ATTACK_NO_NETWORK_BLOCK"),
            ("192.168.1.20", "SELF_ATTACK_NO_NETWORK_BLOCK"),
            ("192.168.1.10", "ADMIN_IP_PROTECTED"),
        ):
            event = {**self.attack, "source_ip": source}
            self.assertEqual(self.manager.handle_attack(event)[1], action)
        self.assertEqual(self.firewall.added, [])

    def test_default_gateway_cannot_be_blocked(self):
        # 192.168.1.1 is configured as the gateway in setUp
        event = {**self.attack, "source_ip": "192.168.1.1"}
        block, action = self.manager.handle_attack(event)
        self.assertIsNone(block)
        self.assertEqual(action, "SELF_ATTACK_NO_NETWORK_BLOCK")
        self.assertEqual(self.firewall.added, [])

    def test_invalid_and_empty_source_ip_handling(self):
        for invalid_ip in ("", "not_an_ip", "999.999.999.999", "192.168.1.300"):
            event = {**self.attack, "source_ip": invalid_ip}
            block, reason = self.manager.handle_attack(event)
            self.assertIsNone(block)
            self.assertTrue(reason.startswith("INVALID_SOURCE_IP"))
        self.assertEqual(self.firewall.added, [])

    def test_ipv6_quarantine_and_unblock(self):
        ipv6_attack = {
            **self.attack,
            "source_ip": "2001:db8:85a3::8a2e:370:7334",
        }
        block, action = self.manager.handle_attack(ipv6_attack)
        self.assertEqual(action, "BLOCK_APPLIED")
        self.assertEqual(block.source_ip, "2001:db8:85a3::8a2e:370:7334")
        self.assertEqual(self.firewall.added, ["2001:db8:85a3::8a2e:370:7334"])
        unblocked = self.manager.unblock("2001:db8:85a3::8a2e:370:7334")
        self.assertIsNotNone(unblocked)
        self.assertEqual(unblocked.status, "ADMIN_UNBLOCKED")

    def test_missing_admin_privileges_handled_gracefully(self):
        failing_firewall = MagicMock()
        failing_firewall.block.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd="New-NetFirewallRule",
            output="Access is denied. Run as administrator.",
        )
        mgr = QuarantineManager(
            firewall=failing_firewall,
            protected_ips=set(),
            admin_ips=set(),
            platform_name="Windows",
            auto_quarantine=True,
        )
        block, reason = mgr.handle_attack(self.attack)
        self.assertIsNone(block)
        self.assertTrue(reason.startswith("FIREWALL_ERROR"))

    def test_non_windows_enforcement_fails_closed(self):
        manager = QuarantineManager(
            self.firewall,
            protected_ips=set(),
            admin_ips=set(),
            platform_name="Linux",
            auto_quarantine=True,
        )
        self.assertEqual(manager.handle_attack(self.attack)[1], "BLOCK_UNAVAILABLE_NON_WINDOWS")
        self.assertEqual(self.firewall.added, [])

    def test_firewall_rule_is_inbound_and_scoped_to_one_source(self):
        calls = []
        firewall = WindowsFirewall(runner=lambda *args, **kwargs: calls.append((args, kwargs)))
        name = firewall.block("192.168.1.45")
        command = calls[0][0][0]
        script = command[-1]
        self.assertIn("-Direction Inbound", script)
        self.assertIn("-RemoteAddress '192.168.1.45'", script)
        self.assertNotIn("192.168.1.0/24", script)
        firewall.unblock(name)
        self.assertIn("Remove-NetFirewallRule", calls[1][0][0][-1])


class ApiQuarantineTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000))
        self.admin_token = "test-secret-admin-token-12345"

    def test_quarantine_endpoints_token_protection(self):
        with patch.dict(os.environ, {"ADMIN_TOKEN": self.admin_token}):
            # Missing token
            res = self.client.get("/api/network/quarantine")
            self.assertEqual(res.status_code, 403)

            # Invalid token
            res = self.client.get("/api/network/quarantine", headers={"X-Admin-Token": "wrong-token"})
            self.assertEqual(res.status_code, 403)

            # Valid token
            res = self.client.get("/api/network/quarantine", headers={"X-Admin-Token": self.admin_token})
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertIn("auto_quarantine", data)
            self.assertIn("quarantines", data)

    def test_quarantine_unblock_endpoint_validation_and_execution(self):
        with patch.dict(os.environ, {"ADMIN_TOKEN": self.admin_token}):
            # Invalid IP syntax
            res = self.client.post(
                "/api/network/quarantine/unblock/not-an-ip",
                headers={"X-Admin-Token": self.admin_token},
            )
            self.assertEqual(res.status_code, 400)

            # Unblocking non-quarantined IP -> 404
            res = self.client.post(
                "/api/network/quarantine/unblock/198.51.100.99",
                headers={"X-Admin-Token": self.admin_token},
            )
            self.assertEqual(res.status_code, 404)

            # Set up a mock blocked IP in network_runtime
            from backend.network.runtime import network_runtime
            from backend.network.enforcement import Quarantine
            mock_block = Quarantine(
                source_ip="198.51.100.42",
                reason="GATv2 ATTACK",
                anomaly_probability=0.95,
                flow_id="test-flow",
                first_detected=100.0,
                blocked_until=500.0,
                status="BLOCKED",
                rule_name="MajorProject-GATv2-Quarantine-test",
            )
            network_runtime.quarantine_manager.blocks["198.51.100.42"] = mock_block
            with patch.object(network_runtime.quarantine_manager.firewall, "unblock") as mock_unblock:
                res = self.client.post(
                    "/api/network/quarantine/unblock/198.51.100.42",
                    headers={"X-Admin-Token": self.admin_token},
                )
                self.assertEqual(res.status_code, 200)
                data = res.json()
                self.assertEqual(data["status"], "unblocked")
                self.assertEqual(data["ip"], "198.51.100.42")
                self.assertEqual(mock_block.status, "ADMIN_UNBLOCKED")
                mock_unblock.assert_called_once_with(mock_block.rule_name)


class NetworkRuntimeChatScopeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.chat = ChatState()
        self.enterContext(patch("backend.network.runtime.chat_state", self.chat))
        self.runtime = NetworkRuntime()
        self.packet = {"source_ip": "192.0.2.10", "destination_ip": "192.0.2.20",
                       "source_port": 49152, "destination_port": 8001, "protocol": "TCP",
                       "packet_length": 120, "timestamp": time.time()}

    def test_background_traffic_stays_visible_without_a_chat_identity(self):
        self.runtime._packet(self.packet)
        self.chat.clients["relayed"] = MagicMock()
        self.runtime._packet(self.packet)
        self.assertEqual(self.runtime.status()["packets"], 2)
        self.assertNotIn("username", self.runtime.status()["active_flows"][0])
        self.chat.client_endpoints["direct"] = ("192.0.2.10", 49152, "192.0.2.20", 8001, "session-a")
        self.runtime._packet({**self.packet, "destination_ip": "192.0.2.30"})
        self.runtime._packet({**self.packet, "protocol": "UDP"})
        self.runtime._packet(self.packet)
        self.runtime._packet({**self.packet, "source_ip": "192.0.2.20", "destination_ip": "192.0.2.10",
                              "source_port": 8001, "destination_port": 49152})
        status = self.runtime.status()
        self.assertEqual(status["packets"], 6)
        self.assertEqual(len(status["active_flows"]), 4)
        attributed = [flow for flow in status["active_flows"] if flow.get("username") == "direct"]
        self.assertEqual(len(attributed), 1)
        self.assertEqual(attributed[0]["total_packets"], 2)

    async def test_unattributed_prediction_does_not_create_an_attack_alert(self):
        self.runtime._packet(self.packet)
        self.runtime.tracker.expire(force=True)
        flow = self.runtime._take_pending()[0]
        with patch("backend.network.runtime.gatv2_engine._is_loaded", True), \
             patch("backend.network.runtime.gatv2_engine.predict_flows", return_value=[{"is_anomaly": True}]), \
             patch.object(self.runtime.quarantine_manager, "handle_attack") as quarantine:
            await self.runtime._analyze([flow])
        status = self.runtime.status()
        self.assertEqual(status["gatv2_analyses"], 1)
        self.assertEqual(status["gatv2_anomalies"], 0)
        self.assertEqual(status["completed_flows"][0]["gatv2_status"], "observed")
        self.assertIsNone(flow["gatv2_prediction"])
        quarantine.assert_not_called()
        self.assertFalse(self.chat.events)

    async def test_reused_endpoints_do_not_publish_results_from_a_disconnected_session(self):
        endpoint = ("192.0.2.10", 49152, "192.0.2.20", 8001)
        self.chat.client_endpoints["direct"] = (*endpoint, "session-a")
        self.runtime._packet(self.packet)
        self.runtime.tracker.expire(force=True)
        first = self.runtime._take_pending()[0]

        def disconnect_during_inference(_inputs):
            self.chat.client_endpoints["direct"] = (*endpoint, "session-b")
            return [{"is_anomaly": True}]

        with patch("backend.network.runtime.gatv2_engine._is_loaded", True), \
             patch("backend.network.runtime.gatv2_engine.predict_flows", side_effect=disconnect_during_inference):
            await self.runtime._analyze([first])
        self.assertEqual(first["gatv2_status"], "ended")
        self.assertEqual(self.runtime.status()["gatv2_anomalies"], 0)
        self.assertIsNone(self.runtime.status()["latest_analysis"])
        self.assertFalse(self.chat.events)


class NetworkRuntimeAnalyzeIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.runtime = NetworkRuntime()
        chat = ChatState()
        chat.client_endpoints["remote_client"] = ("198.51.100.22", 49152, "192.168.1.50", 8000, "session-a")
        self.enterContext(patch("backend.network.runtime.chat_state", chat))
        self.runtime.quarantine_manager.protected_ips = {"127.0.0.1", "::1", "192.168.1.1", "192.168.1.50"}
        self.runtime.quarantine_manager.admin_ips = {"10.0.0.99"}
        self.runtime.quarantine_manager.platform_name = "Windows"

        self.remote_flow = {
            "flow_id": "flow-remote-attack",
            "source_ip": "198.51.100.22",
            "destination_ip": "192.168.1.50",
            "source_port": 49152,
            "destination_port": 8000,
            "protocol": "TCP",
            "total_packets": 20,
            "total_bytes": 2400,
            "duration": 1.2,
            "username": "remote_client",
            "chat_session_id": "session-a",
            "features": {
                "Flow Duration": 1200000.0,
                "Total Fwd Packets": 10,
                "Total Backward Packets": 10,
                "Flow Bytes/s": 2000.0,
                "Flow Packets/s": 16.6,
            },
        }

    async def test_analyze_attack_with_auto_quarantine_disabled_emits_alert_no_firewall(self):
        """1. ATTACK prediction with NETWORK_AUTO_QUARANTINE=false:
        No firewall command executes, SOC event is emitted, action remains ALERT,
        quarantine_status indicates automatic quarantine is disabled."""
        self.runtime.quarantine_manager.auto_quarantine = False
        mock_block = MagicMock()
        self.runtime.quarantine_manager.firewall.block = mock_block

        mock_prediction = [{
            "flow_id": self.remote_flow["flow_id"],
            "source_ip": self.remote_flow["source_ip"],
            "destination_ip": self.remote_flow["destination_ip"],
            "is_anomaly": True,
            "confidence": 88.0,
            "anomaly_probability": 0.88,
            "threshold": 0.53,
            "graph_nodes": 2,
            "graph_edges": 1,
        }]

        with patch("backend.network.runtime.gatv2_engine.predict_flows", return_value=mock_prediction), \
             patch("backend.network.runtime.chat_state.event", new_callable=AsyncMock) as mock_event:
            await self.runtime._analyze([self.remote_flow])

            mock_block.assert_not_called()
            mock_event.assert_called_once()
            call_kind, event = mock_event.call_args[0]
            self.assertEqual(call_kind, "gatv2_analysis")
            self.assertEqual(event["prediction"], "ATTACK")
            self.assertEqual(event["action"], "ALERT")
            self.assertEqual(event["quarantine_status"], "AUTO_QUARANTINE_DISABLED")
            self.assertEqual(event["quarantine_reason"], "AUTO_QUARANTINE_DISABLED")
            self.assertIsNone(event["quarantine_rule"])

    async def test_analyze_attack_with_auto_quarantine_enabled_applies_quarantine(self):
        """2. ATTACK prediction with NETWORK_AUTO_QUARANTINE=true and eligible remote source IP:
        Quarantine manager is invoked, firewall block operation succeeds through mock,
        SOC event contains quarantine status and rule, action becomes QUARANTINED."""
        self.runtime.quarantine_manager.auto_quarantine = True
        mock_block = MagicMock(return_value="MajorProject-GATv2-Quarantine-mockrule-1")
        self.runtime.quarantine_manager.firewall.block = mock_block

        mock_prediction = [{
            "flow_id": self.remote_flow["flow_id"],
            "source_ip": self.remote_flow["source_ip"],
            "destination_ip": self.remote_flow["destination_ip"],
            "is_anomaly": True,
            "confidence": 92.0,
            "anomaly_probability": 0.92,
            "threshold": 0.53,
            "graph_nodes": 2,
            "graph_edges": 1,
        }]

        with patch("backend.network.runtime.gatv2_engine.predict_flows", return_value=mock_prediction), \
             patch("backend.network.runtime.chat_state.event", new_callable=AsyncMock) as mock_event:
            await self.runtime._analyze([self.remote_flow])

            mock_block.assert_called_once_with("198.51.100.22")
            mock_event.assert_called_once()
            call_kind, event = mock_event.call_args[0]
            self.assertEqual(call_kind, "gatv2_analysis")
            self.assertEqual(event["prediction"], "ATTACK")
            self.assertEqual(event["action"], "QUARANTINED")
            self.assertEqual(event["quarantine_status"], "BLOCKED")
            self.assertEqual(event["quarantine_rule"], "MajorProject-GATv2-Quarantine-mockrule-1")
            self.assertIn("198.51.100.22", self.runtime.quarantine_manager.blocks)
            self.assertEqual(self.runtime.quarantine_manager.blocks["198.51.100.22"].status, "BLOCKED")

    async def test_analyze_benign_prediction_skips_quarantine(self):
        """3. BENIGN prediction:
        Quarantine manager is not invoked, no firewall command executes, action remains OBSERVED."""
        self.runtime.quarantine_manager.auto_quarantine = True
        mock_block = MagicMock()
        self.runtime.quarantine_manager.firewall.block = mock_block

        mock_prediction = [{
            "flow_id": self.remote_flow["flow_id"],
            "source_ip": self.remote_flow["source_ip"],
            "destination_ip": self.remote_flow["destination_ip"],
            "is_anomaly": False,
            "confidence": 75.0,
            "anomaly_probability": 0.25,
            "threshold": 0.53,
            "graph_nodes": 2,
            "graph_edges": 1,
        }]

        with patch("backend.network.runtime.gatv2_engine.predict_flows", return_value=mock_prediction), \
             patch("backend.network.runtime.chat_state.event", new_callable=AsyncMock) as mock_event:
            await self.runtime._analyze([self.remote_flow])

            mock_block.assert_not_called()
            mock_event.assert_called_once()
            call_kind, event = mock_event.call_args[0]
            self.assertEqual(call_kind, "gatv2_analysis")
            self.assertEqual(event["prediction"], "BENIGN")
            self.assertEqual(event["action"], "OBSERVED")
            self.assertIsNone(event["quarantine_status"])
            self.assertIsNone(event["quarantine_rule"])

    async def test_analyze_attack_on_protected_or_admin_ips_rejects_quarantine(self):
        """4. ATTACK involving a protected host, gateway, or administrator IP:
        No firewall block executes, SOC event explains why quarantine was rejected."""
        self.runtime.quarantine_manager.auto_quarantine = True
        mock_block = MagicMock()
        self.runtime.quarantine_manager.firewall.block = mock_block

        protected_test_cases = [
            ("127.0.0.1", "SELF_ATTACK_NO_NETWORK_BLOCK"),
            ("192.168.1.1", "SELF_ATTACK_NO_NETWORK_BLOCK"),
            ("192.168.1.50", "SELF_ATTACK_NO_NETWORK_BLOCK"),
            ("10.0.0.99", "ADMIN_IP_PROTECTED"),
        ]

        for ip, expected_status in protected_test_cases:
            flow = {**self.remote_flow, "flow_id": f"flow-{ip}", "source_ip": ip}
            mock_prediction = [{
                "flow_id": flow["flow_id"],
                "source_ip": ip,
                "destination_ip": flow["destination_ip"],
                "is_anomaly": True,
                "confidence": 95.0,
                "anomaly_probability": 0.95,
                "threshold": 0.53,
                "graph_nodes": 2,
                "graph_edges": 1,
            }]

            with patch("backend.network.runtime.gatv2_engine.predict_flows", return_value=mock_prediction), \
                 patch("backend.network.runtime.chat_state.event", new_callable=AsyncMock) as mock_event:
                await self.runtime._analyze([flow])

                mock_block.assert_not_called()
                call_kind, event = mock_event.call_args[0]
                self.assertEqual(event["action"], "ALERT")
                self.assertEqual(event["quarantine_status"], expected_status)
                self.assertEqual(event["quarantine_reason"], expected_status)
                self.assertIsNone(event["quarantine_rule"])

    async def test_analyze_firewall_failure_records_error_and_continues_processing(self):
        """5. Firewall execution failure:
        Error is recorded in SOC event, runtime continues processing subsequent flows,
        and background worker does not terminate."""
        self.runtime.quarantine_manager.auto_quarantine = True

        def block_side_effect(ip):
            if ip == "198.51.100.81":
                raise subprocess.CalledProcessError(1, "New-NetFirewallRule", "Access is denied.")
            return f"MajorProject-GATv2-Quarantine-{ip}"

        self.runtime.quarantine_manager.firewall.block = MagicMock(side_effect=block_side_effect)

        flow1 = {**self.remote_flow, "flow_id": "flow-fail", "source_ip": "198.51.100.81"}
        flow2 = {**self.remote_flow, "flow_id": "flow-succeed", "source_ip": "198.51.100.82"}

        mock_predictions = [
            {
                "flow_id": flow1["flow_id"], "source_ip": flow1["source_ip"], "destination_ip": flow1["destination_ip"],
                "is_anomaly": True, "confidence": 90.0, "anomaly_probability": 0.90, "threshold": 0.53,
                "graph_nodes": 2, "graph_edges": 1,
            },
            {
                "flow_id": flow2["flow_id"], "source_ip": flow2["source_ip"], "destination_ip": flow2["destination_ip"],
                "is_anomaly": True, "confidence": 91.0, "anomaly_probability": 0.91, "threshold": 0.53,
                "graph_nodes": 2, "graph_edges": 1,
            },
        ]

        with patch("backend.network.runtime.gatv2_engine.predict_flows", return_value=mock_predictions), \
             patch("backend.network.runtime.chat_state.event", new_callable=AsyncMock) as mock_event:
            # Process both flows in a single batch
            await self.runtime._analyze([flow1, flow2])

            self.assertEqual(mock_event.call_count, 2)
            event1 = mock_event.call_args_list[0][0][1]
            event2 = mock_event.call_args_list[1][0][1]

            # Flow 1 failed firewall command but did not crash batch
            self.assertEqual(event1["action"], "ALERT")
            self.assertTrue(event1["quarantine_status"].startswith("FIREWALL_ERROR"))
            self.assertIsNone(event1["quarantine_rule"])

            # Flow 2 succeeded
            self.assertEqual(event2["action"], "QUARANTINED")
            self.assertEqual(event2["quarantine_status"], "BLOCKED")
            self.assertEqual(event2["quarantine_rule"], "MajorProject-GATv2-Quarantine-198.51.100.82")

    async def test_analyze_preserves_endpoints_and_only_quarantines_source_ip(self):
        """6. Verify that event source and destination IPs are preserved correctly
        and only the intended source IP is passed to quarantine."""
        self.runtime.quarantine_manager.auto_quarantine = True
        mock_block = MagicMock(return_value="MajorProject-GATv2-Quarantine-src")
        self.runtime.quarantine_manager.firewall.block = mock_block

        mock_prediction = [{
            "flow_id": self.remote_flow["flow_id"],
            "source_ip": self.remote_flow["source_ip"],
            "destination_ip": self.remote_flow["destination_ip"],
            "is_anomaly": True,
            "confidence": 93.0,
            "anomaly_probability": 0.93,
            "threshold": 0.53,
            "graph_nodes": 2,
            "graph_edges": 1,
        }]

        with patch("backend.network.runtime.gatv2_engine.predict_flows", return_value=mock_prediction), \
             patch("backend.network.runtime.chat_state.event", new_callable=AsyncMock) as mock_event:
            await self.runtime._analyze([self.remote_flow])

            # Block must only be called with source_ip, never destination_ip
            mock_block.assert_called_once_with("198.51.100.22")
            self.assertNotIn("192.168.1.50", [call.args[0] for call in mock_block.call_args_list])

            event = mock_event.call_args[0][1]
            self.assertEqual(event["source_ip"], "198.51.100.22")
            self.assertEqual(event["destination_ip"], "192.168.1.50")


if __name__ == "__main__":
    unittest.main()
