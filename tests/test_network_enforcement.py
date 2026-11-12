import unittest

from backend.network.enforcement import QuarantineManager, WindowsFirewall


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
        self.manager = QuarantineManager(self.firewall, duration_seconds=20,
                                         protected_ips={"127.0.0.1", "192.168.1.20"},
                                         admin_ips={"192.168.1.10"}, clock=lambda: self.now,
                                         platform_name="Windows")
        self.attack = {"flow_id": "flow-1", "source_ip": "192.168.1.45",
                       "prediction": "ATTACK", "anomaly_probability": 0.91,
                       "threshold": 0.53}

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
        self.assertEqual(result.status, "ADMIN_UNBLOCKED")
        self.assertEqual(self.firewall.removed, [block.rule_name])

    def test_normal_shutdown_removes_non_expired_rule(self):
        block, _ = self.manager.handle_attack(self.attack)
        closed = self.manager.close()
        self.assertEqual(closed[0].status, "SHUTDOWN_CLEANUP")
        self.assertEqual(self.firewall.removed, [block.rule_name])

    def test_server_and_admin_addresses_cannot_be_blocked(self):
        for source, action in (("127.0.0.1", "SELF_ATTACK_NO_NETWORK_BLOCK"),
                               ("192.168.1.20", "SELF_ATTACK_NO_NETWORK_BLOCK"),
                               ("192.168.1.10", "ADMIN_IP_PROTECTED")):
            event = {**self.attack, "source_ip": source}
            self.assertEqual(self.manager.handle_attack(event)[1], action)
        self.assertEqual(self.firewall.added, [])

    def test_non_windows_enforcement_fails_closed(self):
        manager = QuarantineManager(self.firewall, protected_ips=set(), admin_ips=set(),
                                    platform_name="Linux")
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


if __name__ == "__main__":
    unittest.main()
