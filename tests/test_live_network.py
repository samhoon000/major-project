import unittest
import pandas as pd

from backend.network.capture import parse_scapy_packet
from backend.network.flow_tracker import FlowTracker
from backend.security.live_behavior_analyzer import BehaviorAnalyzer, BehaviorConfig
from ml.graph_builder import build_inductive_graph
from ml.preprocessing import EDGE_FEATURE_COLS


class FakeClock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


class IdentityScaler:
    def transform(self, values):
        return values


class FakePacket:
    def __init__(self, layers):
        self.layers, self.time = layers, 42.5

    def __contains__(self, layer):
        return layer in self.layers

    def __getitem__(self, layer):
        return self.layers[layer]

    def __len__(self):
        return 999  # Ethernet length; parser should use the IPv4 packet length.


class LiveNetworkTests(unittest.TestCase):
    def test_reverse_packets_share_one_flow_and_expire(self):
        clock = FakeClock()
        tracker = FlowTracker(idle_timeout=5, clock=clock)
        tracker.add_packet("10.0.0.1", "10.0.0.2", 5000, 8000, "TCP", 100, 100, "S")
        flow = tracker.add_packet("10.0.0.2", "10.0.0.1", 8000, 5000, "TCP", 60, 102, "A")
        self.assertEqual(len(tracker.active), 1)
        self.assertEqual((flow["forward_packet_count"], flow["backward_packet_count"]), (1, 1))
        self.assertEqual(flow["total_bytes"], 160)
        expired = tracker.expire(now=108)
        self.assertEqual(len(expired), 1)
        features = tracker.features(expired[0])
        self.assertEqual(features["Flow Duration"], 2_000_000)
        self.assertEqual(features["Flow Bytes/s"], 80)

    def test_udp_flow_and_max_duration_expiration(self):
        tracker = FlowTracker(idle_timeout=20, max_duration=3, clock=FakeClock())
        tracker.add_packet("10.0.0.1", "10.0.0.2", 53000, 53, "UDP", 80, 100)
        expired = tracker.expire(now=104)
        self.assertEqual(expired[0]["protocol"], "UDP")

    def test_packet_parser_extracts_tcp_flags_and_ipv4_packet_size(self):
        from scapy.layers.inet import IP, TCP
        ip, tcp = type("IPLayer", (), {})(), type("TCPLayer", (), {})()
        ip.src, ip.dst = "192.0.2.1", "192.0.2.2"
        ip.__len__ = lambda self: 60
        tcp.sport, tcp.dport, tcp.flags = 51000, 8000, "SA"
        # Special methods are resolved on the class, so use a tiny concrete IP layer.
        class IPLayer:
            src, dst = "192.0.2.1", "192.0.2.2"
            def __len__(self): return 60
        parsed = parse_scapy_packet(FakePacket({IP: IPLayer(), TCP: tcp}))
        self.assertEqual((parsed["protocol"], parsed["packet_length"], parsed["tcp_flags"]), ("TCP", 60, "SA"))

    def test_unsupported_packet_is_ignored(self):
        self.assertIsNone(parse_scapy_packet(object()))

    def test_graph_builder_uses_local_mapping_for_unseen_ips(self):
        row = {"Source IP": "198.51.100.10", "Destination IP": "203.0.113.20",
               "Flow Duration": 1_000_000, "Total Fwd Packets": 3,
               "Total Backward Packets": 2, "Flow Bytes/s": 500, "Flow Packets/s": 5}
        graph, _, _ = build_inductive_graph(pd.DataFrame([row]), IdentityScaler(), IdentityScaler())
        self.assertEqual(graph.unique_ips, ["198.51.100.10", "203.0.113.20"])
        self.assertEqual(graph.edge_index.tolist(), [[0], [1]])
        self.assertEqual(tuple(graph.x.shape), (2, 5))

    def test_behavior_sliding_window_block_threshold(self):
        clock = FakeClock()
        analyzer = BehaviorAnalyzer(BehaviorConfig(warning_messages_30s=3, block_messages_30s=5), clock)
        for i in range(5):
            details = analyzer.record("bulk", "peer", f"message {i}")
        self.assertEqual(details["risk"], "BLOCK")
        clock.value += 31
        details = analyzer.record("bulk", "peer", "new")
        self.assertEqual(details["messages_last_30_seconds"], 1)


if __name__ == "__main__":
    unittest.main()
