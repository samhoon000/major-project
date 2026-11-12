import unittest
import math

from backend.network.flow_tracker import FlowTracker
from backend.security.behavior_analyzer import BehaviorAnalyzer, BehaviorConfig


class IdentityScaler:
    def transform(self, values):
        return values


class FakePacket:
    def __init__(self, layers):
        self.layers = layers
        self.time = 42.5

    def __contains__(self, layer):
        return layer in self.layers

    def __getitem__(self, layer):
        return self.layers[layer]

    def __len__(self):
        return 123


class FakeClock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


class LiveNetworkTests(unittest.TestCase):
    def test_reverse_packets_are_one_bidirectional_flow(self):
        tracker = FlowTracker(idle_timeout=10, clock=FakeClock())
        tracker.add_packet("10.0.0.1", "10.0.0.2", 5000, 8000, "TCP", 100, 100, "S")
        current = tracker.add_packet("10.0.0.2", "10.0.0.1", 8000, 5000, "TCP", 60, 101, "A")
        self.assertEqual(len(tracker.active), 1)
        self.assertEqual(current["forward_packet_count"], 1)
        self.assertEqual(current["backward_packet_count"], 1)
        self.assertEqual(current["total_bytes"], 160)

    def test_idle_flow_finalizes_and_features_use_training_units(self):
        clock = FakeClock()
        tracker = FlowTracker(idle_timeout=5, clock=clock)
        tracker.add_packet("10.0.0.1", "10.0.0.2", 5000, 8000, "UDP", 100, 100)
        tracker.add_packet("10.0.0.1", "10.0.0.2", 5000, 8000, "UDP", 100, 102)
        expired = tracker.expire(now=108)
        self.assertEqual(len(expired), 1)
        features = tracker.features(expired[0])
        self.assertEqual(features["Flow Duration"], 2_000_000)
        self.assertEqual(features["Total Fwd Packets"], 2)
        self.assertEqual(features["Flow Bytes/s"], 100)

    def test_behavior_windows_and_block_threshold(self):
        clock = FakeClock()
        analyzer = BehaviorAnalyzer(BehaviorConfig(warning_messages_30s=3, block_messages_30s=5), clock)
        for i in range(5):
            details = analyzer.record("flooder", "peer", f"msg {i}")
        self.assertEqual(details["risk"], "BLOCK")
        self.assertEqual(details["messages_last_30_seconds"], 5)
        clock.value += 31
        details = analyzer.record("flooder", "peer", "new")
        self.assertEqual(details["messages_last_30_seconds"], 1)
        self.assertEqual(details["risk"], "SAFE")

    def test_packet_parser_ignores_unsupported_without_scapy_dependency(self):
        from backend.network.capture import parse_scapy_packet
        self.assertIsNone(parse_scapy_packet(object()))

    def test_packet_parser_extracts_tcp_and_udp(self):
        from scapy.layers.inet import IP, TCP, UDP
        from backend.network.capture import parse_scapy_packet

        class Layer:
            pass

        ip, tcp = Layer(), Layer()
        ip.src, ip.dst, tcp.sport, tcp.dport, tcp.flags = "192.0.2.1", "192.0.2.2", 51000, 8000, "SA"
        parsed = parse_scapy_packet(FakePacket({IP: ip, TCP: tcp}))
        self.assertEqual((parsed["protocol"], parsed["source_port"], parsed["tcp_flags"]), ("TCP", 51000, "SA"))
        udp = Layer()
        ip2 = Layer()
        ip2.src, ip2.dst, udp.sport, udp.dport = "192.0.2.3", "192.0.2.4", 53000, 53
        parsed = parse_scapy_packet(FakePacket({IP: ip2, UDP: udp}))
        self.assertEqual((parsed["protocol"], parsed["destination_port"]), ("UDP", 53))

    def test_inductive_graph_maps_unseen_ips_locally(self):
        from backend.network.live_graph import build_live_graph, FEATURES
        flows = [{"flow_id": "f1", "source_ip": "192.0.2.50", "destination_ip": "192.0.2.72",
                  "features": dict(zip(FEATURES, [1000, 3, 2, 500, 5]))}]
        graph = build_live_graph(flows, IdentityScaler(), IdentityScaler())
        self.assertEqual(graph.ip_to_index, {"192.0.2.50": 0, "192.0.2.72": 1})
        self.assertEqual(graph.edge_index.tolist(), [[0], [1]])
        self.assertEqual(tuple(graph.x.shape), (2, 5))
        self.assertEqual(graph.live_node_features["192.0.2.50"], [0.0, 1.0, 5.0, 0.5, 1000.0])
        self.assertEqual(graph.live_node_features["192.0.2.72"], [1.0, 0.0, 5.0, 0.5, 1000.0])
        self.assertAlmostEqual(graph.x[0, 1].item(), math.log1p(1.0), places=6)
        self.assertAlmostEqual(graph.edge_attr[0, 0].item(), math.log1p(1000.0), places=6)

    def test_attack_event_retains_captured_flow_identity(self):
        from backend.network.runtime import build_attack_event
        flow = {"flow_id": "real-flow", "source_ip": "192.168.1.45", "destination_ip": "192.168.1.20",
                "source_port": 54001, "destination_port": 8001, "protocol": "TCP"}
        result = {"prediction": "ATTACK", "anomaly_probability": 0.91, "threshold": 0.53}
        event = build_attack_event(flow, result, timestamp=100.0)
        self.assertEqual((event["flow_id"], event["source_ip"], event["destination_ip"]),
                         ("real-flow", "192.168.1.45", "192.168.1.20"))
        self.assertEqual((event["source_port"], event["destination_port"], event["protocol"]), (54001, 8001, "TCP"))
        self.assertEqual((event["prediction"], event["anomaly_probability"], event["threshold"], event["timestamp"]),
                         ("ATTACK", 0.91, 0.53, 100.0))

    def test_gatv2_probability_uses_saved_threshold_decision(self):
        from backend.network.gatv2_inference import classify_anomaly_probability
        self.assertEqual(classify_anomaly_probability(0.53, 0.53), "ATTACK")
        self.assertEqual(classify_anomaly_probability(0.531, 0.53), "ATTACK")
        self.assertEqual(classify_anomaly_probability(0.529, 0.53), "BENIGN")

    def test_gatv2_fails_closed_when_checkpoint_or_scalers_are_missing(self):
        from backend.network.gatv2_inference import GATv2Inference
        inference = GATv2Inference(model_path="missing-test-model.pth",
                                   node_scaler_path="missing-test-node-scaler.pkl",
                                   edge_scaler_path="missing-test-edge-scaler.pkl",
                                   config_path="missing-test-config.json")
        self.assertFalse(inference.available)
        self.assertIn("missing-test-model.pth", inference.error)

    def test_restored_real_gatv2_checkpoint_and_scalers_load(self):
        from backend.network.gatv2_inference import GATv2Inference
        inference = GATv2Inference()
        self.assertTrue(inference.available, inference.error)
        self.assertEqual(inference.threshold, 0.53)
        self.assertEqual(inference.node_scaler.n_features_in_, 5)
        self.assertEqual(inference.edge_scaler.n_features_in_, 5)


if __name__ == "__main__":
    unittest.main()
