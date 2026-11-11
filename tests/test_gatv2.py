from backend.network.gatv2_inference import gatv2_engine

def test_gatv2_inference():
    # Real CICIDS2017-style benign flow: long duration, bidirectional exchange, moderate packet rate
    benign_flow = {
        "flow_id": "flow-phone-normal",
        "src_ip": "192.168.1.105",
        "dst_ip": "192.168.1.100",
        "src_port": 54321,
        "dst_port": 8000,
        "protocol": "TCP",
        "duration": 12000000.0,  # 12 seconds
        "fwd_packets": 6,
        "bwd_packets": 6,
        "flow_bytes_s": 250.0,
        "flow_packets_s": 1.0
    }

    # Real CICIDS2017-style attack flow: rapid scan/flood probe, ultra-short duration, zero backward response, high rate
    attack_flow = {
        "flow_id": "flow-portscan-probe",
        "src_ip": "192.168.1.200",
        "dst_ip": "192.168.1.100",
        "src_port": 44444,
        "dst_port": 8000,
        "protocol": "TCP",
        "duration": 48.0,  # 48 microseconds
        "fwd_packets": 1,
        "bwd_packets": 0,
        "flow_bytes_s": 125000.0,
        "flow_packets_s": 41666.0
    }

    sample_flows = [benign_flow, attack_flow]

    results = gatv2_engine.predict_flows(sample_flows)
    assert len(results) == 2, f"Expected 2 results, got {len(results)}"
    
    print("GATv2 Test Results:")
    for r in results:
        print(f"Flow {r['flow_id']} ({r['source_ip']} -> {r['destination_ip']}):")
        print(f"  Prediction : {r['prediction']}")
        print(f"  Confidence : {r['confidence']}%")
        print(f"  Probability: {r['anomaly_probability']}")
        print(f"  Attention  : {r['attention_score']}")

    normal_prob = results[0]["anomaly_probability"]
    attack_prob = results[1]["anomaly_probability"]
    print(f"\nNormal Prob: {normal_prob:.4f}, Attack Prob: {attack_prob:.4f}")
    assert results[0]["prediction"] == "NORMAL", "Benign flow should be classified as NORMAL!"
    assert results[1]["prediction"] == "ANOMALY", "Attack probe should be classified as ANOMALY!"
    print("\nSUCCESS: GATv2 Inductive Live Inference Test Passed!")

if __name__ == "__main__":
    test_gatv2_inference()
