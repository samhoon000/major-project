from pathlib import Path

import pandas as pd
import pytest
from backend.network.gatv2_inference import gatv2_engine

DATASET = Path(__file__).resolve().parents[1] / "data" / "cleaned_dataset.csv"


@pytest.mark.skipif(not DATASET.exists(), reason="optional offline GATv2 evaluation requires data/cleaned_dataset.csv")
def test_mixed():
    df = pd.read_csv(DATASET)
    sample_benign = df[df["Label"] == 0].sample(5, random_state=42)
    sample_attack = df[df["Label"] == 1].sample(5, random_state=42)
    combined = pd.concat([sample_benign, sample_attack]).reset_index(drop=True)

    flows = []
    for i, r in combined.iterrows():
        flows.append({
            "flow_id": f"flow-{i}",
            "src_ip": str(r["Source IP"]),
            "dst_ip": str(r["Destination IP"]),
            "duration": float(r["Flow Duration"]),
            "fwd_packets": int(r["Total Fwd Packets"]),
            "bwd_packets": int(r["Total Backward Packets"]),
            "flow_bytes_s": float(r["Flow Bytes/s"]),
            "flow_packets_s": float(r["Flow Packets/s"]),
            "true_label": int(r["Label"])
        })

    res = gatv2_engine.predict_flows(flows)
    print("Results on 10 mixed flows:")
    benign_probs = []
    attack_probs = []
    for i, r in enumerate(res):
        true_type = "ATTACK" if flows[i]["true_label"] == 1 else "BENIGN"
        prob = r["anomaly_probability"]
        print(f"{r['flow_id']} [Actual: {true_type:6s}] -> Pred: {r['prediction']:7s} (Prob: {prob:.4f}, Conf: {r['confidence']}%)")
        if flows[i]["true_label"] == 0:
            benign_probs.append(prob)
        else:
            attack_probs.append(prob)

    avg_benign = sum(benign_probs) / len(benign_probs)
    avg_attack = sum(attack_probs) / len(attack_probs)
    print(f"\nAverage Benign Prob: {avg_benign:.4f}")
    print(f"Average Attack Prob: {avg_attack:.4f}")
    assert avg_attack > avg_benign, "Attack flows must have significantly higher anomaly probability!"
    print("SUCCESS: GATv2 model separates Benign vs Attack on live window graph!")

if __name__ == "__main__":
    test_mixed()

