import json
import logging
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import torch
from torch_geometric.data import Data

from backend.config import (
    GATV2_MODEL_PATH,
    NODE_SCALER_PATH,
    EDGE_SCALER_PATH,
    FEATURE_CONFIG_PATH,
    MODEL_CONFIG_PATH,
    GATV2_ANOMALY_THRESHOLD
)
from ml.model import GNNAnomalyDetector
from ml.preprocessing import compute_inductive_node_features, preprocess_features_log, EDGE_FEATURE_COLS

logger = logging.getLogger(__name__)

class GATv2InferenceEngine:
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = None
        self.node_scaler = None
        self.edge_scaler = None
        self.feature_config = None
        self.model_config = None
        self.best_threshold = GATV2_ANOMALY_THRESHOLD
        self._is_loaded = False
        self.load()

    def load(self):
        try:
            if not GATV2_MODEL_PATH.exists():
                raise FileNotFoundError(f"GATv2 model file not found at {GATV2_MODEL_PATH}")

            with open(FEATURE_CONFIG_PATH, "r") as f:
                self.feature_config = json.load(f)

            with open(MODEL_CONFIG_PATH, "r") as f:
                self.model_config = json.load(f)
                self.best_threshold = self.model_config.get("best_threshold", GATV2_ANOMALY_THRESHOLD)

            self.node_scaler = joblib.load(NODE_SCALER_PATH)
            self.edge_scaler = joblib.load(EDGE_SCALER_PATH)

            self.model = GNNAnomalyDetector(
                node_dim=self.feature_config.get("node_dim", 5),
                edge_dim=self.feature_config.get("edge_dim", 5),
                hidden_dim=self.model_config.get("hidden_dim", 64),
                heads=self.model_config.get("heads", 4),
                dropout=0.0
            ).to(self.device)

            state_dict = torch.load(GATV2_MODEL_PATH, map_location=self.device, weights_only=True)
            self.model.load_state_dict(state_dict)
            self.model.eval()
            self._is_loaded = True
            logger.info("GATv2 Inference Engine successfully loaded from disk.")
        except Exception as e:
            logger.error(f"Failed to load GATv2 Inference Engine: {e}")
            self._is_loaded = False

    def predict_flows(self, flows: list) -> list:
        if not flows:
            return []

        if not self._is_loaded:
            self.load()
            if not self._is_loaded:
                return []

        src_ips = [f["src_ip"] for f in flows]
        dst_ips = [f["dst_ip"] for f in flows]
        unique_ips = list(dict.fromkeys(src_ips + dst_ips))

        metrics_data = {
            "Flow Duration": [float(f.get("duration", 0.0)) for f in flows],
            "Total Fwd Packets": [float(f.get("fwd_packets", 0)) for f in flows],
            "Total Backward Packets": [float(f.get("bwd_packets", 0)) for f in flows],
            "Flow Bytes/s": [float(f.get("flow_bytes_s", 0.0)) for f in flows],
            "Flow Packets/s": [float(f.get("flow_packets_s", 0.0)) for f in flows],
        }
        metrics_df = pd.DataFrame(metrics_data)

        # 1. Inductive node features
        raw_node_features, ip_to_idx = compute_inductive_node_features(
            unique_ips, src_ips, dst_ips, metrics_df
        )

        # 2. Extract edge features
        raw_edge_features = metrics_df[EDGE_FEATURE_COLS].to_numpy(dtype=np.float32)

        # 3. Log-stabilization
        log_node_features = preprocess_features_log(raw_node_features)
        log_edge_features = preprocess_features_log(raw_edge_features)

        # 4. Standardize using saved Scalers
        norm_node_features = self.node_scaler.transform(log_node_features)
        norm_edge_features = self.edge_scaler.transform(log_edge_features)

        # 5. Build edge index
        src_indices = [ip_to_idx[s] for s in src_ips]
        dst_indices = [ip_to_idx[d] for d in dst_ips]

        edge_index = torch.tensor([src_indices, dst_indices], dtype=torch.long, device=self.device)
        edge_attr = torch.tensor(norm_edge_features, dtype=torch.float, device=self.device)
        x = torch.tensor(norm_node_features, dtype=torch.float, device=self.device)

        # 6. GATv2 Inference
        with torch.no_grad():
            logits, attention_info = self.model(x, edge_index, edge_attr, return_attention=True)
            probs = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()

            _, att_weights = attention_info
            att_weights = att_weights.detach().cpu().numpy()
            if att_weights.ndim > 1:
                att_weights = att_weights.mean(axis=1)

        # 7. Package results
        results = []
        for i, flow in enumerate(flows):
            anomaly_prob = float(probs[i])
            is_anomaly = bool(anomaly_prob >= self.best_threshold)
            confidence = anomaly_prob if is_anomaly else (1.0 - anomaly_prob)
            att_val = float(att_weights[i]) if i < len(att_weights) else 0.0

            results.append({
                "flow_id": flow.get("flow_id", f"{flow['src_ip']}->{flow['dst_ip']}:{i}"),
                "source_ip": flow["src_ip"],
                "destination_ip": flow["dst_ip"],
                "protocol": flow.get("protocol", "TCP"),
                "source_port": flow.get("src_port", 0),
                "destination_port": flow.get("dst_port", 0),
                "duration": float(flow.get("duration", 0.0)),
                "fwd_packets": int(flow.get("fwd_packets", 0)),
                "bwd_packets": int(flow.get("bwd_packets", 0)),
                "total_packets": int(flow.get("fwd_packets", 0) + flow.get("bwd_packets", 0)),
                "flow_bytes_s": float(flow.get("flow_bytes_s", 0.0)),
                "flow_packets_s": float(flow.get("flow_packets_s", 0.0)),
                "prediction": "ANOMALY" if is_anomaly else "NORMAL",
                "is_anomaly": is_anomaly,
                "confidence": round(confidence * 100, 2),
                "anomaly_probability": round(anomaly_prob, 4),
                "threshold": self.best_threshold,
                "attention_score": round(att_val, 4),
                "graph_nodes": int(x.shape[0]),
                "graph_edges": int(edge_index.shape[1]),
                "model_name": "GATv2 Network Anomaly Detector"
            })

        return results

gatv2_engine = GATv2InferenceEngine()
