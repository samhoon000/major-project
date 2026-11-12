"""Honest GATv2 runtime wrapper around the repository's existing architecture."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)


def classify_anomaly_probability(probability: float, threshold: float) -> str:
    # Match the recovered GATv2 inference engine's saved-threshold semantics.
    return "ATTACK" if float(probability) >= float(threshold) else "BENIGN"


class GATv2Inference:
    def __init__(self, model_path=None, node_scaler_path=None, edge_scaler_path=None, config_path=None):
        model_path = model_path or os.getenv("GATV2_MODEL_PATH", "models/gatv2_model.pth")
        node_scaler_path = node_scaler_path or os.getenv("NODE_SCALER_PATH", "models/node_scaler.pkl")
        edge_scaler_path = edge_scaler_path or os.getenv("EDGE_SCALER_PATH", "models/edge_scaler.pkl")
        config_path = config_path or os.getenv("GATV2_CONFIG_PATH", "models/model_config.json")
        feature_config_path = os.getenv("GATV2_FEATURE_CONFIG_PATH", "models/feature_config.json")
        self.model_path, self.node_scaler_path = Path(model_path), Path(node_scaler_path)
        self.edge_scaler_path, self.config_path = Path(edge_scaler_path), Path(config_path)
        self.feature_config_path = Path(feature_config_path)
        self.available = False
        self.error = None
        self.model = self.node_scaler = self.edge_scaler = None
        self._load()

    def _load(self):
        missing = [str(path) for path in (self.model_path, self.node_scaler_path, self.edge_scaler_path,
                                         self.config_path, self.feature_config_path) if not path.is_file()]
        if missing:
            self.error = "Required existing GATv2 artifacts are missing: " + ", ".join(missing)
            log.warning("[GATV2] unavailable: %s", self.error)
            return
        try:
            import joblib
            import torch
            from model import GNNAnomalyDetector
            if not self.config_path.is_file():
                raise FileNotFoundError(f"GATv2 config with saved classification threshold is required: {self.config_path}")
            config = json.loads(self.config_path.read_text(encoding="utf-8"))
            from backend.network.live_graph import FEATURES, NODE_FEATURES
            feature_config = json.loads(self.feature_config_path.read_text(encoding="utf-8"))
            if feature_config.get("edge_features") != FEATURES or feature_config.get("node_features") != NODE_FEATURES:
                raise ValueError("Saved feature config does not match the repository's live graph feature schema")
            if feature_config.get("log_transform") is not True:
                raise ValueError("Saved GATv2 feature config requires log1p preprocessing")
            node_dim = int(feature_config["node_dim"])
            edge_dim = int(feature_config["edge_dim"])
            if node_dim != len(NODE_FEATURES) or edge_dim != len(FEATURES):
                raise ValueError(f"Saved GATv2 dimensions ({node_dim}, {edge_dim}) conflict with the five-feature live graph")
            self.threshold = float(config.get("best_threshold", config.get("threshold")))
            if not 0.0 < self.threshold < 1.0:
                raise ValueError("Saved GATv2 threshold must be between 0 and 1")
            if int(config.get("hidden_dim", 64)) != 64 or int(config.get("heads", 4)) != 4:
                raise ValueError("Saved GATv2 config architecture is incompatible with the current model definition")
            self.model = GNNAnomalyDetector(node_dim=node_dim, edge_dim=edge_dim)
            state = torch.load(self.model_path, map_location="cpu", weights_only=True)
            if isinstance(state, dict) and "state_dict" in state:
                state = state["state_dict"]
            self.model.load_state_dict(state)
            self.model.eval()
            self.node_scaler = joblib.load(self.node_scaler_path)
            self.edge_scaler = joblib.load(self.edge_scaler_path)
            if self.node_scaler.n_features_in_ != node_dim or self.edge_scaler.n_features_in_ != edge_dim:
                raise ValueError("Saved scaler dimensions do not match the model feature configuration")
            self.available = True
        except Exception as exc:
            self.error = f"GATv2 artifact load failed: {exc}"
            log.exception("[GATV2] unavailable")

    def analyze(self, flows: list[dict]) -> list[dict]:
        if not self.available:
            raise RuntimeError(self.error or "GATv2 unavailable")
        import torch
        from backend.network.live_graph import FEATURES, NODE_FEATURES, build_live_graph
        graph = build_live_graph(flows, self.node_scaler, self.edge_scaler)
        log.info("[GRAPH] nodes=%d edges=%d", graph.x.shape[0], graph.edge_index.shape[1])
        with torch.inference_mode():
            logits = self.model(graph.x, graph.edge_index, graph.edge_attr)
            probabilities = torch.softmax(logits, dim=1)
            anomaly_probabilities = probabilities[:, 1]
        results = []
        for index, flow in enumerate(flows):
            probability = float(anomaly_probabilities[index].item())
            prediction = classify_anomaly_probability(probability, self.threshold)
            label = int(prediction == "ATTACK")
            results.append({"flow_id": flow.get("flow_id"), "prediction": prediction,
                            "anomaly_probability": probability, "threshold": self.threshold, "class_id": label,
                            "node_features": dict(zip(NODE_FEATURES, graph.live_node_features.get(flow["source_ip"], []))),
                            "edge_features": dict(zip(FEATURES, graph.live_edge_features[index])),
                            "node_model_features": dict(zip(NODE_FEATURES, graph.live_node_model_features.get(flow["source_ip"], []))),
                            "edge_model_features": dict(zip(FEATURES, graph.live_edge_model_features[index])),
                            "graph_node_count": int(graph.x.shape[0]),
                            "graph_edge_count": int(graph.edge_index.shape[1])})
        return results
