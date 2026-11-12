import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Server
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))

# Network & Capture
FLOW_TIMEOUT_SECONDS = float(os.getenv("FLOW_TIMEOUT_SECONDS", 10.0))
GRAPH_WINDOW_SECONDS = float(os.getenv("GRAPH_WINDOW_SECONDS", 5.0))
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", None)

# Model Artifacts
MODELS_DIR = BASE_DIR / "models"
GATV2_MODEL_PATH = MODELS_DIR / "gatv2_model.pth"
NODE_SCALER_PATH = MODELS_DIR / "node_scaler.pkl"
EDGE_SCALER_PATH = MODELS_DIR / "edge_scaler.pkl"
FEATURE_CONFIG_PATH = MODELS_DIR / "feature_config.json"
MODEL_CONFIG_PATH = MODELS_DIR / "model_config.json"

# Security & Threat Engine Weights
WEIGHT_GATV2_NETWORK = 0.40
WEIGHT_MESSAGE_CONTENT = 0.20
WEIGHT_URL_RISK = 0.25
WEIGHT_BEHAVIOR_RISK = 0.15

# Thresholds
GATV2_ANOMALY_THRESHOLD = 0.50
MESSAGE_RISK_WARN_THRESHOLD = 0.60
URL_RISK_WARN_THRESHOLD = 0.65
BEHAVIOR_FLOOD_THRESHOLD = 0.70

# Cumulative User Risk Threshold for Blocking
USER_BLOCK_THRESHOLD = 0.85

# Behavior Limits (rolling window)
BEHAVIOR_WINDOW_SECONDS = 10.0
MAX_MESSAGES_PER_WINDOW = 6
MAX_REPEATED_MESSAGES = 3

