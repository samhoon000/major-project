import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env if present
try:
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env")
except ImportError:
    pass

# Server
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))

# Security
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")

# Network & Capture
FLOW_TIMEOUT_SECONDS = float(os.getenv("FLOW_TIMEOUT_SECONDS", 10.0))
GRAPH_WINDOW_SECONDS = float(os.getenv("GRAPH_WINDOW_SECONDS", 5.0))
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", None)
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE") or CAPTURE_INTERFACE

# Cloudflare Tunnel Configuration
CLOUDFLARE_TUNNEL_TOKEN = os.getenv("CLOUDFLARE_TUNNEL_TOKEN", "").strip() or None
CLOUDFLARE_PUBLIC_HOSTNAME = os.getenv("CLOUDFLARE_PUBLIC_HOSTNAME", "").strip() or None
CLOUDFLARE_PATH = os.getenv("CLOUDFLARE_PATH", "cloudflared").strip()

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
GATV2_ANOMALY_THRESHOLD = 0.53
MESSAGE_RISK_WARN_THRESHOLD = 0.60
URL_RISK_WARN_THRESHOLD = 0.65
BEHAVIOR_FLOOD_THRESHOLD = 0.70

# Cumulative User Risk Threshold for Blocking
USER_BLOCK_THRESHOLD = 0.85

# Behavior Limits (rolling window)
BEHAVIOR_WINDOW_SECONDS = 10.0
MAX_MESSAGES_PER_WINDOW = 6
MAX_REPEATED_MESSAGES = 3

# Network Quarantine & Firewall Settings
NETWORK_AUTO_QUARANTINE = os.getenv("NETWORK_AUTO_QUARANTINE", "false").lower() in ("true", "1", "yes")
ADMIN_IPS = [ip.strip() for ip in os.getenv("ADMIN_IPS", "").split(",") if ip.strip()]


