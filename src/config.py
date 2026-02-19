"""Configuration for the Cognitive Network Defense System (CNDS)."""

import os

# ── Capture ─────────────────────────────────────────────────────────────────
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", None)   # None = auto
PACKET_WORKERS    = int(os.getenv("PACKET_WORKERS", "4"))
PACKET_QUEUE_SIZE = int(os.getenv("PACKET_QUEUE_SIZE", "20000"))

# ── Flow extractor ──────────────────────────────────────────────────────────
FLOW_TIMEOUT        = float(os.getenv("FLOW_TIMEOUT", "120"))    # seconds
MAX_ACTIVE_FLOWS    = int(os.getenv("MAX_ACTIVE_FLOWS", "50000"))
ACTIVE_IDLE_THRESH  = float(os.getenv("ACTIVE_IDLE_THRESH", "1.0"))  # seconds

# ── Host extractor ───────────────────────────────────────────────────────────
HOST_WINDOW_SIZE    = int(os.getenv("HOST_WINDOW_SIZE", "100"))   # packet history
MAX_TRACKED_IPS     = int(os.getenv("MAX_TRACKED_IPS", "5000"))
MIN_PACKETS_FOR_ML  = int(os.getenv("MIN_PACKETS_FOR_ML", "10"))

COMMON_PORTS = {
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443,
    465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443,
}

# ── Engine weights ────────────────────────────────────────────────────────────
WEIGHT_SUPERVISED   = float(os.getenv("WEIGHT_SUPERVISED", "0.40"))
WEIGHT_IFOREST      = float(os.getenv("WEIGHT_IFOREST", "0.30"))
WEIGHT_LSTM         = float(os.getenv("WEIGHT_LSTM", "0.20"))
WEIGHT_RULES        = float(os.getenv("WEIGHT_RULES", "0.10"))
ENSEMBLE_THRESHOLD  = float(os.getenv("ENSEMBLE_THRESHOLD", "0.55"))

# ── Rule thresholds ───────────────────────────────────────────────────────────
RATE_SPIKE_MULTIPLIER = float(os.getenv("RATE_SPIKE_MULTIPLIER", "2.0"))
ICMP_FLOOD_THRESHOLD  = int(os.getenv("ICMP_FLOOD_THRESHOLD", "50"))
PORT_SCAN_THRESHOLD   = int(os.getenv("PORT_SCAN_THRESHOLD", "20"))   # unique ports
LARGE_PAYLOAD_BYTES   = int(os.getenv("LARGE_PAYLOAD_BYTES", "10000"))
ALERT_COOLDOWN_SECS   = int(os.getenv("ALERT_COOLDOWN_SECS", "60"))

# ── Model paths ────────────────────────────────────────────────────────────────
MODELS_DIR          = os.getenv("MODELS_DIR", "models")
RF_MODEL_PATH       = os.path.join(MODELS_DIR, os.getenv("RF_MODEL_FILE", "rf_model.joblib"))
IF_MODEL_PATH       = os.path.join(MODELS_DIR, os.getenv("IF_MODEL_FILE", "isolation_forest.joblib"))
IF_SCALER_PATH      = os.path.join(MODELS_DIR, os.getenv("IF_SCALER_FILE", "if_scaler.joblib"))
LSTM_MODEL_PATH     = os.path.join(MODELS_DIR, os.getenv("LSTM_MODEL_FILE", "lstm_autoencoder.pt"))
LSTM_CONFIG_PATH    = os.path.join(MODELS_DIR, os.getenv("LSTM_CONFIG_FILE", "lstm_config.json"))

# ── Database ────────────────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./cnds.db")

# ── API ────────────────────────────────────────────────────────────────────────
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
API_KEY  = os.getenv("API_KEY", "")   # empty = no auth
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]

# ── Alerts ─────────────────────────────────────────────────────────────────────
DEDUP_WINDOW_SECS = int(os.getenv("DEDUP_WINDOW_SECS", "300"))
