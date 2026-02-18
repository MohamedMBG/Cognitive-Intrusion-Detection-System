# Cognitive Network Defense System

Multi-engine network defense system combining supervised classification (ML-IDS), unsupervised anomaly detection (cognitive-anomaly-detector), and rule-based heuristics into a unified pipeline.

## Architecture

```
[Scapy capture] ──► [PacketProcessor queue (async)]
                            │
                      [Dispatcher]
                     /      |      \
            Flow      Host     Payload
          Extractor  Extractor  Analyzer
          (76 feat)  (18 feat)  (patterns)
              │          │          │
              ▼          ▼          │
         Supervised  IsolationForest│
         (RF model)  + LSTM AE      │
              └──────────┴──────────┘
                         │
                  [Ensemble Scorer]
                  weighted confidence
                         │
               Alert + FastAPI + SQLite
```

### Detection Engines

| Engine | Input | Detects |
|---|---|---|
| **Supervised** (Random Forest) | 76 CICFlowMeter flow features | Named attacks from CIC-IDS2017 training |
| **Isolation Forest** | 18 per-IP host features | Zero-day / novel anomalies |
| **LSTM Autoencoder** | 18-feature sequence per IP | Slow attacks, temporal patterns |
| **Rules** | Flow metadata + payload | ICMP floods, port scans, SQLi, XSS, etc. |

Default ensemble weights: Supervised 40%, IF 30%, LSTM 20%, Rules 10%. Missing engines have their weight redistributed to active ones.

## Quick Start

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### Add models

Copy trained model files to `models/`:
```bash
# From ML-IDS
cp /path/to/ml-ids/models/rf_model.joblib            models/

# From cognitive-anomaly-detector
cp /path/to/cognitive/models/isolation_forest_v1.joblib models/isolation_forest.joblib
cp /path/to/cognitive/models/scaler_v1.joblib           models/if_scaler.joblib
cp /path/to/cognitive/models/lstm_autoencoder.pt        models/
cp /path/to/cognitive/models/lstm_config.json           models/
```

The system works with any subset of models — missing engines are skipped and their weights redistributed.

### Run

```bash
# Capture + detect (requires root for packet capture)
sudo venv/bin/python main.py

# Also start API server on :8000
sudo venv/bin/python main.py --api

# API only (no packet capture)
uvicorn src.api.main:app --host 0.0.0.0 --port 8000

# Docker
docker-compose up -d
```

### API

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Engine availability status |
| `/api/predict` | POST | Run all engines on supplied features |
| `/api/alerts` | GET | List alerts (filter by severity, IP, ack) |
| `/api/alerts/{id}` | PATCH | Acknowledge / add notes |
| `/api/incidents` | GET / POST | Incident management |
| `/api/stats` | GET | Alert counts by severity |
| `/docs` | GET | Swagger UI |

**Predict example:**
```bash
curl -X POST http://localhost:8000/api/predict \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1",
    "dst_port": 80,
    "protocol": 6,
    "host_features": [45.2, 5200.0, 115.0, 800.0, 452, 52000,
                      0.02, 0.005, 12.0, 10.0, 0.9, 0.1, 0.0,
                      3.0, 0.2, 3.5, 80.0, 200.0]
  }'
```

## Testing

```bash
pytest tests/ -v
pytest tests/ --cov=src --cov-report=term-missing
```

## Configuration

See [`.env.example`](.env.example) for all options. Key settings:

| Variable | Default | Description |
|---|---|---|
| `ENSEMBLE_THRESHOLD` | `0.55` | Score above which an alert is fired |
| `WEIGHT_SUPERVISED` | `0.40` | Supervised engine weight |
| `WEIGHT_IFOREST` | `0.30` | Isolation Forest weight |
| `WEIGHT_LSTM` | `0.20` | LSTM weight |
| `WEIGHT_RULES` | `0.10` | Rules weight |
| `FLOW_TIMEOUT` | `120` | Seconds before an inactive flow is flushed |
| `PACKET_WORKERS` | `4` | Async worker threads |

## Project Structure

```
├── src/
│   ├── capture/
│   │   ├── packet_capture.py   # Scapy + async queue
│   │   └── dispatcher.py       # Fan-out to feature pipelines
│   ├── features/
│   │   ├── flow_extractor.py   # 78 CICFlowMeter-compatible features
│   │   ├── host_extractor.py   # 18 per-IP host features
│   │   └── payload_analyzer.py # Pattern matching (SQLi, XSS, etc.)
│   ├── engines/
│   │   ├── supervised.py       # Random Forest wrapper
│   │   ├── isolation_forest.py # Isolation Forest wrapper
│   │   ├── lstm_autoencoder.py # LSTM Autoencoder wrapper
│   │   └── rules.py            # Rule-based engine
│   ├── ensemble/
│   │   └── scorer.py           # Weighted confidence fusion
│   └── api/
│       ├── main.py             # FastAPI app
│       ├── models.py           # SQLAlchemy ORM
│       ├── schemas.py          # Pydantic schemas
│       ├── database.py         # Async DB setup
│       └── routers/
│           ├── predict.py      # POST /api/predict
│           └── alerts.py       # Alert / incident CRUD
├── models/                     # ML model files (not committed)
├── tests/
├── main.py                     # Entry point (capture + detection)
├── docker-compose.yml
└── requirements.txt
```

## Roadmap

- [x] Phase 1 — Shared capture layer (single Scapy loop → dual feature extraction)
- [x] Phase 2 — All four engines + ensemble scoring + FastAPI orchestration
- [ ] Phase 3 — Payload pattern integration into supervised feature set
- [ ] Phase 4 — Confidence calibration and per-attack-type weight tuning
- [ ] Phase 5 — Unified MLflow registry for all three models
- [ ] Phase 6 — Dashboard (ML-IDS WebSocket + Streamlit analytics)
- [ ] Phase 7 — Auth (JWT/RBAC), Prometheus metrics, OpenTelemetry tracing
