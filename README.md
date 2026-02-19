# Cognitive Network Defense System

**CNDS** is a real-time network intrusion detection system that fuses four detection engines — supervised ML, unsupervised anomaly detection, temporal sequence modeling, and rule-based heuristics — into a single weighted ensemble. A Scapy capture loop feeds packets into parallel feature pipelines; alerts are exposed over a FastAPI REST interface backed by SQLite (or PostgreSQL).

---

## Architecture

```
[Network Interface]
        │  Scapy packet capture
        ▼
[PacketProcessor]  ── async queue ──►  Worker threads (×4)
        │
        ▼
[Dispatcher]  ── flow expiry ──►  on_flow_complete()
   ├─ FlowExtractor   → 76 CICFlowMeter flow features
   ├─ HostExtractor   → 18 per-IP host features
   └─ PayloadAnalyzer → regex pattern matches
        │
        ├─► [Supervised Engine]     Random Forest (76 flow features)
        ├─► [Isolation Forest]      Novelty score  (18 host features)
        ├─► [LSTM Autoencoder]      Sequence score (18 host features)
        └─► [Rules Engine]          Threshold + pattern rules
                │
                ▼
        [Ensemble Scorer]
         weighted confidence fusion
                │
        ┌───────┴────────┐
        │   Alert fired  │  → logger + SQLite  →  FastAPI
        └────────────────┘
```

### Detection Engines

| Engine | Input | Model | Detects |
|---|---|---|---|
| **Supervised** | 76 CICFlowMeter flow features | Random Forest (sklearn Pipeline) | Named attacks: DoS, PortScan, Brute-force, Web attacks, Infiltration |
| **Isolation Forest** | 18 per-IP host features | IsolationForest + StandardScaler | Novel / zero-day volumetric anomalies |
| **LSTM Autoencoder** | 18-feature time-series per IP | PyTorch sequence AE | Slow attacks, temporal behaviour drift |
| **Rules** | Flow metadata + payload bytes | Threshold rules | ICMP floods, port scans, SQLi, XSS, LFI, large payloads |

Default ensemble weights: Supervised 40 %, Isolation Forest 30 %, LSTM 20 %, Rules 10 %.
Any missing engine has its weight redistributed proportionally across the active engines.

---

## Quick Start

### 1. Install

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### 2. Add models

Copy trained model files to `models/` (binary files are excluded from git):

```bash
# Supervised engine — Random Forest Pipeline (76 features)
cp /path/to/rf_model.joblib               models/

# Isolation Forest + scaler
cp /path/to/isolation_forest.joblib       models/
cp /path/to/if_scaler.joblib              models/

# LSTM Autoencoder
cp /path/to/lstm_autoencoder.pt           models/
cp /path/to/lstm_config.json              models/   # tracked in git
```

CNDS works with any subset of models — missing engines are gracefully skipped.

### 3. Run

```bash
# Packet capture + detection (requires root for raw sockets)
sudo venv/bin/python main.py

# Capture + REST API on :8000
sudo venv/bin/python main.py --api

# API only — no live capture (useful for testing)
uvicorn src.api.main:app --host 0.0.0.0 --port 8000

# Stop automatically after N seconds
sudo venv/bin/python main.py --duration 60

# Docker Compose (API + SQLite volume)
docker-compose up -d
```

---

## REST API

Base URL: `http://localhost:8000`

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Engine availability + capture stats |
| `/api/predict` | POST | Run all engines on supplied features |
| `/api/alerts` | GET | List alerts (filter: `severity`, `src_ip`, `acknowledged`) |
| `/api/alerts/{id}` | PATCH | Acknowledge alert, add notes, link to incident |
| `/api/incidents` | GET / POST | Incident management |
| `/api/stats` | GET | Alert counts grouped by severity |
| `/docs` | GET | Swagger UI (auto-generated) |

### Example: manual prediction

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

### Example: list high-severity alerts

```bash
curl "http://localhost:8000/api/alerts?severity=high&limit=20"
```

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# With coverage report
pytest tests/ --cov=src --cov-report=term-missing

# Single module
pytest tests/test_flow_extractor.py -v
```

---

## Configuration

Copy `.env.example` to `.env` and adjust as needed.

| Variable | Default | Description |
|---|---|---|
| `CAPTURE_INTERFACE` | auto | Network interface (e.g. `eth0`) |
| `PACKET_WORKERS` | `4` | Async worker threads |
| `FLOW_TIMEOUT` | `120` | Seconds before idle flow is flushed |
| `MAX_ACTIVE_FLOWS` | `50000` | Max simultaneous tracked flows |
| `MIN_PACKETS_FOR_ML` | `10` | Min packets before ML engines activate |
| `ENSEMBLE_THRESHOLD` | `0.55` | Score above which an alert fires |
| `WEIGHT_SUPERVISED` | `0.40` | Supervised engine weight |
| `WEIGHT_IFOREST` | `0.30` | Isolation Forest weight |
| `WEIGHT_LSTM` | `0.20` | LSTM weight |
| `WEIGHT_RULES` | `0.10` | Rules weight |
| `LARGE_PAYLOAD_BYTES` | `10000` | Forward payload size (bytes) that triggers the large-payload rule |
| `DATABASE_URL` | `sqlite+aiosqlite:///./cnds.db` | SQLite or PostgreSQL URL |
| `API_KEY` | _(empty)_ | Bearer token; leave empty to disable auth |
| `CORS_ORIGINS` | _(empty)_ | Comma-separated allowed origins; defaults to `http://localhost:3000` |

---

## Project Structure

```
├── main.py                      # Entry point: capture + detection pipeline
├── docker-compose.yml
├── Dockerfile
├── Jenkinsfile                  # CI/CD: build → lint → test → SonarQube → push
├── sonar-project.properties
├── requirements.txt
├── .env.example
├── models/                      # ML model files (binaries not committed)
│   ├── rf_model.joblib          # Random Forest pipeline (76 features)
│   ├── isolation_forest.joblib  # Isolation Forest
│   ├── if_scaler.joblib         # StandardScaler for IF
│   ├── lstm_autoencoder.pt      # LSTM Autoencoder weights
│   └── lstm_config.json         # LSTM architecture config (tracked)
├── src/
│   ├── config.py                # All settings (env-var driven)
│   ├── capture/
│   │   ├── packet_capture.py    # Scapy capture + async worker queue
│   │   └── dispatcher.py        # Fan-out to feature pipelines on flow expiry
│   ├── features/
│   │   ├── flow_extractor.py    # 76 CICFlowMeter-compatible features per flow
│   │   ├── host_extractor.py    # 18 per-IP host features
│   │   └── payload_analyzer.py  # Regex pattern matching (SQLi, XSS, LFI, …)
│   ├── engines/
│   │   ├── registry.py          # Shared engine singletons
│   │   ├── supervised.py        # Random Forest wrapper
│   │   ├── isolation_forest.py  # Isolation Forest wrapper
│   │   ├── lstm_autoencoder.py  # LSTM Autoencoder wrapper
│   │   └── rules.py             # Rule-based engine
│   ├── ensemble/
│   │   └── scorer.py            # Weighted confidence fusion → EnsembleResult
│   └── api/
│       ├── main.py              # FastAPI application
│       ├── models.py            # SQLAlchemy ORM (Alert, Incident)
│       ├── schemas.py           # Pydantic request/response schemas
│       ├── database.py          # Async SQLAlchemy session setup
│       └── routers/
│           ├── predict.py       # POST /api/predict
│           └── alerts.py        # Alert + incident CRUD
└── tests/
    ├── test_flow_extractor.py
    ├── test_host_extractor.py
    ├── test_rules_engine.py
    └── test_ensemble.py
```

---

## CI/CD Pipeline

Jenkins pipeline stages (see `Jenkinsfile`):

1. **Checkout** — pull from Gitea
2. **Build Image** — `docker build` tagged with build number and `latest`
3. **Code Quality** (parallel)
   - *Lint* — flake8 (max line length 120)
   - *Security* — Safety dependency audit
4. **Run Tests** — pytest with JUnit XML + coverage report
5. **SonarQube Analysis** — static analysis pushed to SonarQube (`cnds` project)
6. **Push to Registry** — push to private Docker registry at `192.168.1.86:5000`

---

## Roadmap

- [x] Phase 1 — Shared capture layer (single Scapy loop → dual feature extraction)
- [x] Phase 2 — All four engines + ensemble scoring + FastAPI orchestration
- [ ] Phase 3 — Payload pattern features fed into supervised feature set
- [ ] Phase 4 — Confidence calibration and per-attack-type weight tuning
- [ ] Phase 5 — Unified MLflow registry for all three models
- [ ] Phase 6 — Real-time dashboard (WebSocket + Streamlit analytics)
- [ ] Phase 7 — Auth (JWT/RBAC), Prometheus metrics, OpenTelemetry tracing
