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
   └─ PayloadAnalyzer → regex pattern matches + 10 numeric payload features
        │
        ├─► [Supervised Engine]     Random Forest (76 flow + 10 payload features)
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
| **Supervised** | 76 CICFlowMeter flow features (+ 10 payload features if retrained) | Random Forest (sklearn Pipeline) | Named attacks: DoS, PortScan, Brute-force, Web attacks, Infiltration |
| **Isolation Forest** | 18 per-IP host features | IsolationForest + StandardScaler | Novel / zero-day volumetric anomalies |
| **LSTM Autoencoder** | 18-feature time-series per IP | PyTorch sequence AE | Slow attacks, temporal behaviour drift |
| **Rules** | Flow metadata + payload bytes | Threshold rules | ICMP floods, SYN scans, SQLi, XSS, LFI, large payloads, asymmetric upload |

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

# Specify network interface
sudo venv/bin/python main.py --iface eth0

# Capture + REST API on :8000
sudo venv/bin/python main.py --api

# API only — no live capture (useful for testing)
uvicorn src.api.main:app --host 0.0.0.0 --port 8000

# Stop automatically after N seconds
sudo venv/bin/python main.py --duration 60

# Docker Compose (API + detector + Streamlit dashboard)
docker-compose up -d
# API:       http://localhost:8000
# Dashboard: http://localhost:8501
```

---

## REST API

Base URL: `http://localhost:8000`

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Engine availability + capture stats |
| `/api/predict` | POST | Run all engines on supplied features |
| `/api/alerts` | GET | List alerts (filter: `severity`, `src_ip`, `acknowledged`) |
| `/api/alerts/{alert_id}` | GET | Get single alert by ID |
| `/api/alerts/{alert_id}` | PATCH | Acknowledge alert, add notes, link to incident |
| `/api/incidents` | GET / POST | Incident management |
| `/api/stats` | GET | Alert counts grouped by severity |
| `/api/suppression-rules` | GET / POST | List or create alert suppression rules |
| `/api/suppression-rules/{rule_id}` | DELETE | Remove a suppression rule |
| `/api/adaptive-weights` | GET | Compute adaptive engine weights from feedback |
| `/api/dns-log` | GET | DNS query logs (filter: `src_ip`) |
| `/api/alerts/trends` | GET | Alert counts bucketed by hour/day (filter: `hours`, `bucket`) |
| `/api/auth/token` | POST | Issue JWT token (when `JWT_SECRET` is set) |
| `/ws/alerts` | WebSocket | Real-time alert stream |
| `/metrics` | GET | Prometheus metrics (when `PROMETHEUS_ENABLED=true`) |
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
| `PACKET_QUEUE_SIZE` | `20000` | Internal packet queue size |
| `FLOW_TIMEOUT` | `120` | Seconds before idle flow is flushed |
| `MAX_ACTIVE_FLOWS` | `50000` | Max simultaneous tracked flows |
| `ACTIVE_IDLE_THRESH` | `1.0` | Seconds of inactivity to mark a flow idle |
| `HOST_WINDOW_SIZE` | `100` | Packet history window per IP for host features |
| `MAX_TRACKED_IPS` | `5000` | Max IPs tracked by host extractor / LSTM buffers |
| `MIN_PACKETS_FOR_ML` | `10` | Min packets before ML engines activate |
| `ENSEMBLE_THRESHOLD` | `0.55` | Score above which an alert fires |
| `WEIGHT_SUPERVISED` | `0.40` | Supervised engine weight |
| `WEIGHT_IFOREST` | `0.30` | Isolation Forest weight |
| `WEIGHT_LSTM` | `0.20` | LSTM weight |
| `WEIGHT_RULES` | `0.10` | Rules weight |
| `LARGE_PAYLOAD_BYTES` | `10000` | Forward payload size (bytes) that triggers the large-payload rule |
| `MAX_PAYLOAD_SAMPLES` | `50` | Max payload samples stored per flow for feature extraction |
| `PAYLOAD_SAMPLE_BYTES` | `4096` | Max bytes kept per payload sample |
| `RATE_SPIKE_MULTIPLIER` | `2.0` | Multiplier for rate-spike rule detection |
| `ICMP_FLOOD_THRESHOLD` | `50` | ICMP packet count that triggers flood rule |
| `PORT_SCAN_THRESHOLD` | `20` | SYN count threshold for scan detection |
| `ALERT_COOLDOWN_SECS` | `60` | Seconds before a duplicate alert can fire again |
| `DEDUP_WINDOW_SECS` | `300` | Alert deduplication window (seconds) |
| `MODELS_DIR` | `models` | Directory containing model files |
| `RF_MODEL_FILE` | `rf_model.joblib` | Random Forest model filename |
| `IF_MODEL_FILE` | `isolation_forest.joblib` | Isolation Forest model filename |
| `IF_SCALER_FILE` | `if_scaler.joblib` | IF scaler filename |
| `LSTM_MODEL_FILE` | `lstm_autoencoder.pt` | LSTM model filename |
| `LSTM_CONFIG_FILE` | `lstm_config.json` | LSTM config filename |
| `DATABASE_URL` | `sqlite+aiosqlite:///./cnds.db` | SQLite or PostgreSQL URL |
| `API_HOST` | `0.0.0.0` | API bind address |
| `API_PORT` | `8000` | API listen port |
| `API_KEY` | _(empty)_ | Bearer token; leave empty to disable auth |
| `CORS_ORIGINS` | _(empty)_ | Comma-separated allowed origins; defaults to `http://localhost:3000` |
| `ATTACK_TYPE_WEIGHTS` | `{}` | JSON: per-attack-type engine weight overrides |
| `CALIBRATION_TEMPERATURE` | `1.0` | Platt scaling temperature (>1 softer, <1 sharper) |
| `MLFLOW_TRACKING_URI` | _(empty)_ | MLflow server URL; empty disables MLflow |
| `MLFLOW_REGISTRY_NAME` | `cnds` | MLflow model registry name |
| `JWT_SECRET` | _(empty)_ | JWT signing secret; empty disables JWT auth |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `JWT_EXPIRE_MINUTES` | `60` | JWT token expiry (minutes) |
| `PROMETHEUS_ENABLED` | `false` | Enable Prometheus metrics at `/metrics` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | _(empty)_ | OpenTelemetry OTLP endpoint |
| `GEOIP_DB_PATH` | _(empty)_ | Path to GeoLite2-City.mmdb; empty disables GeoIP |
| `CORRELATION_WINDOW_SECS` | `300` | Time window for alert correlation (seconds) |
| `CORRELATION_THRESHOLD` | `5` | Alerts from same IP before auto-incident creation |
| `ADAPTIVE_WEIGHTS_ENABLED` | `false` | Enable adaptive engine weight computation |
| `ADAPTIVE_MIN_SAMPLES` | `100` | Min acknowledged alerts before adapting weights |
| `WEBHOOK_URLS` | _(empty)_ | Comma-separated webhook/Slack notification URLs |
| `NOTIFY_MIN_SEVERITY` | `high` | Minimum severity to trigger webhook notification |
| `TELEGRAM_BOT_TOKEN` | _(empty)_ | Telegram bot token from @BotFather; empty disables |
| `TELEGRAM_CHAT_ID` | _(empty)_ | Telegram chat/group ID to send alerts to |
| `RATE_LIMIT_REQUESTS` | `60` | Max API requests per window per IP |
| `RATE_LIMIT_WINDOW` | `60` | Rate limit window (seconds) |
| `DNS_LOGGING_ENABLED` | `false` | Enable DNS query logging from captured traffic |
| `CONFIDENCE_DECAY_FACTOR` | `0.9` | Score multiplier per repeat alert from same IP |
| `CONFIDENCE_DECAY_WINDOW` | `300` | Seconds to track repeat alerts for decay |
| `IP_ALLOWLIST` | _(empty)_ | Comma-separated IPs to skip detection entirely |
| `IP_BLOCKLIST` | _(empty)_ | Comma-separated IPs to auto-flag as critical |

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
├── scripts/
│   └── retrain_with_payload.py  # Retrain RF with 86 features (76 flow + 10 payload)
├── dashboard/
│   └── app.py                   # Streamlit real-time dashboard
├── models/                      # ML model files (binaries not committed)
│   ├── rf_model.joblib          # Random Forest pipeline (76 features)
│   ├── isolation_forest.joblib  # Isolation Forest
│   ├── if_scaler.joblib         # StandardScaler for IF
│   ├── lstm_autoencoder.pt      # LSTM Autoencoder weights
│   └── lstm_config.json         # LSTM architecture config (tracked)
├── src/
│   ├── config.py                # All settings (env-var driven)
│   ├── mlflow_registry.py       # Unified MLflow model registry
│   ├── capture/
│   │   ├── packet_capture.py    # Scapy capture + async worker queue
│   │   └── dispatcher.py        # Fan-out to feature pipelines on flow expiry
│   ├── features/
│   │   ├── flow_extractor.py    # 76 CICFlowMeter-compatible features per flow
│   │   ├── host_extractor.py    # 18 per-IP host features
│   │   └── payload_analyzer.py  # Regex pattern matching + numeric payload features
│   ├── engines/
│   │   ├── registry.py          # Shared engine singletons
│   │   ├── supervised.py        # Random Forest wrapper
│   │   ├── isolation_forest.py  # Isolation Forest wrapper
│   │   ├── lstm_autoencoder.py  # LSTM Autoencoder wrapper
│   │   └── rules.py             # Rule-based engine
│   ├── ensemble/
│   │   └── scorer.py            # Weighted confidence fusion → EnsembleResult
│   ├── enrichment/
│   │   ├── geoip.py             # GeoIP enrichment (MaxMind)
│   │   ├── correlation.py       # Auto-group alerts into incidents
│   │   ├── adaptive_weights.py  # Feedback-driven engine weight tuning
│   │   ├── suppression.py       # Temporary alert suppression rules
│   │   ├── notifications.py     # Webhook/Slack alert notifications
│   │   └── dns_logger.py        # DNS query logging from captured traffic
│   └── api/
│       ├── main.py              # FastAPI application
│       ├── models.py            # SQLAlchemy ORM (Alert, Incident)
│       ├── schemas.py           # Pydantic request/response schemas
│       ├── database.py          # Async SQLAlchemy session setup
│       ├── auth.py              # JWT authentication and RBAC
│       ├── metrics.py           # Prometheus metrics + OpenTelemetry
│       ├── rate_limit.py        # Per-IP rate limiting middleware
│       └── routers/
│           ├── predict.py       # POST /api/predict
│           ├── alerts.py        # Alert + incident CRUD
│           ├── auth.py          # POST /api/auth/token
│           └── websocket.py     # WebSocket /ws/alerts
└── tests/
    ├── test_flow_extractor.py
    ├── test_host_extractor.py
    ├── test_payload_features.py
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

### v1.0 (complete)

- [x] Phase 1 — Shared capture layer (single Scapy loop → dual feature extraction)
- [x] Phase 2 — All four engines + ensemble scoring + FastAPI orchestration
- [x] Phase 3 — Payload pattern features fed into supervised feature set
- [x] Phase 4 — Confidence calibration and per-attack-type weight tuning
- [x] Phase 5 — Unified MLflow registry for all three models
- [x] Phase 6 — Real-time dashboard (WebSocket + Streamlit analytics)
- [x] Phase 7 — Auth (JWT/RBAC), Prometheus metrics, OpenTelemetry tracing
- [x] Phase 8 — GeoIP enrichment, alert correlation, adaptive weights, suppression rules, webhook/Telegram notifications, rate limiting, DNS logging
- [x] Phase 9 — Confidence decay, IP allowlist/blocklist, alert trends endpoint, capture stats in /health

### v2.0 (planned)

- [x] PCAP replay mode — offline ingestion of `.pcap` files for threat hunting and model evaluation
- [ ] Alembic DB migrations — proper schema versioning for production deployments
- [x] Config validation — fail-fast on startup if weights don't sum to 1.0 or thresholds are out of range
- [x] API integration tests — end-to-end endpoint testing with in-memory SQLite
- [x] RBAC enforcement — wire `require_role()` to sensitive endpoints (suppression rules, incidents)
- [x] Alert export — CSV/JSON bulk export endpoint for analyst reporting
- [x] Dashboard enhancements — top talkers view, attack type breakdown, timeline visualization
- [ ] Model drift detection — alert when live traffic feature distributions diverge from training data
- [ ] Feedback-driven retraining — analyst TP/FP labels → accumulated dataset → automated retraining via MLflow
- [ ] ONNX Runtime for LSTM — 2-5x inference speedup over raw PyTorch
