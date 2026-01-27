# Local Attack Simulation Testing (No Docker)

## Quick Start

### Option 1: Automated Test (Recommended)

```bash
cd /home/ecerocg/ML-IDS
./tests/run_local_test.sh --count 3
```

### Option 2: Manual Steps

**Terminal 1 - Start Server:**
```bash
cd /home/ecerocg/ML-IDS
python3 tests/local_test_server.py
```

**Terminal 2 - Run Simulation:**
```bash
cd /home/ecerocg/ML-IDS
python3 tests/simulate_attacks.py --count 5
```

## What Just Happened

✓ **Local test server started** on http://localhost:8000
✓ **Dataset loaded**: 447,915 samples with 9 attack types
✓ **Simulation ran**: Sent real attack features to the API
✓ **Mock predictions**: Server uses heuristics (no trained model loaded)

## Current Limitations

⚠ **No trained model**: The server uses simple heuristics instead of ML predictions
⚠ **No database**: Alerts are not persisted (in-memory only)
⚠ **Mock accuracy**: Predictions won't match real model performance

## Test Results

The simulation successfully:
- ✓ Loaded 447K+ samples from CIC-IDS2017
- ✓ Sent attack payloads to API
- ✓ Received predictions (mock)
- ✓ Validated API connectivity
- ✓ Tested all 9 attack types

## To Get Real Predictions

You need either:

### Option A: Train a Model Locally

```bash
# Run training notebook
cd /home/ecerocg/ML-IDS/notebooks
jupyter notebook model_training.ipynb

# This will create a model and register it with MLflow
```

Then update the server to load it:
```bash
export MLFLOW_TRACKING_URI=http://your-mlflow-server:5000
python3 tests/local_test_server.py
```

### Option B: Use Docker (Full System)

```bash
# Install Docker
sudo apt-get update
sudo apt-get install docker.io docker-compose-v2

# Start full system
docker compose up -d

# Run real test
python3 tests/simulate_attacks.py
```

## Test Commands

**Test specific attack:**
```bash
python3 tests/simulate_attacks.py --attack-type 1 --count 10
```

**High-volume test:**
```bash
python3 tests/simulate_attacks.py --count 50 --delay 0
```

**Verbose output:**
```bash
python3 tests/simulate_attacks.py --attack-type 7 --count 3 --verbose
```

## Validate Dataset Only

If you just want to see what attacks are available:

```bash
python3 tests/validate_dataset.py
```

Output shows:
- Total samples per attack type
- Sample payloads ready for API
- Feature statistics

## Next Steps

1. **For development/testing**: Current setup works for API testing
2. **For real detection**: Train model or use Docker with MLflow
3. **For production**: Deploy with Docker Compose (includes PostgreSQL, MLflow, etc.)

## Troubleshooting

**Port already in use:**
```bash
# Find process
lsof -i :8000

# Kill it
kill <PID>
```

**Server won't start:**
```bash
# Check dependencies
pip install fastapi uvicorn pandas scikit-learn

# Check logs
python3 tests/local_test_server.py
```

**Dataset not found:**
```bash
# Verify files exist
ls -lh data/CIC-IDS2017/*.csv

# Run from project root
cd /home/ecerocg/ML-IDS
```
