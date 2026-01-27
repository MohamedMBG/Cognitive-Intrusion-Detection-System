# Attack Simulation Testing Guide

## Overview

The `simulate_attacks.py` script tests the ML-IDS detector using real attack samples from the CIC-IDS2017 dataset. It sends actual network flow features to the inference server and validates detection accuracy.

## Prerequisites

1. **Start the ML-IDS system:**
   ```bash
   docker-compose up -d
   ```

2. **Verify system is healthy:**
   ```bash
   curl http://localhost:8000/health
   ```

3. **Install dependencies (if running outside Docker):**
   ```bash
   pip install pandas requests
   ```

## Usage Examples

### 1. Run Full Test Suite (All Attack Types)

Tests all available attack types with 5 samples each:

```bash
python tests/simulate_attacks.py
```

### 2. Test Specific Attack Type

Test only DDoS attacks (label 1):

```bash
python tests/simulate_attacks.py --attack-type 1 --count 10
```

### 3. High-Volume Test

Test with more samples and no delay:

```bash
python tests/simulate_attacks.py --count 20 --delay 0
```

### 4. Verbose Mode

See detailed API responses:

```bash
python tests/simulate_attacks.py --attack-type 2 --count 3 --verbose
```

### 5. Test Against Remote Server

```bash
python tests/simulate_attacks.py --api-url http://your-server:8000
```

### 6. Quick Test with Limited Dataset

Load only 10,000 samples for faster testing:

```bash
python tests/simulate_attacks.py --sample-size 10000 --count 3
```

## Attack Type Labels

| Label | Attack Type |
|-------|-------------|
| 0 | BENIGN |
| 1 | DDoS |
| 2 | PortScan |
| 3 | Bot |
| 4 | Infiltration |
| 5 | Web Attack - Brute Force |
| 6 | Web Attack - XSS |
| 7 | Web Attack - SQL Injection |
| 8 | FTP-Patator |
| 9 | SSH-Patator |
| 10 | DoS slowloris |
| 11 | DoS Slowhttptest |
| 12 | DoS Hulk |
| 13 | DoS GoldenEye |
| 14 | Heartbleed |

## Command-Line Options

```
--data PATH              Path to Data.csv (default: data/CIC-IDS2017/Data.csv)
--labels PATH            Path to Label.csv (default: data/CIC-IDS2017/Label.csv)
--attack-type INT        Specific attack type 0-14 (default: test all)
--count INT              Samples per attack type (default: 5)
--delay FLOAT            Delay between requests in seconds (default: 0.5)
--sample-size INT        Limit dataset size for faster loading
--verbose                Show detailed API responses
--api-url URL            API base URL (default: http://localhost:8000)
```

## Expected Output

```
API Health: {
  "status": "healthy",
  "model_initialized": true,
  ...
}

Loading dataset from data/CIC-IDS2017/Data.csv...
Loaded 50000 samples
Attack distribution:
4    15234
7    12456
1    10234
...

============================================================
Simulating: DDoS (5 samples)
============================================================

[1/5] Sending DDoS sample...
  ✓ Predicted: DDoS (confidence: 98.45%)
  🚨 Alert created: ID=123

[2/5] Sending DDoS sample...
  ✓ Predicted: DDoS (confidence: 99.12%)
  🚨 Alert created: ID=124

...

------------------------------------------------------------
Summary for DDoS:
  Total: 5
  Success: 5
  Failed: 0
  Accuracy: 100.0% (5/5)
```

## Monitoring Results

### 1. Real-time Dashboard

Open browser to: http://localhost:8000/dashboard

Watch alerts appear in real-time as attacks are simulated.

### 2. API Queries

**Recent alerts:**
```bash
curl http://localhost:8000/api/alerts?limit=20 | jq
```

**Alerts by severity:**
```bash
curl "http://localhost:8000/api/alerts?severity=critical&limit=10" | jq
```

**Dashboard statistics:**
```bash
curl http://localhost:8000/api/dashboard/stats | jq
```

**Top attackers:**
```bash
curl http://localhost:8000/api/dashboard/top-attackers | jq
```

### 3. Database Queries

```bash
docker-compose exec postgres psql -U mlids -d mlids -c "
  SELECT attack_type, severity, COUNT(*) 
  FROM alerts 
  WHERE created_at > NOW() - INTERVAL '1 hour'
  GROUP BY attack_type, severity 
  ORDER BY COUNT(*) DESC;
"
```

## Troubleshooting

### API Connection Error

```
ERROR: Cannot connect to API at http://localhost:8000
```

**Solution:** Start the services:
```bash
docker-compose up -d
docker-compose logs -f ml-ids
```

### Dataset Not Found

```
FileNotFoundError: data/CIC-IDS2017/Data.csv
```

**Solution:** Run from project root or specify full path:
```bash
cd /home/ecerocg/ML-IDS
python tests/simulate_attacks.py
```

### No Samples for Attack Type

```
WARNING: No samples found for attack type 14
```

**Solution:** The dataset may not contain all attack types. Check available types:
```bash
python -c "import pandas as pd; print(pd.read_csv('data/CIC-IDS2017/Label.csv')['Label'].value_counts())"
```

### Low Detection Accuracy

If accuracy is below 80%, check:
1. Model is properly loaded: `curl http://localhost:8000/health`
2. Feature names match training data
3. MLflow model version is correct

## Performance Testing

### Stress Test

Send 100 attacks with no delay:

```bash
python tests/simulate_attacks.py --count 100 --delay 0 --attack-type 1
```

Monitor system resources:
```bash
docker stats ml-ids
```

### Latency Test

Measure prediction latency:

```bash
time python tests/simulate_attacks.py --count 1 --attack-type 1
```

## Next Steps

After successful simulation:

1. **Review alerts in dashboard:** http://localhost:8000/dashboard
2. **Check notification delivery** (if configured)
3. **Analyze false positives/negatives**
4. **Tune alert severity thresholds**
5. **Test incident management workflow**
6. **Export results for reporting**

## Advanced: Custom Attack Scenarios

Create custom test scenarios by modifying the script:

```python
# Example: Simulate coordinated attack from single IP
def simulate_coordinated_attack():
    samples = df[df['Label'].isin([1, 2, 8])].head(20)  # DDoS + PortScan + FTP
    for _, row in samples.iterrows():
        payload = prepare_prediction_payload(row)
        payload['src_ip'] = "192.168.1.100"  # Same source
        send_prediction(payload)
        time.sleep(0.1)
```

## Validation Checklist

- [ ] All attack types detected with >80% accuracy
- [ ] Alerts created in database
- [ ] Dashboard shows real-time updates
- [ ] Notifications sent (if configured)
- [ ] No API errors or timeouts
- [ ] System handles load without degradation
- [ ] False positive rate is acceptable
