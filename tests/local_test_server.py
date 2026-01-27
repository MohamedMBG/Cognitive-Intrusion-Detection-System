#!/usr/bin/env python3
"""
Minimal local inference server for testing without Docker
Runs in-memory without database dependencies
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import mlflow
import pandas as pd
import numpy as np
from typing import Dict, Optional
import os
import sys

app = FastAPI(title="ML-IDS Test Server")

# Global model
model = None
feature_columns = None

class PredictionRequest(BaseModel):
    class Config:
        extra = "allow"

class PredictionResponse(BaseModel):
    prediction: int
    confidence: float
    attack_type: str
    alert_created: bool = False

ATTACK_LABELS = {
    0: "BENIGN", 1: "DDoS", 2: "PortScan", 3: "Bot", 4: "Infiltration",
    5: "Web Attack - Brute Force", 6: "Web Attack - XSS",
    7: "Web Attack - SQL Injection", 8: "FTP-Patator", 9: "SSH-Patator",
    10: "DoS slowloris", 11: "DoS Slowhttptest", 12: "DoS Hulk",
    13: "DoS GoldenEye", 14: "Heartbleed"
}

def load_model():
    """Load model from MLflow or local pickle"""
    global model, feature_columns
    
    # Try loading from MLflow
    mlflow_uri = os.getenv("MLFLOW_TRACKING_URI")
    model_name = os.getenv("MLFLOW_MODEL_NAME", "models:/ML_IDS_Model_v1/latest")
    
    if mlflow_uri:
        try:
            mlflow.set_tracking_uri(mlflow_uri)
            model = mlflow.sklearn.load_model(model_name)
            print(f"✓ Model loaded from MLflow: {model_name}")
        except Exception as e:
            print(f"✗ MLflow load failed: {e}")
    
    # Fallback: Load feature columns from dataset
    if model is None:
        print("⚠ No model loaded - will return mock predictions")
    
    # Load feature columns from dataset
    try:
        data_df = pd.read_csv('data/CIC-IDS2017/Data.csv', nrows=1)
        feature_columns = data_df.columns.tolist()
        print(f"✓ Loaded {len(feature_columns)} feature columns")
    except Exception as e:
        print(f"✗ Could not load features: {e}")
        feature_columns = []

@app.on_event("startup")
async def startup():
    load_model()

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "model_initialized": model is not None,
        "mode": "local_test"
    }

@app.post("/predict", response_model=PredictionResponse)
def predict(request: PredictionRequest):
    """Make prediction"""
    try:
        # Convert request to dataframe
        data = request.dict()
        
        # Remove non-feature fields
        data.pop('src_ip', None)
        data.pop('dst_ip', None)
        
        if model is not None:
            # Real prediction
            df = pd.DataFrame([data])
            
            # Ensure correct column order
            if feature_columns:
                missing = set(feature_columns) - set(df.columns)
                if missing:
                    for col in missing:
                        df[col] = 0
                df = df[feature_columns]
            
            prediction = int(model.predict(df)[0])
            
            # Get confidence
            if hasattr(model, 'predict_proba'):
                proba = model.predict_proba(df)[0]
                confidence = float(proba[prediction])
            else:
                confidence = 0.95
        else:
            # Mock prediction based on simple heuristics
            flow_duration = data.get('Flow Duration', 0)
            fwd_pkts = data.get('Total Fwd Packet', 0)
            bwd_pkts = data.get('Total Bwd packets', 0)
            
            # Simple heuristic
            if flow_duration > 1000000 or fwd_pkts > 100:
                prediction = 1  # DDoS
            elif bwd_pkts == 0 and fwd_pkts > 5:
                prediction = 2  # PortScan
            elif fwd_pkts > 50:
                prediction = 3  # Bot
            else:
                prediction = 0  # Benign
            
            confidence = 0.85
        
        attack_type = ATTACK_LABELS.get(prediction, f"Unknown-{prediction}")
        alert_created = prediction != 0
        
        return PredictionResponse(
            prediction=prediction,
            confidence=confidence,
            attack_type=attack_type,
            alert_created=alert_created
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/alerts")
def get_alerts():
    """Mock alerts endpoint"""
    return {"alerts": [], "total": 0, "message": "Database not available in test mode"}

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("ML-IDS Local Test Server")
    print("="*60)
    print("Starting server on http://localhost:8000")
    print("Press CTRL+C to stop")
    print("="*60 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
