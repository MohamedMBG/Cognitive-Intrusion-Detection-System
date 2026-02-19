#!/usr/bin/env python3
"""Retrain the Random Forest with 76 flow + 10 payload features (86 total).

Usage:
    python scripts/retrain_with_payload.py \
        --dataset /path/to/labeled_flows.csv \
        --output models/rf_model_v2.joblib

The CSV must contain:
  - The 76 CICFlowMeter columns (matching FLOW_FEATURE_NAMES order)
  - 10 payload columns (matching PAYLOAD_FEATURE_NAMES order)
  - A 'Label' column with attack type strings ('BENIGN' for normal)

If payload columns are missing, they are zero-filled so you can still
run this on the original CIC-IDS2017 dataset to produce a baseline.
"""

import argparse
import sys
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.features.flow_extractor import FLOW_FEATURE_NAMES
from src.features.payload_analyzer import PAYLOAD_FEATURE_NAMES
from src.engines.supervised import EXTENDED_FEATURE_NAMES


def main():
    parser = argparse.ArgumentParser(description="Retrain RF with payload features")
    parser.add_argument("--dataset", required=True, help="Path to labeled CSV")
    parser.add_argument("--output", default="models/rf_model_v2.joblib")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()

    print(f"Loading dataset: {args.dataset}")
    df = pd.read_csv(args.dataset)
    df.columns = df.columns.str.strip()

    # Zero-fill missing payload columns
    for col in PAYLOAD_FEATURE_NAMES:
        if col not in df.columns:
            print(f"  Column '{col}' not found — zero-filling")
            df[col] = 0.0

    feature_cols = EXTENDED_FEATURE_NAMES
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        print(f"ERROR: Missing required columns: {missing}", file=sys.stderr)
        sys.exit(1)

    X = df[feature_cols].values.astype(np.float32)
    y = df["Label"].values

    # Replace inf/nan
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    print(f"Features: {X.shape[1]}, Samples: {X.shape[0]}")
    print(f"Classes: {np.unique(y)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.random_state, stratify=y,
    )

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(
            n_estimators=args.n_estimators,
            random_state=args.random_state,
            n_jobs=-1,
        )),
    ])

    print("Training...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    print("\n" + classification_report(y_test, y_pred))

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    joblib.dump(pipeline, args.output)
    print(f"Model saved: {args.output} (n_features_in_={pipeline.n_features_in_})")


if __name__ == "__main__":
    main()
