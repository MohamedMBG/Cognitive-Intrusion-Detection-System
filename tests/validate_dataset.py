#!/usr/bin/env python3
"""
Dataset Validation - Test attack samples without requiring API
"""

import pandas as pd
import json
from collections import Counter

ATTACK_LABELS = {
    0: "BENIGN", 1: "DDoS", 2: "PortScan", 3: "Bot", 4: "Infiltration",
    5: "Web Attack - Brute Force", 6: "Web Attack - XSS", 
    7: "Web Attack - SQL Injection", 8: "FTP-Patator", 9: "SSH-Patator",
    10: "DoS slowloris", 11: "DoS Slowhttptest", 12: "DoS Hulk",
    13: "DoS GoldenEye", 14: "Heartbleed"
}

print("Loading CIC-IDS2017 dataset...")
data_df = pd.read_csv('data/CIC-IDS2017/Data.csv')
label_df = pd.read_csv('data/CIC-IDS2017/Label.csv')
df = pd.concat([data_df, label_df], axis=1)

print(f"\n✓ Loaded {len(df):,} samples")
print(f"✓ Features: {len(data_df.columns)}")

print("\n" + "="*60)
print("ATTACK DISTRIBUTION")
print("="*60)

label_counts = df['Label'].value_counts().sort_index()
for label, count in label_counts.items():
    attack_name = ATTACK_LABELS.get(label, f"Unknown-{label}")
    percentage = count / len(df) * 100
    print(f"{label:2d} | {attack_name:30s} | {count:7,} ({percentage:5.2f}%)")

print("\n" + "="*60)
print("SAMPLE ATTACK PAYLOADS (Ready for API)")
print("="*60)

for attack_label in sorted(df['Label'].unique()):
    if attack_label == 0:
        continue
    
    attack_name = ATTACK_LABELS.get(attack_label, f"Unknown-{attack_label}")
    sample = df[df['Label'] == attack_label].iloc[0]
    
    payload = sample.drop('Label').to_dict()
    payload['src_ip'] = "192.168.1.100"
    payload['dst_ip'] = "10.0.0.50"
    
    print(f"\n{attack_name}:")
    print(f"  Features: {len(payload)} values")
    print(f"  Sample: Flow Duration={payload.get('Flow Duration', 0):.0f}, "
          f"Fwd Packets={payload.get('Total Fwd Packet', 0):.0f}, "
          f"Bwd Packets={payload.get('Total Bwd packets', 0):.0f}")

print("\n" + "="*60)
print("DATASET READY FOR TESTING")
print("="*60)
print("\nTo run attack simulation:")
print("  1. Start ML-IDS: docker compose up -d")
print("  2. Run: python3 tests/simulate_attacks.py")
print("\nOr test specific attack:")
print("  python3 tests/simulate_attacks.py --attack-type 1 --count 5")
