#!/usr/bin/env python3
"""
Attack Simulation Script for ML-IDS Testing
Loads real attack samples from CIC-IDS2017 dataset and sends them to the inference server
"""

import pandas as pd
import requests
import json
import time
import argparse
from pathlib import Path
from typing import Dict, List
import sys

# API Configuration
API_BASE_URL = "http://localhost:8000"

# Attack type mapping (based on CIC-IDS2017)
ATTACK_LABELS = {
    0: "BENIGN",
    1: "DDoS",
    2: "PortScan",
    3: "Bot",
    4: "Infiltration",
    5: "Web Attack - Brute Force",
    6: "Web Attack - XSS",
    7: "Web Attack - SQL Injection",
    8: "FTP-Patator",
    9: "SSH-Patator",
    10: "DoS slowloris",
    11: "DoS Slowhttptest",
    12: "DoS Hulk",
    13: "DoS GoldenEye",
    14: "Heartbleed"
}


def load_dataset(data_path: str, label_path: str, sample_size: int = None):
    """Load CIC-IDS2017 dataset"""
    print(f"Loading dataset from {data_path}...")
    
    data_df = pd.read_csv(data_path)
    label_df = pd.read_csv(label_path)
    
    # Combine data and labels
    df = pd.concat([data_df, label_df], axis=1)
    
    if sample_size:
        df = df.sample(n=min(sample_size, len(df)), random_state=42)
    
    print(f"Loaded {len(df)} samples")
    print(f"Attack distribution:\n{df['Label'].value_counts()}")
    
    return df


def get_samples_by_attack_type(df: pd.DataFrame, attack_label: int, count: int = 5):
    """Get specific number of samples for a given attack type"""
    samples = df[df['Label'] == attack_label].head(count)
    return samples


def prepare_prediction_payload(row: pd.Series) -> Dict:
    """Convert dataset row to API payload format"""
    # Get all feature columns (exclude Label)
    features = row.drop('Label').to_dict()
    
    # Add synthetic IP addresses for testing
    features['src_ip'] = f"192.168.1.{100 + (hash(str(row.name)) % 150)}"
    features['dst_ip'] = f"10.0.0.{10 + (hash(str(row.name)) % 240)}"
    
    return features


def send_prediction(payload: Dict, verbose: bool = False) -> Dict:
    """Send prediction request to API"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/predict",
            json=payload,
            timeout=10
        )
        response.raise_for_status()
        result = response.json()
        
        if verbose:
            print(f"  Response: {json.dumps(result, indent=2)}")
        
        return result
    except requests.exceptions.RequestException as e:
        print(f"  ERROR: {e}")
        return None


def check_api_health():
    """Check if API is available"""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        response.raise_for_status()
        health = response.json()
        print(f"API Health: {json.dumps(health, indent=2)}\n")
        return health.get('status') == 'healthy'
    except Exception as e:
        print(f"ERROR: Cannot connect to API at {API_BASE_URL}")
        print(f"Details: {e}")
        return False


def simulate_attack_scenario(df: pd.DataFrame, attack_label: int, count: int, delay: float, verbose: bool):
    """Simulate a specific attack scenario"""
    attack_name = ATTACK_LABELS.get(attack_label, f"Unknown-{attack_label}")
    print(f"\n{'='*60}")
    print(f"Simulating: {attack_name} ({count} samples)")
    print(f"{'='*60}")
    
    samples = get_samples_by_attack_type(df, attack_label, count)
    
    if len(samples) == 0:
        print(f"  WARNING: No samples found for attack type {attack_label}")
        return
    
    results = {
        'total': len(samples),
        'success': 0,
        'failed': 0,
        'predictions': []
    }
    
    for idx, (_, row) in enumerate(samples.iterrows(), 1):
        print(f"\n[{idx}/{len(samples)}] Sending {attack_name} sample...")
        
        payload = prepare_prediction_payload(row)
        result = send_prediction(payload, verbose)
        
        if result:
            results['success'] += 1
            results['predictions'].append(result)
            
            predicted_label = result.get('prediction')
            predicted_name = ATTACK_LABELS.get(predicted_label, f"Unknown-{predicted_label}")
            confidence = result.get('confidence', 0)
            
            match = "✓" if predicted_label == attack_label else "✗"
            print(f"  {match} Predicted: {predicted_name} (confidence: {confidence:.2%})")
            
            if result.get('alert_created'):
                print(f"  🚨 Alert created: ID={result.get('alert_id')}")
        else:
            results['failed'] += 1
        
        if delay > 0 and idx < len(samples):
            time.sleep(delay)
    
    # Summary
    print(f"\n{'-'*60}")
    print(f"Summary for {attack_name}:")
    print(f"  Total: {results['total']}")
    print(f"  Success: {results['success']}")
    print(f"  Failed: {results['failed']}")
    
    if results['predictions']:
        correct = sum(1 for p in results['predictions'] if p.get('prediction') == attack_label)
        accuracy = correct / len(results['predictions']) * 100
        print(f"  Accuracy: {accuracy:.1f}% ({correct}/{len(results['predictions'])})")
    
    return results


def run_full_test_suite(df: pd.DataFrame, samples_per_attack: int, delay: float, verbose: bool):
    """Run comprehensive test with multiple attack types"""
    print("\n" + "="*60)
    print("FULL ATTACK SIMULATION TEST SUITE")
    print("="*60)
    
    # Get available attack types in dataset
    available_attacks = df['Label'].unique()
    print(f"\nAvailable attack types in dataset: {sorted(available_attacks)}")
    
    all_results = {}
    
    for attack_label in sorted(available_attacks):
        if attack_label == 0:  # Skip benign for now
            continue
        
        results = simulate_attack_scenario(df, attack_label, samples_per_attack, delay, verbose)
        all_results[attack_label] = results
    
    # Overall summary
    print("\n" + "="*60)
    print("OVERALL TEST SUMMARY")
    print("="*60)
    
    total_samples = sum(r['total'] for r in all_results.values())
    total_success = sum(r['success'] for r in all_results.values())
    total_failed = sum(r['failed'] for r in all_results.values())
    
    print(f"Total samples tested: {total_samples}")
    print(f"Successful predictions: {total_success}")
    print(f"Failed requests: {total_failed}")
    
    print("\nPer-attack accuracy:")
    for attack_label, results in all_results.items():
        attack_name = ATTACK_LABELS.get(attack_label, f"Unknown-{attack_label}")
        if results['predictions']:
            correct = sum(1 for p in results['predictions'] if p.get('prediction') == attack_label)
            accuracy = correct / len(results['predictions']) * 100
            print(f"  {attack_name:30s}: {accuracy:5.1f}% ({correct}/{len(results['predictions'])})")


def main():
    parser = argparse.ArgumentParser(description="Simulate attacks using CIC-IDS2017 dataset")
    parser.add_argument(
        '--data',
        default='data/CIC-IDS2017/Data.csv',
        help='Path to Data.csv'
    )
    parser.add_argument(
        '--labels',
        default='data/CIC-IDS2017/Label.csv',
        help='Path to Label.csv'
    )
    parser.add_argument(
        '--attack-type',
        type=int,
        help='Specific attack type to simulate (0-14). If not specified, runs all attacks.'
    )
    parser.add_argument(
        '--count',
        type=int,
        default=5,
        help='Number of samples per attack type (default: 5)'
    )
    parser.add_argument(
        '--delay',
        type=float,
        default=0.5,
        help='Delay between requests in seconds (default: 0.5)'
    )
    parser.add_argument(
        '--sample-size',
        type=int,
        help='Limit dataset size for faster loading'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed API responses'
    )
    parser.add_argument(
        '--api-url',
        default='http://localhost:8000',
        help='API base URL (default: http://localhost:8000)'
    )
    
    args = parser.parse_args()
    
    global API_BASE_URL
    API_BASE_URL = args.api_url
    
    # Check API health
    if not check_api_health():
        print("\nPlease ensure the ML-IDS inference server is running:")
        print("  docker-compose up -d")
        sys.exit(1)
    
    # Load dataset
    df = load_dataset(args.data, args.labels, args.sample_size)
    
    # Run simulation
    if args.attack_type is not None:
        simulate_attack_scenario(df, args.attack_type, args.count, args.delay, args.verbose)
    else:
        run_full_test_suite(df, args.count, args.delay, args.verbose)
    
    print("\n✓ Simulation complete!")
    print(f"\nView results:")
    print(f"  Dashboard: {API_BASE_URL}/dashboard")
    print(f"  Recent alerts: curl {API_BASE_URL}/api/alerts?limit=20")


if __name__ == "__main__":
    main()
