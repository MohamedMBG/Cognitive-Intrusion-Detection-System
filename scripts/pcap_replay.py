#!/usr/bin/env python3
"""PCAP replay and model evaluation pipeline.

Reads .pcap files, runs them through the detection pipeline, and computes
evaluation metrics against optional ground-truth labels.

Usage:
    python scripts/pcap_replay.py data/test.pcap --labels data/labels.csv --output results.json
    python scripts/pcap_replay.py data/*.pcap --output batch_results.json
"""

import argparse
import csv
import json
import logging
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
from scapy.all import PcapReader, IP

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.features.flow_extractor import FlowExtractor
from src.features.host_extractor import HostExtractor
from src.features.payload_analyzer import analyze_payload, extract_payload_features
from src.engines.registry import supervised, iforest, lstm, rules, ensemble
from src.ensemble.scorer import EngineScores

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class EvalResult:
    """Stores predictions and metrics for evaluation."""
    predictions: List[dict] = field(default_factory=list)
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / max(self.tp + self.fp, 1)

    @property
    def recall(self) -> float:
        return self.tp / max(self.tp + self.fn, 1)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / max(p + r, 1e-9)

    @property
    def accuracy(self) -> float:
        total = self.tp + self.tn + self.fp + self.fn
        return (self.tp + self.tn) / max(total, 1)

    def to_dict(self) -> dict:
        return {
            "total_flows": len(self.predictions),
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
        }


def load_labels(path: str) -> Dict[str, str]:
    """Load ground-truth labels from CSV: flow_key -> label."""
    labels = {}
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Expected columns: src_ip,dst_ip,src_port,dst_port,protocol,label
            key = f"{row['src_ip']}-{row['dst_ip']}-{row['src_port']}-{row['dst_port']}-{row['protocol']}"
            labels[key] = row["label"]
    logger.info("Loaded %d labels from %s", len(labels), path)
    return labels


def flow_key_str(record) -> str:
    src, dst, sp, dp, proto = record.key
    return f"{src}-{dst}-{sp}-{dp}-{proto}"


def run_detection(record, flow_vec, host_vec, payload_matches) -> dict:
    """Run all engines on a single flow and return prediction dict."""
    scores = EngineScores()

    # Supervised
    if flow_vec is not None and supervised.is_available:
        result = supervised.predict(flow_vec)
        if result:
            label, conf = result
            scores.supervised = 0.0 if label == "BENIGN" else conf
            scores.attack_type = label
            scores.supervised_confidence = conf

    # Isolation Forest
    if host_vec is not None and iforest.is_available:
        scores.isolation_forest = iforest.anomaly_score(host_vec)

    # LSTM
    if host_vec is not None and lstm.is_available:
        lstm.update(record.key[0], host_vec)
        scores.lstm = lstm.anomaly_score(record.key[0])

    # Rules
    if flow_vec is not None:
        rule_score, triggered = rules.evaluate(record, flow_vec, payload_matches)
        scores.rules = rule_score
        scores.triggered_rules = triggered

    result = ensemble.score(scores)

    return {
        "flow_key": flow_key_str(record),
        "src_ip": record.key[0],
        "dst_ip": record.key[1],
        "ensemble_score": round(result.score, 4),
        "is_anomaly": result.is_anomaly,
        "attack_type": scores.attack_type,
        "active_engines": result.active_engines,
        "triggered_rules": scores.triggered_rules,
    }


def replay_pcap(pcap_path: str, labels: Optional[Dict[str, str]] = None) -> EvalResult:
    """Replay a single PCAP file through the detection pipeline."""
    logger.info("Processing %s", pcap_path)

    flow_extractor = FlowExtractor()
    host_extractor = HostExtractor()
    payload_hits: Dict[str, List[str]] = defaultdict(list)

    # Process packets
    pkt_count = 0
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if not pkt.haslayer(IP):
                continue
            flow_extractor.process_packet(pkt)
            src_ip = host_extractor.process_packet(pkt)
            matches = analyze_payload(pkt)
            if matches and src_ip:
                payload_hits[src_ip].extend(matches)
            pkt_count += 1

    logger.info("Processed %d packets, extracting flows...", pkt_count)

    # Collect all flows
    eval_result = EvalResult()
    for record, flow_vec in flow_extractor.collect_all():
        host_vec = host_extractor.extract_features(record.key[0])
        payload_matches = list(set(payload_hits.get(record.key[0], [])))

        pred = run_detection(record, flow_vec, host_vec, payload_matches)
        eval_result.predictions.append(pred)

        # Compute confusion matrix if labels provided
        if labels:
            key = flow_key_str(record)
            true_label = labels.get(key, "BENIGN")
            is_attack = true_label != "BENIGN"
            predicted_attack = pred["is_anomaly"]

            if is_attack and predicted_attack:
                eval_result.tp += 1
            elif is_attack and not predicted_attack:
                eval_result.fn += 1
            elif not is_attack and predicted_attack:
                eval_result.fp += 1
            else:
                eval_result.tn += 1

    return eval_result


def main():
    parser = argparse.ArgumentParser(description="PCAP replay and model evaluation")
    parser.add_argument("pcap_files", nargs="+", help="PCAP file(s) to process")
    parser.add_argument("--labels", help="CSV file with ground-truth labels")
    parser.add_argument("--output", "-o", default="eval_results.json", help="Output JSON file")
    parser.add_argument("--threshold", type=float, help="Override ensemble threshold")
    args = parser.parse_args()

    if args.threshold:
        from src import config
        config.ENSEMBLE_THRESHOLD = args.threshold

    labels = load_labels(args.labels) if args.labels else None

    all_results = {"files": {}, "aggregate": EvalResult().to_dict()}
    aggregate = EvalResult()

    for pcap_path in args.pcap_files:
        if not Path(pcap_path).exists():
            logger.warning("File not found: %s", pcap_path)
            continue

        result = replay_pcap(pcap_path, labels)
        all_results["files"][pcap_path] = {
            "metrics": result.to_dict(),
            "predictions": result.predictions,
        }

        # Aggregate
        aggregate.predictions.extend(result.predictions)
        aggregate.tp += result.tp
        aggregate.fp += result.fp
        aggregate.tn += result.tn
        aggregate.fn += result.fn

    all_results["aggregate"] = aggregate.to_dict()
    all_results["engines"] = {
        "supervised": supervised.is_available,
        "isolation_forest": iforest.is_available,
        "lstm": lstm.is_available,
        "rules": True,
    }

    with open(args.output, "w") as f:
        json.dump(all_results, f, indent=2)

    logger.info("Results written to %s", args.output)
    logger.info("Aggregate: P=%.3f R=%.3f F1=%.3f", aggregate.precision, aggregate.recall, aggregate.f1)


if __name__ == "__main__":
    main()
