"""Entry point: start packet capture and run the full detection pipeline.

Usage:
    sudo venv/bin/python main.py [--iface eth0] [--api] [--duration 60]

    --iface IFACE   Network interface to capture on (default: auto)
    --api           Also start the FastAPI server (port 8000)
    --duration N    Stop after N seconds (default: run until Ctrl+C)
"""

import argparse
import logging
import signal
import sys
import time
import threading
import numpy as np
from typing import List, Optional

from src.config import CAPTURE_INTERFACE, MIN_PACKETS_FOR_ML
from src.capture.packet_capture import PacketCapture, PacketProcessor
from src.capture.dispatcher import Dispatcher
from src.engines.supervised import SupervisedEngine
from src.engines.isolation_forest import IsolationForestEngine
from src.engines.lstm_autoencoder import LSTMAutoencoderEngine
from src.engines.rules import RulesEngine
from src.ensemble.scorer import EnsembleScorer, EngineScores
from src.features.flow_extractor import FlowRecord

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("unified-ids")

# ── Engine singletons ────────────────────────────────────────────────────────
supervised  = SupervisedEngine()
iforest     = IsolationForestEngine()
lstm        = LSTMAutoencoderEngine()
rules       = RulesEngine()
ensemble    = EnsembleScorer()


def on_flow_complete(
    record: FlowRecord,
    flow_vec: np.ndarray,
    host_vec: Optional[np.ndarray],
    payload_matches: List[str],
) -> None:
    """Called by the Dispatcher when a flow expires."""
    scores = EngineScores()

    if supervised.is_available:
        result = supervised.predict(flow_vec)
        if result:
            label, conf = result
            scores.supervised = 0.0 if label == "BENIGN" else conf
            scores.attack_type = label
            scores.supervised_confidence = conf

    if host_vec is not None:
        if iforest.is_available:
            scores.isolation_forest = iforest.anomaly_score(host_vec)
        if lstm.is_available:
            lstm.update(record.src_ip, host_vec)
            scores.lstm = lstm.anomaly_score(record.src_ip)

    rule_score, triggered = rules.evaluate(record, flow_vec, payload_matches)
    scores.rules = rule_score
    scores.triggered_rules = triggered

    result = ensemble.score(scores)

    if result.is_anomaly:
        parts = [
            f"src={record.src_ip}",
            f"dst={record.dst_ip}",
            f"score={result.score:.3f}",
            f"engines={result.active_engines}",
        ]
        if scores.attack_type and scores.attack_type != "BENIGN":
            parts.append(f"type={scores.attack_type}")
        if triggered:
            parts.append(f"rules={triggered}")

        logger.warning("[ALERT] %s", " | ".join(parts))


def main():
    parser = argparse.ArgumentParser(description="Unified IDS packet capture")
    parser.add_argument("--iface", default=CAPTURE_INTERFACE)
    parser.add_argument("--api", action="store_true", help="Also start FastAPI server")
    parser.add_argument("--duration", type=int, default=0, help="Run for N seconds (0 = forever)")
    args = parser.parse_args()

    logger.info("Engines: supervised=%s  iforest=%s  lstm=%s  rules=True",
                supervised.is_available, iforest.is_available, lstm.is_available)

    # Optional API server
    if args.api:
        import uvicorn
        api_thread = threading.Thread(
            target=lambda: uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, log_level="warning"),
            daemon=True,
            name="api-server",
        )
        api_thread.start()
        logger.info("API server starting on http://0.0.0.0:8000")

    dispatcher = Dispatcher(flow_callback=on_flow_complete, flush_interval=10.0)
    processor  = PacketProcessor(callback=dispatcher.dispatch)
    capture    = PacketCapture(processor=processor, iface=args.iface)

    def _shutdown(sig, frame):
        logger.info("Shutting down…")
        capture.stop()
        processor.stop()
        dispatcher.stop()
        stats = processor.stats
        logger.info("Final stats: %s | dispatcher: %s", stats, dispatcher.stats)
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    dispatcher.start()
    processor.start()
    capture.start()

    logger.info("Capture started. Press Ctrl+C to stop.")

    if args.duration > 0:
        time.sleep(args.duration)
        _shutdown(None, None)
    else:
        signal.pause()


if __name__ == "__main__":
    main()
