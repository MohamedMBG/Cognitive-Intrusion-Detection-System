"""Multi-engine ensemble confidence scorer.

Combines scores from four engines into a single [0, 1] confidence value.
Engines without data have their weight redistributed to active engines.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..config import (
    WEIGHT_SUPERVISED, WEIGHT_IFOREST, WEIGHT_LSTM, WEIGHT_RULES,
    ENSEMBLE_THRESHOLD,
)

logger = logging.getLogger(__name__)


@dataclass
class EngineScores:
    supervised: Optional[float] = None   # None = engine unavailable / no data
    isolation_forest: Optional[float] = None
    lstm: Optional[float] = None
    rules: Optional[float] = None

    # Named attack classification from supervised engine
    attack_type: Optional[str] = None
    supervised_confidence: Optional[float] = None

    # Rules that fired
    triggered_rules: List[str] = field(default_factory=list)


@dataclass
class EnsembleResult:
    score: float                          # Combined [0, 1]
    is_anomaly: bool
    engine_scores: EngineScores
    active_engines: List[str]


class EnsembleScorer:
    """Weighted ensemble with dynamic weight redistribution."""

    _BASE_WEIGHTS: Dict[str, float] = {
        "supervised":      WEIGHT_SUPERVISED,
        "isolation_forest": WEIGHT_IFOREST,
        "lstm":            WEIGHT_LSTM,
        "rules":           WEIGHT_RULES,
    }

    def score(self, scores: EngineScores) -> EnsembleResult:
        available: Dict[str, float] = {}

        if scores.supervised is not None:
            available["supervised"] = scores.supervised
        if scores.isolation_forest is not None:
            available["isolation_forest"] = scores.isolation_forest
        if scores.lstm is not None:
            available["lstm"] = scores.lstm
        if scores.rules is not None:
            available["rules"] = scores.rules

        if not available:
            return EnsembleResult(
                score=0.0,
                is_anomaly=False,
                engine_scores=scores,
                active_engines=[],
            )

        # Redistribute weights of missing engines
        total_base = sum(self._BASE_WEIGHTS[e] for e in available)
        if total_base == 0:
            return EnsembleResult(
                score=0.0, is_anomaly=False, engine_scores=scores, active_engines=list(available.keys()),
            )
        weights = {e: self._BASE_WEIGHTS[e] / total_base for e in available}

        combined = sum(weights[e] * available[e] for e in available)
        combined = float(max(0.0, min(1.0, combined)))

        return EnsembleResult(
            score=combined,
            is_anomaly=combined >= ENSEMBLE_THRESHOLD,
            engine_scores=scores,
            active_engines=list(available.keys()),
        )
