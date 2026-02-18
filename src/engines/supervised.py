"""Supervised classification engine — Random Forest trained on CIC-IDS2017.

Wraps the ML-IDS model (joblib) and returns a (attack_type, confidence) pair
from a 76-feature flow vector.
"""

import logging
import os
import numpy as np
from typing import Optional, Tuple

import joblib

from ..config import RF_MODEL_PATH
from ..features.flow_extractor import FLOW_FEATURE_NAMES

logger = logging.getLogger(__name__)

BENIGN_LABEL = "BENIGN"


class SupervisedEngine:
    """Random Forest classifier for named attack detection."""

    def __init__(self, model_path: str = RF_MODEL_PATH):
        self._model = None
        self._model_path = model_path
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._model_path):
            logger.warning("RF model not found at %s — supervised engine disabled", self._model_path)
            return
        try:
            self._model = joblib.load(self._model_path)
            logger.info("SupervisedEngine loaded: %s", self._model_path)
        except Exception as e:
            logger.error("Failed to load RF model: %s", e)

    @property
    def is_available(self) -> bool:
        return self._model is not None

    def predict(self, flow_features: np.ndarray) -> Optional[Tuple[str, float]]:
        """Predict attack type and confidence score.

        Returns:
            (attack_type, confidence) — attack_type is 'BENIGN' for normal traffic.
            None if engine unavailable or prediction fails.
        """
        if not self.is_available:
            return None
        try:
            vec = flow_features.reshape(1, -1)
            label = self._model.predict(vec)[0]
            proba = self._model.predict_proba(vec)[0]
            confidence = float(proba.max())
            return str(label), confidence
        except Exception as e:
            logger.error("SupervisedEngine prediction error: %s", e)
            return None

    def anomaly_score(self, flow_features: np.ndarray) -> float:
        """Normalised anomaly score [0, 1]; 1.0 = definitely attack."""
        result = self.predict(flow_features)
        if result is None:
            return 0.0
        label, confidence = result
        if label == BENIGN_LABEL:
            return 0.0
        return confidence
