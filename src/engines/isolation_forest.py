"""Isolation Forest unsupervised anomaly detection engine.

Operates on the 18-feature host-level vector from HostExtractor.
Adapted from cognitive-anomaly-detector.
"""

import logging
import os
import numpy as np
from typing import Optional

import joblib

from ..config import IF_MODEL_PATH, IF_SCALER_PATH

logger = logging.getLogger(__name__)


class IsolationForestEngine:
    """Unsupervised anomaly detector for host-level features."""

    def __init__(
        self,
        model_path: str = IF_MODEL_PATH,
        scaler_path: str = IF_SCALER_PATH,
    ):
        self._model = None
        self._scaler = None
        self._model_path = model_path
        self._scaler_path = scaler_path
        self._load()

    def _load(self) -> None:
        try:
            if os.path.exists(self._model_path):
                self._model = joblib.load(self._model_path)
                logger.info("IsolationForestEngine loaded: %s", self._model_path)
            else:
                logger.warning("IF model not found at %s", self._model_path)
        except Exception as e:
            logger.error("Failed to load IF model: %s", e)

        try:
            if os.path.exists(self._scaler_path):
                self._scaler = joblib.load(self._scaler_path)
        except Exception as e:
            logger.warning("IF scaler not loaded: %s", e)

    @property
    def is_available(self) -> bool:
        return self._model is not None

    def anomaly_score(self, host_features: np.ndarray) -> float:
        """Normalised anomaly score [0, 1]; higher = more anomalous."""
        if not self.is_available or host_features is None:
            return 0.0
        try:
            vec = host_features.reshape(1, -1)
            if self._scaler is not None:
                vec = self._scaler.transform(vec)
            raw = float(self._model.decision_function(vec)[0])
            # decision_function: negative = anomaly, positive = normal.
            # Map to [0,1] via sigmoid so extreme values retain granularity.
            score = 1.0 / (1.0 + np.exp(5.0 * raw))  # steepness=5 centres transition at 0
            return float(np.clip(score, 0.0, 1.0))
        except Exception as e:
            logger.error("IsolationForestEngine score error: %s", e)
            return 0.0
