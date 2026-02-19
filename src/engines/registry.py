"""Shared engine singletons — single source of truth for all entry points."""

from .supervised import SupervisedEngine
from .isolation_forest import IsolationForestEngine
from .lstm_autoencoder import LSTMAutoencoderEngine
from .rules import RulesEngine
from ..ensemble.scorer import EnsembleScorer

supervised = SupervisedEngine()
iforest = IsolationForestEngine()
lstm = LSTMAutoencoderEngine()
rules = RulesEngine()
ensemble = EnsembleScorer()
