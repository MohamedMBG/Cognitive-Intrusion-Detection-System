"""Tests for the ensemble scorer."""

import pytest
from src.ensemble.scorer import EnsembleScorer, EngineScores, EnsembleResult


@pytest.fixture
def scorer():
    return EnsembleScorer()


def test_all_engines_zero(scorer):
    scores = EngineScores(supervised=0.0, isolation_forest=0.0, lstm=0.0, rules=0.0)
    result = scorer.score(scores)
    assert result.score == pytest.approx(0.0)
    assert not result.is_anomaly
    assert len(result.active_engines) == 4


def test_all_engines_one(scorer):
    scores = EngineScores(supervised=1.0, isolation_forest=1.0, lstm=1.0, rules=1.0)
    result = scorer.score(scores)
    assert result.score == pytest.approx(1.0)
    assert result.is_anomaly


def test_no_engines_available(scorer):
    scores = EngineScores()
    result = scorer.score(scores)
    assert result.score == 0.0
    assert not result.is_anomaly
    assert result.active_engines == []


def test_weight_redistribution(scorer):
    """When some engines are None, their weight goes to active ones."""
    # Only rules active at 1.0 — should still be an anomaly since full weight goes to rules
    scores = EngineScores(rules=1.0)
    result = scorer.score(scores)
    assert result.score == pytest.approx(1.0)
    assert result.is_anomaly
    assert result.active_engines == ["rules"]


def test_partial_engines(scorer):
    scores = EngineScores(supervised=0.9, isolation_forest=0.8)
    result = scorer.score(scores)
    assert 0 < result.score < 1.0
    assert result.is_anomaly


def test_score_clamped(scorer):
    scores = EngineScores(supervised=2.0, isolation_forest=3.0, rules=5.0)
    result = scorer.score(scores)
    assert result.score <= 1.0


def test_below_threshold_not_anomaly(scorer):
    scores = EngineScores(supervised=0.1, isolation_forest=0.1, lstm=0.1, rules=0.0)
    result = scorer.score(scores)
    assert not result.is_anomaly
