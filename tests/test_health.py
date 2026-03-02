"""
Unit tests for GET /health endpoint.

Tests cover:
  - Fully healthy state → HTTP 200
  - Degraded engine state (engine not loaded) → HTTP 503
  - Degraded database state (DB disconnected) → HTTP 503
  - Response payload shape and types

All engine objects and DB calls are mocked — no real database is required.
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from fastapi.testclient import TestClient

import sys, os

# Ensure src is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Mock MLflow before importing the app to prevent actual model loading
with (
    patch("mlflow.set_tracking_uri"),
    patch("mlflow.sklearn.load_model") as _mock_load,
):
    _mock_model = MagicMock()
    _mock_model.predict.return_value = [0]
    _mock_model.feature_names_in_ = ["Flow Duration", "Total Fwd Packet"]
    _mock_load.return_value = _mock_model

    from src.inference_server.main import app
    from src.inference_server.engine_registry import engine_registry
    from src.inference_server.routers.health import set_startup_time

client = TestClient(app, raise_server_exceptions=False)

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

EXPECTED_ENGINE_NAMES = {
    "anomaly_detection",
    "signature_detection",
    "behavioral_analysis",
    "threat_intelligence",
}


def _register_all_engines_loaded() -> None:
    """Register every expected engine as loaded with valid metadata."""
    engine_registry.register(
        "anomaly_detection",
        loaded=True,
        metadata={"model_version": "1.2.3"},
    )
    engine_registry.register(
        "signature_detection",
        loaded=True,
        metadata={"rules_count": 512},
    )
    engine_registry.register(
        "behavioral_analysis",
        loaded=True,
        metadata={"profiles_count": 42},
    )
    engine_registry.register(
        "threat_intelligence",
        loaded=True,
        metadata={"iocs_count": 9001},
    )


def _clear_engines() -> None:
    """Reset the engine registry to a clean (empty) state."""
    engine_registry._engines.clear()


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_state():
    """Ensure a clean registry and a set startup time for each test."""
    _clear_engines()
    set_startup_time(time.monotonic() - 10)  # pretend we started 10 s ago
    yield
    _clear_engines()


# --------------------------------------------------------------------------
# 1. Healthy state → 200
# --------------------------------------------------------------------------

class TestHealthy:
    """All engines loaded AND DB connected."""

    @patch(
        "src.inference_server.routers.health._check_database",
        new_callable=AsyncMock,
        return_value={"status": "connected", "latency_ms": 1},
    )
    def test_returns_200(self, _mock_db: AsyncMock) -> None:
        _register_all_engines_loaded()

        resp = client.get("/health")
        assert resp.status_code == 200

        body = resp.json()
        assert body["status"] == "healthy"

    @patch(
        "src.inference_server.routers.health._check_database",
        new_callable=AsyncMock,
        return_value={"status": "connected", "latency_ms": 2},
    )
    def test_response_shape(self, _mock_db: AsyncMock) -> None:
        _register_all_engines_loaded()

        body = client.get("/health").json()

        # Top-level keys
        assert set(body.keys()) == {
            "status",
            "timestamp",
            "uptime_seconds",
            "engines",
            "database",
        }

        # Engine keys
        assert set(body["engines"].keys()) == EXPECTED_ENGINE_NAMES

        # Each engine has at minimum "status"
        for name, info in body["engines"].items():
            assert info["status"] in ("loaded", "not_loaded")

        # Metadata fields
        assert body["engines"]["anomaly_detection"]["model_version"] == "1.2.3"
        assert body["engines"]["signature_detection"]["rules_count"] == 512
        assert body["engines"]["behavioral_analysis"]["profiles_count"] == 42
        assert body["engines"]["threat_intelligence"]["iocs_count"] == 9001

        # Database
        assert body["database"]["status"] == "connected"
        assert isinstance(body["database"]["latency_ms"], int)

        # Uptime / timestamp
        assert isinstance(body["uptime_seconds"], int)
        assert body["uptime_seconds"] >= 0
        assert isinstance(body["timestamp"], str)
        # ISO‑8601 should contain a "T"
        assert "T" in body["timestamp"]


# --------------------------------------------------------------------------
# 2. Degraded engine state → 503
# --------------------------------------------------------------------------

class TestDegradedEngine:
    """At least one engine is not loaded → overall unhealthy, HTTP 503."""

    @patch(
        "src.inference_server.routers.health._check_database",
        new_callable=AsyncMock,
        return_value={"status": "connected", "latency_ms": 1},
    )
    def test_one_engine_missing(self, _mock_db: AsyncMock) -> None:
        """Register only 3 of 4 engines → unhealthy."""
        engine_registry.register("anomaly_detection", loaded=True, metadata={"model_version": "1.0"})
        engine_registry.register("signature_detection", loaded=True, metadata={"rules_count": 100})
        engine_registry.register("behavioral_analysis", loaded=True, metadata={"profiles_count": 5})
        # threat_intelligence is NOT registered

        resp = client.get("/health")
        assert resp.status_code == 503
        assert resp.json()["status"] == "unhealthy"

    @patch(
        "src.inference_server.routers.health._check_database",
        new_callable=AsyncMock,
        return_value={"status": "connected", "latency_ms": 1},
    )
    def test_one_engine_not_loaded(self, _mock_db: AsyncMock) -> None:
        """All engines registered, but one reports loaded=False."""
        _register_all_engines_loaded()
        # Override one engine as not loaded
        engine_registry.register("signature_detection", loaded=False, metadata={"rules_count": None})

        resp = client.get("/health")
        assert resp.status_code == 503
        body = resp.json()
        assert body["status"] == "unhealthy"
        assert body["engines"]["signature_detection"]["status"] == "not_loaded"

    @patch(
        "src.inference_server.routers.health._check_database",
        new_callable=AsyncMock,
        return_value={"status": "connected", "latency_ms": 1},
    )
    def test_no_engines_registered(self, _mock_db: AsyncMock) -> None:
        """No engines registered at all → unhealthy."""
        resp = client.get("/health")
        assert resp.status_code == 503
        assert resp.json()["status"] == "unhealthy"


# --------------------------------------------------------------------------
# 3. Degraded database state → 503
# --------------------------------------------------------------------------

class TestDegradedDatabase:
    """Database disconnected → overall unhealthy, HTTP 503."""

    @patch(
        "src.inference_server.routers.health._check_database",
        new_callable=AsyncMock,
        return_value={"status": "disconnected"},
    )
    def test_db_disconnected(self, _mock_db: AsyncMock) -> None:
        _register_all_engines_loaded()

        resp = client.get("/health")
        assert resp.status_code == 503

        body = resp.json()
        assert body["status"] == "unhealthy"
        assert body["database"]["status"] == "disconnected"
        # latency_ms should NOT be present when disconnected
        assert "latency_ms" not in body["database"]

    @patch(
        "src.inference_server.routers.health._check_database",
        new_callable=AsyncMock,
        return_value={"status": "disconnected"},
    )
    def test_db_disconnected_and_engine_down(self, _mock_db: AsyncMock) -> None:
        """Both DB and an engine are down — still 503."""
        engine_registry.register("anomaly_detection", loaded=False, metadata={"model_version": "unknown"})

        resp = client.get("/health")
        assert resp.status_code == 503
        body = resp.json()
        assert body["status"] == "unhealthy"
        assert body["database"]["status"] == "disconnected"
        assert body["engines"]["anomaly_detection"]["status"] == "not_loaded"
