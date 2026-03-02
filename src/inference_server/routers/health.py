"""
Health check router for the ML-IDS Inference Server.

Returns a comprehensive system health snapshot including:
- Overall status (healthy / unhealthy)
- Detection engine statuses with metadata
- Database connectivity and latency
- Uptime and UTC timestamp
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse
from sqlalchemy import text

from ..engine_registry import engine_registry

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

# ---------------------------------------------------------------------------
# The startup_time is set once from main.py's startup event.
# ---------------------------------------------------------------------------
_startup_time: Optional[float] = None


def set_startup_time(ts: float) -> None:
    """Called once during app startup to record the monotonic start time."""
    global _startup_time
    _startup_time = ts


# ---------------------------------------------------------------------------
# Database health helper
# ---------------------------------------------------------------------------

async def _check_database() -> Dict[str, Any]:
    """
    Run a lightweight ``SELECT 1`` against the async engine and measure latency.

    Returns a dict with ``status`` ("connected" | "disconnected") and
    ``latency_ms`` (int, only present when connected).
    """
    # Import here to avoid circular imports: database.py ← main.py ← routers
    from ..database import engine as db_engine, db_available

    if not db_available or db_engine is None:
        return {"status": "disconnected"}

    try:
        start = time.monotonic()
        async with db_engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {"status": "connected", "latency_ms": elapsed_ms}
    except Exception as exc:
        logger.warning("Database health probe failed: %s", exc)
        return {"status": "disconnected"}


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------

@router.get("/health")
async def health_check() -> Response:
    """
    Comprehensive health-check endpoint.

    **200** — all engines loaded **and** database connected.
    **503** — any engine not loaded **or** database disconnected.
    """
    # 1. Engine statuses
    engines = engine_registry.get_status()
    all_engines_ok = engine_registry.all_loaded()

    # 2. Database
    db_info = await _check_database()
    db_ok = db_info["status"] == "connected"

    # 3. Overall
    overall = "healthy" if (all_engines_ok and db_ok) else "unhealthy"

    # 4. Uptime
    uptime_seconds = (
        int(time.monotonic() - _startup_time) if _startup_time is not None else 0
    )

    # 5. Timestamp
    timestamp = datetime.now(timezone.utc).isoformat()

    payload: Dict[str, Any] = {
        "status": overall,
        "timestamp": timestamp,
        "uptime_seconds": uptime_seconds,
        "engines": engines,
        "database": db_info,
    }

    status_code = 200 if overall == "healthy" else 503
    return JSONResponse(content=payload, status_code=status_code)
