"""WebSocket endpoint for real-time alert streaming (Phase 6)."""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])

# Connected clients
_clients: Set[WebSocket] = set()
_lock = asyncio.Lock()


async def broadcast_alert(alert_data: dict) -> None:
    """Broadcast an alert to all connected WebSocket clients."""
    if not _clients:
        return
    message = json.dumps(alert_data, default=str)
    async with _lock:
        disconnected = set()
        for ws in _clients:
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.add(ws)
        _clients -= disconnected


@router.websocket("/ws/alerts")
async def alerts_ws(websocket: WebSocket):
    """WebSocket endpoint — clients receive real-time alert JSON messages."""
    await websocket.accept()
    async with _lock:
        _clients.add(websocket)
    logger.info("WebSocket client connected (%d total)", len(_clients))
    try:
        while True:
            # Keep connection alive; client can send pings
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        async with _lock:
            _clients.discard(websocket)
        logger.info("WebSocket client disconnected (%d remaining)", len(_clients))
