"""FastAPI application — unified network defense orchestration API."""

import hmac
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .database import init_db
from .routers import alerts, predict
from ..config import API_KEY, CORS_ORIGINS
from ..engines.registry import supervised, iforest, lstm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initialising database…")
    await init_db()
    logger.info("Cognitive Network Defense System API ready")
    yield
    logger.info("Shutdown")


app = FastAPI(
    title="Cognitive Network Defense System API",
    description="Multi-engine network defense: supervised + unsupervised anomaly detection + rule-based heuristics",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS or ["http://localhost:3000"],
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["*"],
)

# Optional API-key auth middleware
if API_KEY:
    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        if request.url.path in ("/health", "/docs", "/openapi.json"):
            return await call_next(request)
        key = request.headers.get("X-API-Key", "")
        if not hmac.compare_digest(key, API_KEY):
            return JSONResponse(status_code=401, content={"detail": "Invalid API key"})
        return await call_next(request)

app.include_router(alerts.router)
app.include_router(predict.router)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "engines": {
            "supervised":       supervised.is_available,
            "isolation_forest": iforest.is_available,
            "lstm":             lstm.is_available,
            "rules":            True,
        },
    }
