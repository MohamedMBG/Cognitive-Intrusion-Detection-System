"""Pydantic schemas for the Cognitive Network Defense System API."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ── Prediction ────────────────────────────────────────────────────────────────

class PredictRequest(BaseModel):
    """Manual prediction from pre-extracted features (for testing/integration)."""
    src_ip: str
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None
    flow_features: Optional[List[float]] = Field(None, description="76 CICFlowMeter features")
    host_features: Optional[List[float]] = Field(None, description="18 host-level features")
    payload_matches: Optional[List[str]] = Field(default_factory=list)


class EngineScoresOut(BaseModel):
    supervised: Optional[float] = None
    isolation_forest: Optional[float] = None
    lstm: Optional[float] = None
    rules: Optional[float] = None
    attack_type: Optional[str] = None
    triggered_rules: List[str] = []


class PredictResponse(BaseModel):
    src_ip: str
    ensemble_score: float
    is_anomaly: bool
    severity: str
    attack_type: Optional[str]
    engine_scores: EngineScoresOut
    active_engines: List[str]
    alert_id: Optional[int] = None


# ── Alerts ─────────────────────────────────────────────────────────────────────

class AlertOut(BaseModel):
    id: int
    timestamp: datetime
    src_ip: str
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    attack_type: Optional[str]
    severity: str
    ensemble_score: Optional[float]
    engine_scores: Optional[Dict[str, Any]]
    triggered_rules: Optional[List[str]]
    acknowledged: bool
    notes: Optional[str]
    incident_id: Optional[int]

    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    acknowledged: Optional[bool] = None
    notes: Optional[str] = None
    incident_id: Optional[int] = None


# ── Incidents ──────────────────────────────────────────────────────────────────

class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: Optional[str] = "medium"
    assigned_to: Optional[str] = None


class IncidentOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    status: str
    severity: str
    assigned_to: Optional[str]
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]
    notes: Optional[str]

    class Config:
        from_attributes = True


# ── Health ─────────────────────────────────────────────────────────────────────

class HealthOut(BaseModel):
    status: str
    engines: Dict[str, bool]
    capture_stats: Optional[Dict[str, Any]] = None
