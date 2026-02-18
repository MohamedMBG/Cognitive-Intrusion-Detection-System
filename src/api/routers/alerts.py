"""Alert and incident CRUD endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import Alert, Incident, SeverityLevel, IncidentStatus
from ..schemas import AlertOut, AlertUpdate, IncidentCreate, IncidentOut

router = APIRouter(prefix="/api", tags=["alerts"])


@router.get("/alerts", response_model=List[AlertOut])
async def list_alerts(
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    src_ip: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    q = select(Alert).order_by(desc(Alert.timestamp))
    if severity:
        q = q.where(Alert.severity == severity)
    if acknowledged is not None:
        q = q.where(Alert.acknowledged == acknowledged)
    if src_ip:
        q = q.where(Alert.src_ip == src_ip)
    q = q.offset(offset).limit(limit)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/alerts/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/alerts/{alert_id}", response_model=AlertOut)
async def update_alert(
    alert_id: int,
    body: AlertUpdate,
    db: AsyncSession = Depends(get_db),
):
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if body.acknowledged is not None:
        alert.acknowledged = body.acknowledged
    if body.notes is not None:
        alert.notes = body.notes
    if body.incident_id is not None:
        alert.incident_id = body.incident_id
    await db.commit()
    await db.refresh(alert)
    return alert


@router.get("/incidents", response_model=List[IncidentOut])
async def list_incidents(
    limit: int = Query(20, le=200),
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    q = select(Incident).order_by(desc(Incident.created_at)).limit(limit)
    if status:
        q = q.where(Incident.status == status)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/incidents", response_model=IncidentOut, status_code=201)
async def create_incident(body: IncidentCreate, db: AsyncSession = Depends(get_db)):
    inc = Incident(
        title=body.title,
        description=body.description,
        severity=body.severity,
        assigned_to=body.assigned_to,
    )
    db.add(inc)
    await db.commit()
    await db.refresh(inc)
    return inc


@router.get("/stats")
async def stats(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import func
    total = (await db.execute(select(func.count(Alert.id)))).scalar()
    unacked = (await db.execute(
        select(func.count(Alert.id)).where(Alert.acknowledged == False)
    )).scalar()
    by_severity = {}
    for sev in SeverityLevel:
        count = (await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == sev)
        )).scalar()
        by_severity[sev.value] = count
    return {
        "total_alerts": total,
        "unacknowledged": unacked,
        "by_severity": by_severity,
    }
