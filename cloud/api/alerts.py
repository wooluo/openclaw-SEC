"""
Alerts API Module
Endpoints for managing security alerts
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

from .auth import get_current_user, User, require_permission


# Request/Response Models
class Alert(BaseModel):
    """Alert model."""
    id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low
    status: str  # open, investigating, resolved, false_positive
    category: str
    source: str
    created_at: str
    updated_at: str
    resolved_at: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AlertUpdate(BaseModel):
    """Alert update request."""
    status: Optional[str] = None
    severity: Optional[str] = None
    notes: Optional[str] = None


class AlertStats(BaseModel):
    """Alert statistics."""
    total_alerts: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]
    by_category: Dict[str, int]
    recent: int  # Last 24 hours


# Router
router = APIRouter()

# Mock data
mock_alerts: Dict[str, Alert] = {
    "alert_1": Alert(
        id="alert_1",
        title="Prompt Injection Detected",
        description="Potential prompt injection attempt detected in AI traffic",
        severity="high",
        status="open",
        category="prompt_injection",
        source="ai_analyzer",
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat(),
        metadata={"model": "gpt-4", "provider": "openai"}
    ),
    "alert_2": Alert(
        id="alert_2",
        title="API Key Exposure",
        description="API key detected in code",
        severity="critical",
        status="open",
        category="api_key_leak",
        source="scanner",
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat(),
        metadata={"file": "/src/config.py", "line": 42}
    ),
}


@router.get("/", response_model=List[Alert])
async def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """List all alerts with optional filtering."""
    alerts = list(mock_alerts.values())

    # Apply filters
    if severity:
        alerts = [a for a in alerts if a.severity == severity]

    if status:
        alerts = [a for a in alerts if a.status == status]

    if category:
        alerts = [a for a in alerts if a.category == category]

    # Sort by created_at descending
    alerts.sort(key=lambda x: x.created_at, reverse=True)

    return alerts[skip:skip + limit]


@router.get("/stats", response_model=AlertStats)
async def get_alert_stats(
    current_user: User = Depends(get_current_user)
):
    """Get alert statistics."""
    alerts = list(mock_alerts.values())

    by_severity = {}
    by_status = {}
    by_category = {}

    for alert in alerts:
        by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1
        by_status[alert.status] = by_status.get(alert.status, 0) + 1
        by_category[alert.category] = by_category.get(alert.category, 0) + 1

    return AlertStats(
        total_alerts=len(alerts),
        by_severity=by_severity,
        by_status=by_status,
        by_category=by_category,
        recent=0  # Calculate based on time
    )


@router.get("/{alert_id}", response_model=Alert)
async def get_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get a specific alert by ID."""
    if alert_id not in mock_alerts:
        raise HTTPException(status_code=404, detail="Alert not found")

    return mock_alerts[alert_id]


@router.put("/{alert_id}", response_model=Alert)
async def update_alert(
    alert_id: str,
    update: AlertUpdate,
    current_user: User = Depends(require_permission("alert:manage"))
):
    """Update an alert."""
    if alert_id not in mock_alerts:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = mock_alerts[alert_id]

    if update.status is not None:
        alert.status = update.status
        if update.status == "resolved":
            alert.resolved_at = datetime.now().isoformat()

    if update.severity is not None:
        alert.severity = update.severity

    if update.notes is not None:
        alert.metadata["notes"] = update.notes

    alert.updated_at = datetime.now().isoformat()

    return alert


@router.post("/{alert_id}/resolve", response_model=Alert)
async def resolve_alert(
    alert_id: str,
    notes: Optional[str] = None,
    current_user: User = Depends(require_permission("alert:resolve"))
):
    """Mark an alert as resolved."""
    if alert_id not in mock_alerts:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = mock_alerts[alert_id]
    alert.status = "resolved"
    alert.resolved_at = datetime.now().isoformat()
    alert.updated_at = datetime.now().isoformat()

    if notes:
        alert.metadata["resolution_notes"] = notes

    return alert


@router.delete("/{alert_id}", status_code=204)
async def delete_alert(
    alert_id: str,
    current_user: User = Depends(require_permission("alert:manage"))
):
    """Delete an alert."""
    if alert_id not in mock_alerts:
        raise HTTPException(status_code=404, detail="Alert not found")

    del mock_alerts[alert_id]
    return None
