"""
Monitoring API Module
Endpoints for system monitoring and metrics
"""

from fastapi import APIRouter, Depends, Query
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from datetime import datetime, timedelta

from .auth import get_current_user, User


# Request/Response Models
class SystemMetrics(BaseModel):
    """System metrics."""
    timestamp: str
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_io: Dict[str, int]
    active_connections: int
    uptime_seconds: int


class SecurityMetrics(BaseModel):
    """Security metrics."""
    timestamp: str
    total_scans: int
    threats_detected: int
    alerts_generated: int
    blocked_requests: int
    detection_rate: float


class MetricSeries(BaseModel):
    """Time series data point."""
    timestamp: str
    value: float


class MonitoringDashboard(BaseModel):
    """Monitoring dashboard data."""
    system_metrics: SystemMetrics
    security_metrics: SecurityMetrics
    recent_alerts: int
    active_threats: int
    last_updated: str


# Router
router = APIRouter()


@router.get("/dashboard", response_model=MonitoringDashboard)
async def get_dashboard(
    current_user: User = Depends(get_current_user)
):
    """Get monitoring dashboard data."""
    import psutil
    from datetime import datetime

    # System metrics
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    # Network I/O
    net_io = psutil.net_io_counters()

    system_metrics = SystemMetrics(
        timestamp=datetime.now().isoformat(),
        cpu_percent=cpu_percent,
        memory_percent=memory.percent,
        disk_percent=disk.percent,
        network_io={
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv
        },
        active_connections=len(psutil.net_connections()),
        uptime_seconds=int((datetime.now() - datetime.fromtimestamp(psutil.boot_time())).total_seconds())
    )

    # Security metrics (mock data)
    security_metrics = SecurityMetrics(
        timestamp=datetime.now().isoformat(),
        total_scans=1250,
        threats_detected=42,
        alerts_generated=15,
        blocked_requests=8,
        detection_rate=0.034
    )

    return MonitoringDashboard(
        system_metrics=system_metrics,
        security_metrics=security_metrics,
        recent_alerts=5,
        active_threats=3,
        last_updated=datetime.now().isoformat()
    )


@router.get("/system", response_model=SystemMetrics)
async def get_system_metrics(
    current_user: User = Depends(get_current_user)
):
    """Get current system metrics."""
    import psutil
    from datetime import datetime

    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net_io = psutil.net_io_counters()

    return SystemMetrics(
        timestamp=datetime.now().isoformat(),
        cpu_percent=cpu_percent,
        memory_percent=memory.percent,
        disk_percent=disk.percent,
        network_io={
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv
        },
        active_connections=len(psutil.net_connections()),
        uptime_seconds=int((datetime.now() - datetime.fromtimestamp(psutil.boot_time())).total_seconds())
    )


@router.get("/security", response_model=SecurityMetrics)
async def get_security_metrics(
    current_user: User = Depends(get_current_user)
):
    """Get security metrics."""
    # In a real implementation, this would query the database
    return SecurityMetrics(
        timestamp=datetime.now().isoformat(),
        total_scans=1250,
        threats_detected=42,
        alerts_generated=15,
        blocked_requests=8,
        detection_rate=0.034
    )


@router.get("/timeseries/cpu")
async def get_cpu_timeseries(
    hours: int = Query(24, ge=1, le=168),
    current_user: User = Depends(get_current_user)
):
    """Get CPU usage time series data."""
    # Mock data - in production, query from time-series database
    data = []
    now = datetime.now()

    for i in range(hours * 12):  # 5-minute intervals
        timestamp = now - timedelta(minutes=i * 5)
        import random
        value = 20 + random.random() * 30  # Mock CPU usage between 20-50%

        data.append({
            "timestamp": timestamp.isoformat(),
            "value": round(value, 2)
        })

    return {"data": data[::-1]}


@router.get("/timeseries/memory")
async def get_memory_timeseries(
    hours: int = Query(24, ge=1, le=168),
    current_user: User = Depends(get_current_user)
):
    """Get memory usage time series data."""
    # Mock data
    data = []
    now = datetime.now()

    for i in range(hours * 12):
        timestamp = now - timedelta(minutes=i * 5)
        import random
        value = 40 + random.random() * 20  # Mock memory usage between 40-60%

        data.append({
            "timestamp": timestamp.isoformat(),
            "value": round(value, 2)
        })

    return {"data": data[::-1]}
