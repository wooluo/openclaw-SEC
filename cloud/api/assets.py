"""
Assets API Module
Endpoints for managing security assets
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

from .auth import get_current_user, User, require_permission


# Request/Response Models
class Asset(BaseModel):
    """Asset model."""
    id: str
    path: str
    asset_type: str
    risk_level: str
    created_at: str
    updated_at: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AssetCreate(BaseModel):
    """Asset creation request."""
    path: str
    asset_type: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AssetUpdate(BaseModel):
    """Asset update request."""
    risk_level: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class AssetScanRequest(BaseModel):
    """Asset scan request."""
    directory: str
    recursive: bool = True


class AssetScanResponse(BaseModel):
    """Asset scan response."""
    scan_id: str
    status: str
    assets_discovered: int
    timestamp: str


class AssetStats(BaseModel):
    """Asset statistics."""
    total_assets: int
    by_type: Dict[str, int]
    by_risk: Dict[str, int]
    last_updated: str


# Router
router = APIRouter()

# Mock data (replace with database)
mock_assets: Dict[str, Asset] = {
    "asset_1": Asset(
        id="asset_1",
        path="/home/user/project/main.py",
        asset_type="code",
        risk_level="medium",
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat(),
        metadata={"language": "python", "size": 1024}
    ),
    "asset_2": Asset(
        id="asset_2",
        path="/home/user/project/config.yaml",
        asset_type="config",
        risk_level="low",
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat(),
        metadata={"format": "yaml", "size": 512}
    ),
}


@router.get("/", response_model=List[Asset])
async def list_assets(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    asset_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """List all assets with optional filtering."""
    assets = list(mock_assets.values())

    # Apply filters
    if asset_type:
        assets = [a for a in assets if a.asset_type == asset_type]

    if risk_level:
        assets = [a for a in assets if a.risk_level == risk_level]

    # Apply pagination
    return assets[skip:skip + limit]


@router.get("/stats", response_model=AssetStats)
async def get_asset_stats(
    current_user: User = Depends(get_current_user)
):
    """Get asset statistics."""
    assets = list(mock_assets.values())

    by_type = {}
    by_risk = {}

    for asset in assets:
        by_type[asset.asset_type] = by_type.get(asset.asset_type, 0) + 1
        by_risk[asset.risk_level] = by_risk.get(asset.risk_level, 0) + 1

    return AssetStats(
        total_assets=len(assets),
        by_type=by_type,
        by_risk=by_risk,
        last_updated=datetime.now().isoformat()
    )


@router.get("/{asset_id}", response_model=Asset)
async def get_asset(
    asset_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get a specific asset by ID."""
    if asset_id not in mock_assets:
        raise HTTPException(status_code=404, detail="Asset not found")

    return mock_assets[asset_id]


@router.post("/", response_model=Asset, status_code=201)
async def create_asset(
    asset: AssetCreate,
    current_user: User = Depends(require_permission("asset:manage"))
):
    """Create a new asset."""
    import uuid
    asset_id = f"asset_{uuid.uuid4().hex[:8]}"

    new_asset = Asset(
        id=asset_id,
        path=asset.path,
        asset_type=asset.asset_type,
        risk_level="unknown",
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat(),
        metadata=asset.metadata
    )

    mock_assets[asset_id] = new_asset
    return new_asset


@router.post("/scan", response_model=AssetScanResponse)
async def scan_assets(
    request: AssetScanRequest,
    current_user: User = Depends(require_permission("asset:manage"))
):
    """Initiate an asset scan."""
    import uuid

    # In a real implementation, this would trigger a background task
    scan_id = f"scan_{uuid.uuid4().hex}"

    return AssetScanResponse(
        scan_id=scan_id,
        status="started",
        assets_discovered=0,
        timestamp=datetime.now().isoformat()
    )


@router.put("/{asset_id}", response_model=Asset)
async def update_asset(
    asset_id: str,
    update: AssetUpdate,
    current_user: User = Depends(require_permission("asset:manage"))
):
    """Update an asset."""
    if asset_id not in mock_assets:
        raise HTTPException(status_code=404, detail="Asset not found")

    asset = mock_assets[asset_id]

    if update.risk_level is not None:
        asset.risk_level = update.risk_level

    if update.metadata is not None:
        asset.metadata.update(update.metadata)

    asset.updated_at = datetime.now().isoformat()

    return asset


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(
    asset_id: str,
    current_user: User = Depends(require_permission("asset:delete"))
):
    """Delete an asset."""
    if asset_id not in mock_assets:
        raise HTTPException(status_code=404, detail="Asset not found")

    del mock_assets[asset_id]
    return None
