"""
Policies API Module
Endpoints for managing security policies
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

from .auth import get_current_user, User, require_permission


# Request/Response Models
class Policy(BaseModel):
    """Policy model."""
    id: str
    name: str
    description: str
    category: str
    enabled: bool
    rules: Dict[str, Any]
    created_at: str
    updated_at: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PolicyCreate(BaseModel):
    """Policy creation request."""
    name: str
    description: str
    category: str
    rules: Dict[str, Any]
    enabled: bool = True


class PolicyUpdate(BaseModel):
    """Policy update request."""
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    rules: Optional[Dict[str, Any]] = None


# Router
router = APIRouter()

# Mock data
mock_policies: Dict[str, Policy] = {
    "policy_1": Policy(
        id="policy_1",
        name="Block Prompt Injection",
        description="Block requests containing known prompt injection patterns",
        category="ai_security",
        enabled=True,
        rules={
            "patterns": ["ignore previous instructions", "override programming"],
            "action": "block",
            "severity": "high"
        },
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat()
    ),
    "policy_2": Policy(
        id="policy_2",
        name="API Key Detection",
        description="Detect and alert on API key exposure",
        category="code_security",
        enabled=True,
        rules={
            "patterns": ["sk-", "sk-ant-", "AKIA"],
            "action": "alert",
            "severity": "critical"
        },
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat()
    ),
}


@router.get("/", response_model=List[Policy])
async def list_policies(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    category: Optional[str] = None,
    enabled_only: bool = False,
    current_user: User = Depends(get_current_user)
):
    """List all policies with optional filtering."""
    policies = list(mock_policies.values())

    # Apply filters
    if category:
        policies = [p for p in policies if p.category == category]

    if enabled_only:
        policies = [p for p in policies if p.enabled]

    return policies[skip:skip + limit]


@router.get("/{policy_id}", response_model=Policy)
async def get_policy(
    policy_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get a specific policy by ID."""
    if policy_id not in mock_policies:
        raise HTTPException(status_code=404, detail="Policy not found")

    return mock_policies[policy_id]


@router.post("/", response_model=Policy, status_code=201)
async def create_policy(
    policy: PolicyCreate,
    current_user: User = Depends(require_permission("policy:manage"))
):
    """Create a new policy."""
    import uuid
    policy_id = f"policy_{uuid.uuid4().hex[:8]}"

    new_policy = Policy(
        id=policy_id,
        name=policy.name,
        description=policy.description,
        category=policy.category,
        enabled=policy.enabled,
        rules=policy.rules,
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat()
    )

    mock_policies[policy_id] = new_policy
    return new_policy


@router.put("/{policy_id}", response_model=Policy)
async def update_policy(
    policy_id: str,
    update: PolicyUpdate,
    current_user: User = Depends(require_permission("policy:manage"))
):
    """Update a policy."""
    if policy_id not in mock_policies:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy = mock_policies[policy_id]

    if update.name is not None:
        policy.name = update.name

    if update.description is not None:
        policy.description = update.description

    if update.enabled is not None:
        policy.enabled = update.enabled

    if update.rules is not None:
        policy.rules = update.rules

    policy.updated_at = datetime.now().isoformat()

    return policy


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: str,
    current_user: User = Depends(require_permission("policy:delete"))
):
    """Delete a policy."""
    if policy_id not in mock_policies:
        raise HTTPException(status_code=404, detail="Policy not found")

    del mock_policies[policy_id]
    return None
