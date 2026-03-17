"""
Authentication and Authorization Module
JWT-based authentication with RBAC support
"""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from loguru import logger


# Configuration
SECRET_KEY = "your-secret-key-change-this"  # Use environment variable in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security scheme
security = HTTPBearer()


class Role:
    """User roles."""
    ADMIN = "admin"
    OPERATOR = "operator"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Permission:
    """Permissions."""
    # Asset permissions
    ASSET_VIEW = "asset:view"
    ASSET_MANAGE = "asset:manage"
    ASSET_DELETE = "asset:delete"

    # Alert permissions
    ALERT_VIEW = "alert:view"
    ALERT_MANAGE = "alert:manage"
    ALERT_RESOLVE = "alert:resolve"

    # Policy permissions
    POLICY_VIEW = "policy:view"
    POLICY_MANAGE = "policy:manage"
    POLICY_DELETE = "policy:delete"

    # Monitoring permissions
    MONITORING_VIEW = "monitoring:view"
    MONITORING_MANAGE = "monitoring:manage"

    # System permissions
    SYSTEM_ADMIN = "system:admin"
    USER_MANAGE = "user:manage"


# Role-Permission mapping
ROLE_PERMISSIONS = {
    Role.ADMIN: [
        Permission.SYSTEM_ADMIN,
        Permission.USER_MANAGE,
        Permission.ASSET_MANAGE,
        Permission.ASSET_DELETE,
        Permission.ALERT_MANAGE,
        Permission.ALERT_RESOLVE,
        Permission.POLICY_MANAGE,
        Permission.POLICY_DELETE,
        Permission.MONITORING_MANAGE,
    ],
    Role.OPERATOR: [
        Permission.ASSET_MANAGE,
        Permission.ALERT_MANAGE,
        Permission.ALERT_RESOLVE,
        Permission.POLICY_MANAGE,
        Permission.MONITORING_MANAGE,
    ],
    Role.ANALYST: [
        Permission.ASSET_VIEW,
        Permission.ALERT_VIEW,
        Permission.POLICY_VIEW,
        Permission.MONITORING_VIEW,
    ],
    Role.VIEWER: [
        Permission.ASSET_VIEW,
        Permission.ALERT_VIEW,
        Permission.POLICY_VIEW,
        Permission.MONITORING_VIEW,
    ],
}


class TokenData(BaseModel):
    """JWT token data."""
    username: str
    roles: List[str]
    exp: Optional[datetime] = None


class User(BaseModel):
    """User model."""
    username: str
    email: str
    roles: List[str]
    permissions: List[str]

    @classmethod
    def from_token_data(cls, token_data: TokenData) -> 'User':
        """Create user from token data."""
        permissions = set()
        for role in token_data.roles:
            permissions.update(ROLE_PERMISSIONS.get(role, []))

        return cls(
            username=token_data.username,
            email=f"{token_data.username}@openclaw.ai",
            roles=token_data.roles,
            permissions=list(permissions)
        )


def create_access_token(data: Dict[str, Any], expires_delta: timedelta = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt


def verify_token(token: str) -> TokenData:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        username = payload.get("sub")
        roles = payload.get("roles", [])

        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return TokenData(username=username, roles=roles)

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> User:
    """Get the current authenticated user."""
    token = credentials.credentials

    token_data = verify_token(token)
    user = User.from_token_data(token_data)

    return user


async def require_permission(permission: str):
    """Dependency factory for requiring a specific permission."""
    async def check_permission(current_user: User = Depends(get_current_user)):
        if permission not in current_user.permissions and Permission.SYSTEM_ADMIN not in current_user.permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission required: {permission}"
            )
        return current_user

    return check_permission


async def require_role(role: str):
    """Dependency factory for requiring a specific role."""
    async def check_role(current_user: User = Depends(get_current_user)):
        if role not in current_user.roles and Role.ADMIN not in current_user.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role required: {role}"
            )
        return current_user

    return check_role


# Mock user database (replace with real database)
MOCK_USERS = {
    "admin": {
        "username": "admin",
        "email": "admin@openclaw.ai",
        "hashed_password": pwd_context.hash("admin123"),  # Change in production!
        "roles": [Role.ADMIN],
    },
    "operator": {
        "username": "operator",
        "email": "operator@openclaw.ai",
        "hashed_password": pwd_context.hash("operator123"),
        "roles": [Role.OPERATOR],
    },
    "analyst": {
        "username": "analyst",
        "email": "analyst@openclaw.ai",
        "hashed_password": pwd_context.hash("analyst123"),
        "roles": [Role.ANALYST],
    },
}


def authenticate_user(username: str, password: str) -> Optional[Dict]:
    """Authenticate a user with username and password."""
    user = MOCK_USERS.get(username)

    if not user:
        return None

    if not pwd_context.verify(password, user["hashed_password"]):
        return None

    return user
