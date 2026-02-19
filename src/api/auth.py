"""JWT authentication and RBAC (Phase 7).

When JWT_SECRET is set, endpoints require a valid Bearer token.
Tokens carry a 'role' claim: 'admin', 'analyst', or 'viewer'.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..config import JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRE_MINUTES

logger = logging.getLogger(__name__)

_security = HTTPBearer(auto_error=False)

ROLES = {"admin", "analyst", "viewer"}


def is_enabled() -> bool:
    return bool(JWT_SECRET)


def create_token(subject: str, role: str = "viewer") -> str:
    """Create a signed JWT token."""
    import jwt
    payload = {
        "sub": subject,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token."""
    import jwt
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_security),
) -> Optional[dict]:
    """Dependency: extract and validate JWT from Authorization header.
    Returns None if JWT auth is disabled."""
    if not is_enabled():
        return None
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    return decode_token(credentials.credentials)


def require_role(*allowed_roles: str):
    """Dependency factory: require the user to have one of the specified roles."""
    async def _check(user: Optional[dict] = Depends(get_current_user)):
        if not is_enabled():
            return None
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        if user.get("role") not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user
    return _check
