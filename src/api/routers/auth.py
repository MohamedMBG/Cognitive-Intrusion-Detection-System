"""Auth endpoints for JWT token management (Phase 7)."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..auth import is_enabled, create_token

router = APIRouter(prefix="/api/auth", tags=["auth"])


class TokenRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/token", response_model=TokenResponse)
async def login(body: TokenRequest):
    """Issue a JWT token. In production, validate against a user store."""
    if not is_enabled():
        raise HTTPException(status_code=501, detail="JWT auth not configured")
    # Placeholder: accept any credentials. Replace with real user validation.
    # In production, check body.username/password against a user database.
    return TokenResponse(
        access_token=create_token(subject=body.username, role="analyst"),
    )
