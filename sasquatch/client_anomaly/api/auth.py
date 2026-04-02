"""
auth.py — Login endpoint and Bearer token auth dependency.

Tokens are stored in Redis with a configurable TTL (default 8 hours).
The require_auth dependency is applied to all protected routes via the router.
"""

import os
import secrets

import redis.asyncio as aioredis
from fastapi import APIRouter, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
APP_USERNAME = os.getenv("APP_USERNAME", "admin")
APP_PASSWORD = os.getenv("APP_PASSWORD", "changeme")
TOKEN_TTL = 8 * 3600  # 8 hours

auth_router = APIRouter(prefix="/api/v1/auth")


class LoginRequest(BaseModel):
    username: str
    password: str


@auth_router.post("/login")
async def login(body: LoginRequest):
    """Exchange username + password for a session token."""
    if body.username != APP_USERNAME or body.password != APP_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_urlsafe(32)
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await client.set(f"sasquatch:auth:{token}", body.username, ex=TOKEN_TTL)
    finally:
        await client.aclose()
    return {"token": token}


_bearer = HTTPBearer()


async def require_auth(credentials: HTTPAuthorizationCredentials = Security(_bearer)) -> str:
    """FastAPI dependency — validates Bearer token against Redis."""
    token = credentials.credentials
    client = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        user = await client.get(f"sasquatch:auth:{token}")
    finally:
        await client.aclose()
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
