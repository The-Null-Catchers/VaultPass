import hashlib
import secrets

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis import Redis, RedisError
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import db
from .models import DeviceSession, now

bearer = HTTPBearer(auto_error=False)
redis = Redis.from_url(settings.redis_url)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def token() -> str:
    return secrets.token_urlsafe(32)


def rate_limit(request: Request):
    # Use the transport peer; configure a trusted reverse proxy, never arbitrary XFF.
    peer = request.client.host if request.client else "unknown"
    key = "limit:" + digest(peer) + ":" + str(now() // 60)
    try:
        with redis.pipeline() as pipe:
            pipe.incr(key)
            pipe.expire(key, 120)
            count, _ = pipe.execute()
        if count > settings.rate_limit:
            raise HTTPException(429, "Too many requests", headers={"Retry-After": "60"})
    except RedisError as exc:
        raise HTTPException(503, "Security service unavailable") from exc


def authenticated(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    session: Session = Depends(db),
) -> DeviceSession:
    if credentials is None:
        raise HTTPException(401, "Authentication required")
    device = session.scalar(
        select(DeviceSession).where(DeviceSession.access_hash == digest(credentials.credentials))
    )
    if (
        device is None
        or device.revoked
        or device.access_expires <= now()
        or device.expires <= now()
    ):
        raise HTTPException(401, "Session expired")
    return device
