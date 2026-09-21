import base64
import hashlib
import secrets
import uuid
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import schemas as s
from .config import settings
from .db import db
from .models import (
    Audit,
    DeviceSession,
    Item,
    RecoveryAttempt,
    RecoveryKey,
    RefreshToken,
    Revision,
    User,
    Vault,
    Verification,
    now,
)
from .security import authenticated, digest, rate_limit, token
from .tasks import send_email

app = FastAPI(title="VaultPass ciphertext API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
DB = Annotated[Session, Depends(db)]
Auth = Annotated[DeviceSession, Depends(authenticated)]
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
DUMMY_HASH = ph.hash(secrets.token_hex(32))


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    # FastAPI defaults reflect invalid input, potentially including secrets.
    return JSONResponse(status_code=422, content={"detail": "Invalid request"})


@app.middleware("http")
async def headers(request: Request, call_next):
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin = request.headers.get("origin")
        if origin and origin not in settings.allowed_origins:
            return JSONResponse(status_code=403, content={"detail": "Origin denied"})
        if (
            not request.headers.get("content-length", "0").isdigit()
            or int(request.headers.get("content-length", "0")) > 400000
        ):
            return JSONResponse(status_code=413, content={"detail": "Request too large"})
    response = await call_next(request)
    response.headers.update(
        {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY",
        }
    )
    return response


def audit(db: Session, user_id: uuid.UUID, event: str):
    db.add(Audit(user_id=user_id, event=event))


def check_secret(user: User | None, secret: str):
    try:
        ph.verify(user.auth_hash if user else DUMMY_HASH, secret)
    except VerifyMismatchError as exc:
        raise HTTPException(401, "Invalid credentials") from exc
    if user is None:
        raise HTTPException(401, "Invalid credentials")


def check_hash(encoded: str | None, secret: str, detail: str = "Invalid credentials"):
    try:
        ph.verify(encoded or DUMMY_HASH, secret)
    except VerifyMismatchError as exc:
        raise HTTPException(401, detail) from exc
    if encoded is None:
        raise HTTPException(401, detail)


def issue(db: Session, user: User, name: str):
    access, refresh = token(), token()
    device = DeviceSession(
        user_id=user.id,
        access_hash=digest(access),
        access_expires=now() + 900,
        expires=now() + 30 * 86400,
        name=name,
    )
    db.add(device)
    db.flush()
    db.add(RefreshToken(digest=digest(refresh), session_id=device.id))
    audit(db, user.id, "login")
    return {
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": 900,
        "session_id": str(device.id),
        "user_id": str(user.id),
        "bundle": user.bundle,
    }


def owned(db: Session, vault_id: uuid.UUID, device: DeviceSession, lock=False) -> Vault:
    query = select(Vault).where(Vault.id == vault_id, Vault.owner_id == device.user_id)
    if lock:
        query = query.with_for_update()
    vault = db.scalar(query)
    if vault is None:
        raise HTTPException(404, "Vault not found")
    return vault


@app.get("/health")
def health(db: DB):
    db.execute(text("SELECT 1"))
    return {"api": "ok", "database": "ok"}


@app.post("/auth/lookup", dependencies=[Depends(rate_limit)])
def lookup(body: s.Lookup, db: DB):
    user = db.scalar(select(User).where(User.email == str(body.email).lower()))
    return {
        "salt": user.bundle["salt"] if user else secrets.token_hex(16),
        "profile": "argon2id-m65536-t3-p4-v1",
    }


@app.post("/auth/register", status_code=201, dependencies=[Depends(rate_limit)])
def register(body: s.Register, db: DB):
    user = User(
        id=body.id,
        email=str(body.email).lower(),
        auth_hash=ph.hash(body.auth_secret),
        bundle=body.bundle.model_dump(),
    )
    db.add(user)
    try:
        db.flush()
        db.add(
            Vault(
                id=body.vault_id, owner_id=user.id, wrapped_key=body.wrapped_vault_key.model_dump()
            )
        )
        result = issue(db, user, body.device)
        audit(db, user.id, "registered")
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Account cannot be registered") from exc
    return result


@app.post("/auth/login", dependencies=[Depends(rate_limit)])
def login(body: s.Login, db: DB):
    user = db.scalar(select(User).where(User.email == str(body.email).lower()))
    try:
        check_secret(user, body.auth_secret)
    except HTTPException:
        if user:
            audit(db, user.id, "login_failed")
            db.commit()
        raise
    assert user is not None
    result = issue(db, user, body.device)
    db.commit()
    return result


@app.post("/auth/refresh", dependencies=[Depends(rate_limit)])
def refresh(body: s.Refresh, db: DB):
    old = db.scalar(
        select(RefreshToken).where(RefreshToken.digest == digest(body.token)).with_for_update()
    )
    if not old:
        raise HTTPException(401, "Invalid refresh token")
    device = db.scalar(
        select(DeviceSession).where(DeviceSession.id == old.session_id).with_for_update()
    )
    if device is None or device.revoked or device.expires <= now():
        raise HTTPException(401, "Session expired")
    if old.used:
        device.revoked = True
        audit(db, device.user_id, "refresh_replay_revoked")
        db.commit()
        raise HTTPException(401, "Refresh token replay; session revoked")
    old.used = True
    access, replacement = token(), token()
    device.access_hash, device.access_expires, device.latest = digest(access), now() + 900, now()
    db.add(RefreshToken(digest=digest(replacement), session_id=device.id))
    db.commit()
    return {"access_token": access, "refresh_token": replacement, "expires_in": 900}


@app.post("/auth/logout")
def logout(db: DB, device: Auth):
    device.revoked = True
    audit(db, device.user_id, "logout")
    db.commit()
    return {"ok": True}


@app.get("/account")
def account(db: DB, device: Auth):
    user = db.get(User, device.user_id)
    assert user
    return {
        "id": str(user.id),
        "email": user.email,
        "verified": user.verified,
        "bundle": user.bundle,
    }


@app.post("/account/password", dependencies=[Depends(rate_limit)])
def change_password(body: s.Rewrap, db: DB, device: Auth):
    user = db.scalar(select(User).where(User.id == device.user_id).with_for_update())
    check_secret(user, body.current_auth_secret)
    assert user
    user.auth_hash, user.bundle = ph.hash(body.auth_secret), body.bundle.model_dump()
    for other in db.scalars(select(DeviceSession).where(DeviceSession.user_id == user.id)):
        other.revoked = True
    audit(db, user.id, "master_password_changed")
    db.commit()
    return {"ok": True, "login_required": True}


@app.post("/account/verification", dependencies=[Depends(rate_limit)])
def request_verification(db: DB, device: Auth):
    user = db.get(User, device.user_id)
    assert user
    code = token()
    db.execute(delete(Verification).where(Verification.user_id == user.id))
    db.add(Verification(digest=digest(code), user_id=user.id, expires=now() + 3600))
    db.commit()
    send_email.apply_async(
        args=[
            user.email,
            "Verify your VaultPass email",
            "Enter this verification token in VaultPass: " + code,
        ],
        argsrepr="[redacted]",
    )
    return {"ok": True}


@app.get("/account/recovery")
def recovery_status(db: DB, device: Auth):
    user = db.get(User, device.user_id)
    assert user
    return {
        "enabled": db.get(RecoveryKey, device.user_id) is not None,
        "context": recovery_context(user.email),
    }


@app.post("/account/recovery", dependencies=[Depends(rate_limit)], status_code=201)
def enroll_recovery(body: s.RecoveryEnroll, db: DB, device: Auth):
    user = db.get(User, device.user_id)
    check_secret(user, body.current_auth_secret)
    assert user
    if db.get(RecoveryKey, user.id):
        raise HTTPException(409, "Disable the existing recovery key before replacing it")
    db.add(
        RecoveryKey(
            user_id=user.id,
            auth_hash=ph.hash(body.recovery_auth_secret),
            account_key=body.account_key.model_dump(),
        )
    )
    audit(db, user.id, "recovery_key_enabled")
    db.commit()
    return {"ok": True}


@app.delete("/account/recovery", dependencies=[Depends(rate_limit)])
def disable_recovery(body: s.Confirm, db: DB, device: Auth):
    user = db.get(User, device.user_id)
    check_secret(user, body.auth_secret)
    assert user
    row = db.get(RecoveryKey, user.id)
    if row:
        db.execute(delete(RecoveryAttempt).where(RecoveryAttempt.user_id == user.id))
        db.delete(row)
        audit(db, user.id, "recovery_key_disabled")
        db.commit()
    return {"ok": True}


def fake_envelope():
    return {
        "v": 1,
        "nonce": base64.b64encode(secrets.token_bytes(12)).decode(),
        "ciphertext": base64.b64encode(secrets.token_bytes(48)).decode(),
    }


def recovery_context(email: str):
    # Public deterministic AAD; identical behavior for enrolled and unknown addresses.
    return hashlib.sha256(f"vaultpass:v1:recovery-context:{email.lower()}".encode()).hexdigest()


@app.post("/auth/recovery/lookup", dependencies=[Depends(rate_limit)])
def recovery_lookup(body: s.RecoveryLookup, db: DB):
    email = str(body.email).lower()
    user = db.scalar(select(User).where(User.email == email))
    row = db.get(RecoveryKey, user.id) if user else None
    # Always return a syntactically valid bundle so this endpoint does not disclose enrollment.
    return {
        "context": recovery_context(email),
        "account_key": row.account_key if row else fake_envelope(),
    }


@app.post("/auth/recovery/verify", dependencies=[Depends(rate_limit)])
def recovery_verify(body: s.RecoveryVerify, db: DB):
    user = db.scalar(select(User).where(User.email == str(body.email).lower()).with_for_update())
    row = db.get(RecoveryKey, user.id) if user else None
    check_hash(row.auth_hash if row else None, body.recovery_auth_secret, "Invalid recovery key")
    assert user and row
    code = token()
    db.execute(delete(RecoveryAttempt).where(RecoveryAttempt.user_id == user.id))
    db.add(
        RecoveryAttempt(
            digest=digest(code),
            user_id=user.id,
            recovery_version=row.version,
            expires=now() + 300,
        )
    )
    audit(db, user.id, "recovery_key_verified")
    db.commit()
    return {"token": code, "user_id": str(user.id), "expires_in": 300}


@app.post("/auth/recovery/complete", dependencies=[Depends(rate_limit)])
def recovery_complete(body: s.RecoveryComplete, db: DB):
    attempt = db.scalar(
        select(RecoveryAttempt)
        .where(RecoveryAttempt.digest == digest(body.token))
        .with_for_update()
    )
    if attempt is None or attempt.expires <= now():
        raise HTTPException(401, "Invalid or expired recovery attempt")
    user = db.get(User, attempt.user_id)
    row = db.get(RecoveryKey, attempt.user_id)
    if user is None or row is None or row.version != attempt.recovery_version:
        raise HTTPException(401, "Invalid or expired recovery attempt")
    user.auth_hash, user.bundle = ph.hash(body.auth_secret), body.bundle.model_dump()
    for device in db.scalars(select(DeviceSession).where(DeviceSession.user_id == user.id)):
        device.revoked = True
    db.delete(attempt)
    db.delete(row)  # Recovery proof is one-time; enrollment must be repeated after use.
    audit(db, user.id, "account_recovered")
    db.commit()
    return {"ok": True, "login_required": True, "recovery_key_consumed": True}


@app.post("/auth/verify", dependencies=[Depends(rate_limit)])
def verify(body: s.Verify, db: DB):
    row = db.scalar(
        select(Verification).where(Verification.digest == digest(body.token)).with_for_update()
    )
    if row is None or row.expires <= now():
        raise HTTPException(400, "Invalid or expired token")
    user = db.get(User, row.user_id)
    assert user
    user.verified = True
    audit(db, user.id, "email_verified")
    db.delete(row)
    db.commit()
    return {"ok": True}


@app.post("/account/delete", dependencies=[Depends(rate_limit)])
def delete_account(body: s.Confirm, db: DB, device: Auth):
    user = db.get(User, device.user_id)
    check_secret(user, body.auth_secret)
    assert user
    db.delete(user)
    db.commit()
    return {"ok": True}


@app.get("/devices")
def devices(db: DB, device: Auth):
    return [
        {
            "id": str(d.id),
            "name": d.name,
            "created": d.created,
            "latest": d.latest,
            "revoked": d.revoked,
            "current": d.id == device.id,
        }
        for d in db.scalars(
            select(DeviceSession)
            .where(DeviceSession.user_id == device.user_id)
            .order_by(DeviceSession.created.desc())
        )
    ]


@app.delete("/devices/{device_id}")
def revoke(device_id: uuid.UUID, db: DB, device: Auth):
    target = db.get(DeviceSession, device_id)
    if not target or target.user_id != device.user_id:
        raise HTTPException(404, "Device not found")
    target.revoked = True
    audit(db, device.user_id, "session_revoked")
    db.commit()
    return {"ok": True}


@app.get("/events")
def events(db: DB, device: Auth):
    return [
        {"id": str(e.id), "event": e.event, "created": e.created}
        for e in db.scalars(
            select(Audit)
            .where(Audit.user_id == device.user_id)
            .order_by(Audit.created.desc())
            .limit(200)
        )
    ]


@app.get("/vaults")
def vaults(db: DB, device: Auth):
    return [
        {"id": str(v.id), "wrapped_key": v.wrapped_key}
        for v in db.scalars(select(Vault).where(Vault.owner_id == device.user_id))
    ]


@app.get("/vaults/{vault_id}/sync")
def sync(vault_id: uuid.UUID, db: DB, device: Auth, after: int = 0):
    vault = owned(db, vault_id, device, lock=True)
    if after < 0 or after > vault.sequence:
        raise HTTPException(400, "Invalid sync cursor")
    rows = list(
        db.scalars(
            select(Item)
            .where(Item.vault_id == vault_id, Item.sequence > after)
            .order_by(Item.sequence)
            .limit(500)
        )
    )
    cursor = rows[-1].sequence if rows else vault.sequence
    result = {
        "cursor": cursor,
        "has_more": cursor < vault.sequence,
        "items": [serialize(i) for i in rows],
    }
    db.commit()
    return result


def serialize(item: Item):
    return {
        "id": str(item.id),
        "payload": item.payload,
        "version": item.version,
        "deleted": item.deleted,
        "purged": item.purged,
        "updated": item.updated,
    }


@app.put("/vaults/{vault_id}/items/{item_id}")
def write(vault_id: uuid.UUID, item_id: uuid.UUID, body: s.Write, db: DB, device: Auth):
    vault = owned(db, vault_id, device, lock=True)
    item = db.get(Item, item_id)
    if item and item.vault_id != vault.id:
        raise HTTPException(404, "Item not found")
    # Exact retry after a lost response is idempotent, not a destructive conflict.
    if (
        item
        and not item.purged
        and item.version == body.expected_version + 1
        and item.payload == body.payload.model_dump()
        and item.deleted == body.deleted
    ):
        return serialize(item)
    if (item.version if item else 0) != body.expected_version or (item and item.purged):
        raise HTTPException(409, "Revision conflict; fetch remote and preserve your local edit")
    if item:
        db.add(Revision(item_id=item.id, version=item.version, payload=item.payload))
    else:
        item = Item(id=item_id, vault_id=vault.id)
        db.add(item)
    vault.sequence += 1
    item.payload, item.deleted = body.payload.model_dump(), body.deleted
    item.version, item.sequence, item.updated = body.expected_version + 1, vault.sequence, now()
    db.flush()
    old = list(
        db.scalars(
            select(Revision)
            .where(Revision.item_id == item_id)
            .order_by(Revision.version.desc())
            .offset(20)
        )
    )
    for revision in old:
        db.delete(revision)
    db.commit()
    return serialize(item)


@app.get("/vaults/{vault_id}/items/{item_id}/history")
def history(vault_id: uuid.UUID, item_id: uuid.UUID, db: DB, device: Auth):
    owned(db, vault_id, device)
    item = db.get(Item, item_id)
    if not item or item.vault_id != vault_id:
        raise HTTPException(404, "Item not found")
    return [
        {"version": r.version, "payload": r.payload, "created": r.created}
        for r in db.scalars(
            select(Revision).where(Revision.item_id == item_id).order_by(Revision.version.desc())
        )
    ]


@app.delete("/vaults/{vault_id}/items/{item_id}")
def purge(vault_id: uuid.UUID, item_id: uuid.UUID, expected_version: int, db: DB, device: Auth):
    vault = owned(db, vault_id, device, lock=True)
    item = db.get(Item, item_id)
    if not item or item.vault_id != vault.id:
        raise HTTPException(404, "Item not found")
    if not item.deleted or item.version != expected_version:
        raise HTTPException(409, "Trash revision conflict")
    vault.sequence += 1
    item.payload, item.purged, item.sequence = {}, True, vault.sequence
    item.version += 1
    item.updated = now()
    db.execute(delete(Revision).where(Revision.item_id == item.id))
    db.commit()
    return {"ok": True}


@app.post("/sharing/keys", dependencies=[Depends(rate_limit)])
def publish_sharing_key(body: s.SharingKey, db: DB, device: Auth):
    from .models import SharingKey

    user = db.scalar(select(User).where(User.id == device.user_id).with_for_update())
    assert user
    if db.get(SharingKey, device.user_id):
        raise HTTPException(
            409, "Sharing identity already exists; key replacement requires a rotation protocol"
        )
    db.add(
        SharingKey(
            user_id=device.user_id,
            public_key=body.public_key,
            private_key=body.private_key.model_dump(),
        )
    )
    audit(db, device.user_id, "sharing_identity_created")
    db.commit()
    return {"ok": True}


@app.get("/sharing/keys")
def own_sharing_key(db: DB, device: Auth):
    from .models import SharingKey

    key = db.get(SharingKey, device.user_id)
    if not key:
        raise HTTPException(404, "Enable sharing first")
    return {"public_key": key.public_key, "private_key": key.private_key}


@app.post("/sharing/lookup", dependencies=[Depends(rate_limit)])
def recipient_key(body: s.Lookup, db: DB, device: Auth):
    from .models import SharingKey

    user = db.scalar(
        select(User).where(User.email == str(body.email).lower(), User.verified.is_(True))
    )
    key = db.get(SharingKey, user.id) if user else None
    if not user or not key:
        raise HTTPException(404, "Recipient must verify email and enable sharing")
    return {"user_id": str(user.id), "public_key": key.public_key}


@app.post("/shares", status_code=201, dependencies=[Depends(rate_limit)])
def create_share(body: s.Share, db: DB, device: Auth):
    from .models import Share, SharingKey

    user = db.get(User, device.user_id)
    recipient = db.get(User, body.recipient_id)
    if not user or not user.verified or not recipient or not recipient.verified:
        raise HTTPException(403, "Both accounts must verify email")
    if not db.get(SharingKey, recipient.id):
        raise HTTPException(400, "Recipient has no sharing identity")
    if body.expires <= now() or body.expires > now() + 30 * 86400:
        raise HTTPException(422, "Choose expiry within 30 days")
    db.add(
        Share(
            id=body.id,
            sender_id=device.user_id,
            recipient_id=body.recipient_id,
            wrapped_key=body.wrapped_key,
            payload=body.payload.model_dump(),
            expires=body.expires,
        )
    )
    audit(db, device.user_id, "item_shared")
    audit(db, recipient.id, "share_received")
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Share already exists") from exc
    return {"ok": True}


@app.get("/shares")
def list_shares(db: DB, device: Auth):
    from .models import Share

    query = (
        select(Share)
        .where((Share.sender_id == device.user_id) | (Share.recipient_id == device.user_id))
        .order_by(Share.created.desc())
        .limit(500)
    )
    return [
        {
            "id": str(r.id),
            "sender_id": str(r.sender_id),
            "recipient_id": str(r.recipient_id),
            "expires": r.expires,
            "revoked": r.revoked,
            "outgoing": r.sender_id == device.user_id,
            **(
                {"wrapped_key": r.wrapped_key, "payload": r.payload}
                if r.recipient_id == device.user_id and not r.revoked and r.expires > now()
                else {}
            ),
        }
        for r in db.scalars(query)
    ]


@app.delete("/shares/{share_id}")
def revoke_share(share_id: uuid.UUID, db: DB, device: Auth):
    from .models import Share

    share = db.get(Share, share_id)
    if not share or share.sender_id != device.user_id:
        raise HTTPException(404, "Share not found")
    share.revoked = True
    share.payload = {}
    share.wrapped_key = ""
    audit(db, device.user_id, "share_revoked")
    db.commit()
    return {"ok": True}
