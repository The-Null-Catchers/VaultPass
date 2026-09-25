import base64
import hashlib
import json
import secrets
import uuid
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from . import schemas as s
from .config import settings
from .db import db
from .models import (
    Audit,
    DeviceSession,
    Item,
    PasskeyChallenge,
    PasskeyCredential,
    RecoveryAttempt,
    RecoveryKey,
    RefreshToken,
    Revision,
    SharingKey,
    Team,
    TeamInvitation,
    TeamItem,
    TeamMember,
    TeamRevision,
    TeamRotationItem,
    TeamRotationJob,
    TeamRotationMember,
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
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
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
        content_length = request.headers.get("content-length")
        if content_length is not None and not content_length.isdigit():
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
        if content_length is not None and int(content_length) > settings.max_request_bytes:
            return JSONResponse(status_code=413, content={"detail": "Request too large"})
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > settings.max_request_bytes:
                return JSONResponse(status_code=413, content={"detail": "Request too large"})
        # Starlette's cached request replays this bounded body to the endpoint.
        request._body = bytes(body)
    response = await call_next(request)
    response.headers.update(
        {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
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
    # Serialize session issuance per account so concurrent logins cannot bypass the cap.
    db.scalar(select(User.id).where(User.id == user.id).with_for_update())
    active = list(
        db.scalars(
            select(DeviceSession)
            .where(
                DeviceSession.user_id == user.id,
                DeviceSession.revoked.is_(False),
                DeviceSession.expires > now(),
            )
            .order_by(DeviceSession.latest, DeviceSession.created)
            .with_for_update()
        )
    )
    overflow = len(active) - settings.max_active_sessions + 1
    for stale in active[: max(overflow, 0)]:
        stale.revoked = True
        audit(db, user.id, "session_limit_revoked_oldest")
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


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def credential_descriptor(row: PasskeyCredential) -> PublicKeyCredentialDescriptor:
    transports = []
    for value in row.transports:
        try:
            transports.append(AuthenticatorTransport(value))
        except ValueError:
            continue
    return PublicKeyCredentialDescriptor(id=unb64url(row.id), transports=transports or None)


def challenge_options(db: Session, user: User, device_name: str):
    credentials = list(
        db.scalars(select(PasskeyCredential).where(PasskeyCredential.user_id == user.id))
    )
    challenge = secrets.token_bytes(32)
    opaque = token()
    options = generate_authentication_options(
        rp_id=settings.webauthn_rp_id,
        challenge=challenge,
        timeout=300000,
        allow_credentials=[credential_descriptor(row) for row in credentials],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    db.execute(delete(PasskeyChallenge).where(PasskeyChallenge.expires <= now()))
    db.add(
        PasskeyChallenge(
            digest=digest(opaque),
            user_id=user.id,
            challenge=b64url(challenge),
            purpose="login",
            name=device_name,
            expires=now() + 300,
        )
    )
    audit(db, user.id, "passkey_login_requested")
    db.commit()
    return {
        "mfa_required": True,
        "token": opaque,
        "expires_in": 300,
        "public_key": json.loads(options_to_json(options)),
    }


def owned(db: Session, vault_id: uuid.UUID, device: DeviceSession, lock=False) -> Vault:
    query = select(Vault).where(Vault.id == vault_id, Vault.owner_id == device.user_id)
    if lock:
        query = query.with_for_update()
    vault = db.scalar(query)
    if vault is None:
        raise HTTPException(404, "Vault not found")
    return vault


def team_access(
    db: Session, team_id: uuid.UUID, device: DeviceSession, lock: bool = False
) -> tuple[Team, TeamMember]:
    query = select(Team).where(Team.id == team_id)
    if lock:
        query = query.with_for_update()
    team = db.scalar(query)
    membership = db.get(TeamMember, (team_id, device.user_id)) if team else None
    if team is None or membership is None:
        raise HTTPException(404, "Team not found")
    return team, membership


def require_team_admin(team: Team, membership: TeamMember):
    if membership.role not in {"owner", "admin"}:
        raise HTTPException(403, "Team administrator access required")


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
    user = db.scalar(select(User).where(User.email == str(body.email).lower()).with_for_update())
    try:
        check_secret(user, body.auth_secret)
    except HTTPException:
        if user:
            audit(db, user.id, "login_failed")
            db.commit()
        raise
    assert user is not None
    if db.scalar(select(PasskeyCredential.id).where(PasskeyCredential.user_id == user.id)):
        return challenge_options(db, user, body.device)
    result = issue(db, user, body.device)
    db.commit()
    return result


@app.post("/auth/passkey/complete", dependencies=[Depends(rate_limit)])
def complete_passkey_login(body: s.PasskeyComplete, db: DB):
    challenge_digest = digest(body.token)
    candidate = db.scalar(
        select(PasskeyChallenge).where(PasskeyChallenge.digest == challenge_digest)
    )
    if candidate is None or candidate.purpose != "login" or candidate.expires <= now():
        raise HTTPException(401, "Invalid or expired passkey challenge")
    user = db.scalar(select(User).where(User.id == candidate.user_id).with_for_update())
    pending = db.scalar(
        select(PasskeyChallenge)
        .where(PasskeyChallenge.digest == challenge_digest)
        .with_for_update()
    )
    if (
        user is None
        or pending is None
        or pending.user_id != user.id
        or pending.purpose != "login"
        or pending.expires <= now()
    ):
        raise HTTPException(401, "Invalid or expired passkey challenge")
    credential_id = b64url(unb64url(body.credential.raw_id))
    credential = db.get(PasskeyCredential, credential_id)
    if credential is None or credential.user_id != pending.user_id:
        db.delete(pending)
        audit(db, pending.user_id, "passkey_login_failed")
        db.commit()
        raise HTTPException(401, "Passkey verification failed")
    try:
        verified = verify_authentication_response(
            credential=body.credential.model_dump(by_alias=True, exclude_none=True),
            expected_challenge=unb64url(pending.challenge),
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin,
            credential_public_key=unb64url(credential.public_key),
            credential_current_sign_count=credential.sign_count,
            require_user_verification=True,
        )
    except (ValueError, WebAuthnException):
        db.delete(pending)
        audit(db, pending.user_id, "passkey_login_failed")
        db.commit()
        raise HTTPException(401, "Passkey verification failed") from None
    credential.sign_count = verified.new_sign_count
    credential.device_type = verified.credential_device_type.value
    credential.backed_up = verified.credential_backed_up
    credential.latest = now()
    device_name = pending.name
    db.delete(pending)
    result = issue(db, user, device_name)
    audit(db, user.id, "passkey_login_completed")
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


@app.get("/account/passkeys")
def passkeys(db: DB, device: Auth):
    return [
        {
            "id": row.id,
            "name": row.name,
            "created": row.created,
            "latest": row.latest,
            "device_type": row.device_type,
            "backed_up": row.backed_up,
            "transports": row.transports,
        }
        for row in db.scalars(
            select(PasskeyCredential)
            .where(PasskeyCredential.user_id == device.user_id)
            .order_by(PasskeyCredential.created.desc())
        )
    ]


@app.post("/account/passkeys/options", dependencies=[Depends(rate_limit)], status_code=201)
def begin_passkey_enrollment(body: s.PasskeyEnrollmentBegin, db: DB, device: Auth):
    user = db.scalar(select(User).where(User.id == device.user_id).with_for_update())
    check_secret(user, body.current_auth_secret)
    assert user
    credentials = list(
        db.scalars(select(PasskeyCredential).where(PasskeyCredential.user_id == user.id))
    )
    if len(credentials) >= settings.max_passkeys:
        raise HTTPException(409, "Passkey limit reached")
    challenge = secrets.token_bytes(32)
    opaque = token()
    options = generate_registration_options(
        rp_id=settings.webauthn_rp_id,
        rp_name="VaultPass",
        user_name=user.email,
        user_id=user.id.bytes,
        user_display_name=user.email,
        challenge=challenge,
        timeout=300000,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[credential_descriptor(row) for row in credentials],
    )
    db.execute(
        delete(PasskeyChallenge).where(
            PasskeyChallenge.user_id == user.id,
            PasskeyChallenge.purpose == "enroll",
            PasskeyChallenge.session_id == device.id,
        )
    )
    db.add(
        PasskeyChallenge(
            digest=digest(opaque),
            user_id=user.id,
            session_id=device.id,
            challenge=b64url(challenge),
            purpose="enroll",
            name=body.name,
            expires=now() + 300,
        )
    )
    db.commit()
    return {
        "token": opaque,
        "expires_in": 300,
        "public_key": json.loads(options_to_json(options)),
    }


@app.post("/account/passkeys", dependencies=[Depends(rate_limit)], status_code=201)
def complete_passkey_enrollment(body: s.PasskeyComplete, db: DB, device: Auth):
    user = db.scalar(select(User).where(User.id == device.user_id).with_for_update())
    assert user
    pending = db.scalar(
        select(PasskeyChallenge)
        .where(PasskeyChallenge.digest == digest(body.token))
        .with_for_update()
    )
    if (
        pending is None
        or pending.purpose != "enroll"
        or pending.user_id != device.user_id
        or pending.session_id != device.id
        or pending.expires <= now()
    ):
        raise HTTPException(401, "Invalid or expired passkey challenge")
    credential_count = db.scalar(
        select(func.count(PasskeyCredential.id)).where(PasskeyCredential.user_id == device.user_id)
    )
    if credential_count is not None and credential_count >= settings.max_passkeys:
        db.delete(pending)
        db.commit()
        raise HTTPException(409, "Passkey limit reached")
    try:
        verified = verify_registration_response(
            credential=body.credential.model_dump(by_alias=True, exclude_none=True),
            expected_challenge=unb64url(pending.challenge),
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin,
            require_user_verification=True,
        )
    except (ValueError, WebAuthnException):
        db.delete(pending)
        audit(db, pending.user_id, "passkey_enrollment_failed")
        db.commit()
        raise HTTPException(401, "Passkey enrollment failed") from None
    credential_id = b64url(verified.credential_id)
    if db.get(PasskeyCredential, credential_id):
        db.delete(pending)
        db.commit()
        raise HTTPException(409, "Passkey is already enrolled")
    db.add(
        PasskeyCredential(
            id=credential_id,
            user_id=device.user_id,
            public_key=b64url(verified.credential_public_key),
            sign_count=verified.sign_count,
            name=pending.name,
            transports=body.credential.response.transports or [],
            aaguid=verified.aaguid,
            device_type=verified.credential_device_type.value,
            backed_up=verified.credential_backed_up,
        )
    )
    db.delete(pending)
    audit(db, device.user_id, "passkey_enrolled")
    db.commit()
    return {"ok": True, "id": credential_id}


@app.delete("/account/passkeys/{credential_id}", dependencies=[Depends(rate_limit)])
def delete_passkey(credential_id: str, body: s.Confirm, db: DB, device: Auth):
    user = db.get(User, device.user_id)
    check_secret(user, body.auth_secret)
    credential = db.get(PasskeyCredential, credential_id)
    if credential is None or credential.user_id != device.user_id:
        raise HTTPException(404, "Passkey not found")
    db.delete(credential)
    audit(db, device.user_id, "passkey_removed")
    db.commit()
    return {"ok": True}


@app.post("/account/password", dependencies=[Depends(rate_limit)])
def change_password(body: s.Rewrap, db: DB, device: Auth):
    user = db.scalar(select(User).where(User.id == device.user_id).with_for_update())
    check_secret(user, body.current_auth_secret)
    assert user
    user.auth_hash, user.bundle = ph.hash(body.auth_secret), body.bundle.model_dump()
    for other in db.scalars(select(DeviceSession).where(DeviceSession.user_id == user.id)):
        other.revoked = True
    db.execute(delete(PasskeyChallenge).where(PasskeyChallenge.user_id == user.id))
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
    db.execute(delete(PasskeyChallenge).where(PasskeyChallenge.user_id == user.id))
    db.execute(delete(PasskeyCredential).where(PasskeyCredential.user_id == user.id))
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
    if item is None:
        item_count = db.scalar(select(func.count(Item.id)).where(Item.vault_id == vault.id))
        if item_count is not None and item_count >= settings.max_vault_items:
            raise HTTPException(409, "Vault item limit reached")
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


def serialize_team_item(item: TeamItem):
    return {
        "id": str(item.id),
        "payload": item.payload,
        "version": item.version,
        "deleted": item.deleted,
        "purged": item.purged,
        "updated": item.updated,
    }


@app.post("/teams", status_code=201, dependencies=[Depends(rate_limit)])
def create_team(body: s.TeamCreate, db: DB, device: Auth):
    user = db.scalar(select(User).where(User.id == device.user_id).with_for_update())
    if user is None or not user.verified or db.get(SharingKey, device.user_id) is None:
        raise HTTPException(403, "Verify email and enable sharing first")
    team_count = db.scalar(
        select(func.count(TeamMember.team_id)).where(TeamMember.user_id == device.user_id)
    )
    if team_count is not None and team_count >= settings.max_teams_per_user:
        raise HTTPException(409, "Team limit reached")
    db.add(Team(id=body.id, name=body.name, owner_id=device.user_id))
    db.add(
        TeamMember(
            team_id=body.id,
            user_id=device.user_id,
            role="owner",
            wrapped_key=body.wrapped_key,
            key_version=1,
        )
    )
    audit(db, device.user_id, "team_created")
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Team already exists") from exc
    return {"id": str(body.id), "key_version": 1}


@app.get("/teams")
def list_teams(db: DB, device: Auth):
    rows = db.execute(
        select(Team, TeamMember)
        .join(TeamMember, TeamMember.team_id == Team.id)
        .where(TeamMember.user_id == device.user_id)
        .order_by(Team.created)
    ).all()
    return [
        {
            "id": str(team.id),
            "name": team.name,
            "owner_id": str(team.owner_id),
            "role": membership.role,
            "key_version": team.key_version,
            "wrapped_key": membership.wrapped_key,
            "created": team.created,
        }
        for team, membership in rows
    ]


@app.get("/teams/{team_id}/members")
def list_team_members(team_id: uuid.UUID, db: DB, device: Auth):
    team_access(db, team_id, device)
    rows = db.execute(
        select(TeamMember, User, SharingKey)
        .join(User, User.id == TeamMember.user_id)
        .outerjoin(SharingKey, SharingKey.user_id == TeamMember.user_id)
        .where(TeamMember.team_id == team_id)
        .order_by(TeamMember.joined)
    ).all()
    return [
        {
            "user_id": str(member.user_id),
            "email": user.email,
            "role": member.role,
            "public_key": key.public_key if key else None,
            "key_version": member.key_version,
            "joined": member.joined,
        }
        for member, user, key in rows
    ]


@app.post("/teams/{team_id}/invitations", status_code=201, dependencies=[Depends(rate_limit)])
def invite_team_member(team_id: uuid.UUID, body: s.TeamInvite, db: DB, device: Auth):
    team, actor = team_access(db, team_id, device, lock=True)
    require_team_admin(team, actor)
    if body.role == "admin" and actor.role != "owner":
        raise HTTPException(403, "Only the owner can invite administrators")
    if body.expected_key_version != team.key_version:
        raise HTTPException(409, "Team key changed; refresh before inviting")
    recipient = db.get(User, body.recipient_id)
    if recipient is None or not recipient.verified or db.get(SharingKey, body.recipient_id) is None:
        raise HTTPException(400, "Recipient must verify email and enable sharing")
    if db.get(TeamMember, (team.id, body.recipient_id)):
        raise HTTPException(409, "Recipient is already a member")
    if body.expires <= now() or body.expires > now() + 7 * 86400:
        raise HTTPException(422, "Choose invitation expiry within 7 days")
    active_members = db.scalar(
        select(func.count(TeamMember.user_id)).where(TeamMember.team_id == team.id)
    )
    pending_recipients = set(
        db.scalars(
            select(TeamInvitation.recipient_id).where(
                TeamInvitation.team_id == team.id,
                TeamInvitation.accepted.is_(False),
                TeamInvitation.revoked.is_(False),
                TeamInvitation.expires > now(),
            )
        )
    )
    if body.recipient_id in pending_recipients:
        raise HTTPException(409, "An active invitation already exists")
    if (active_members or 0) + len(pending_recipients) >= settings.max_team_members:
        raise HTTPException(409, "Team member limit reached")
    db.add(
        TeamInvitation(
            id=body.id,
            team_id=team.id,
            inviter_id=device.user_id,
            recipient_id=body.recipient_id,
            role=body.role,
            wrapped_key=body.wrapped_key,
            key_version=team.key_version,
            expires=body.expires,
        )
    )
    audit(db, device.user_id, "team_invitation_created")
    audit(db, body.recipient_id, "team_invitation_received")
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Invitation already exists") from exc
    return {"ok": True}


@app.get("/teams/{team_id}/invitations")
def list_team_invitations(team_id: uuid.UUID, db: DB, device: Auth):
    team, actor = team_access(db, team_id, device)
    require_team_admin(team, actor)
    return [
        {
            "id": str(invitation.id),
            "recipient_id": str(invitation.recipient_id),
            "role": invitation.role,
            "key_version": invitation.key_version,
            "expires": invitation.expires,
            "revoked": invitation.revoked,
            "accepted": invitation.accepted,
            "created": invitation.created,
        }
        for invitation in db.scalars(
            select(TeamInvitation)
            .where(TeamInvitation.team_id == team.id)
            .order_by(TeamInvitation.created.desc())
            .limit(500)
        )
    ]


@app.get("/team-invitations")
def incoming_team_invitations(db: DB, device: Auth):
    rows = db.execute(
        select(TeamInvitation, Team)
        .join(Team, Team.id == TeamInvitation.team_id)
        .where(
            TeamInvitation.recipient_id == device.user_id,
            TeamInvitation.accepted.is_(False),
            TeamInvitation.revoked.is_(False),
            TeamInvitation.expires > now(),
            TeamInvitation.key_version == Team.key_version,
        )
        .order_by(TeamInvitation.created.desc())
    ).all()
    return [
        {
            "id": str(invitation.id),
            "team_id": str(team.id),
            "team_name": team.name,
            "inviter_id": str(invitation.inviter_id),
            "role": invitation.role,
            "wrapped_key": invitation.wrapped_key,
            "key_version": invitation.key_version,
            "expires": invitation.expires,
        }
        for invitation, team in rows
    ]


@app.post("/team-invitations/{invitation_id}/accept")
def accept_team_invitation(invitation_id: uuid.UUID, db: DB, device: Auth):
    candidate = db.get(TeamInvitation, invitation_id)
    if candidate is None or candidate.recipient_id != device.user_id:
        raise HTTPException(404, "Invitation not found")
    team = db.scalar(select(Team).where(Team.id == candidate.team_id).with_for_update())
    invitation = db.scalar(
        select(TeamInvitation).where(TeamInvitation.id == invitation_id).with_for_update()
    )
    if (
        team is None
        or invitation is None
        or invitation.recipient_id != device.user_id
        or invitation.accepted
        or invitation.revoked
        or invitation.expires <= now()
        or invitation.key_version != team.key_version
    ):
        raise HTTPException(409, "Invitation is no longer valid")
    if db.get(TeamMember, (team.id, device.user_id)):
        raise HTTPException(409, "Already a team member")
    user = db.scalar(select(User).where(User.id == device.user_id).with_for_update())
    if user is None:
        raise HTTPException(404, "Invitation not found")
    team_count = db.scalar(
        select(func.count(TeamMember.team_id)).where(TeamMember.user_id == device.user_id)
    )
    if team_count is not None and team_count >= settings.max_teams_per_user:
        raise HTTPException(409, "Team limit reached")
    member_count = db.scalar(
        select(func.count(TeamMember.user_id)).where(TeamMember.team_id == team.id)
    )
    if member_count is not None and member_count >= settings.max_team_members:
        raise HTTPException(409, "Team member limit reached")
    db.add(
        TeamMember(
            team_id=team.id,
            user_id=device.user_id,
            role=invitation.role,
            wrapped_key=invitation.wrapped_key,
            key_version=invitation.key_version,
        )
    )
    invitation.accepted = True
    invitation.wrapped_key = ""
    audit(db, device.user_id, "team_invitation_accepted")
    db.commit()
    return {"team_id": str(team.id)}


@app.delete("/teams/{team_id}/invitations/{invitation_id}")
def revoke_team_invitation(team_id: uuid.UUID, invitation_id: uuid.UUID, db: DB, device: Auth):
    team, actor = team_access(db, team_id, device, lock=True)
    require_team_admin(team, actor)
    invitation = db.get(TeamInvitation, invitation_id)
    if invitation is None or invitation.team_id != team.id or invitation.accepted:
        raise HTTPException(404, "Invitation not found")
    invitation.revoked = True
    invitation.wrapped_key = ""
    audit(db, device.user_id, "team_invitation_revoked")
    db.commit()
    return {"ok": True}


@app.patch("/teams/{team_id}/members/{user_id}")
def change_team_role(
    team_id: uuid.UUID,
    user_id: uuid.UUID,
    body: s.TeamRoleChange,
    db: DB,
    device: Auth,
):
    team, actor = team_access(db, team_id, device, lock=True)
    require_team_admin(team, actor)
    target = db.get(TeamMember, (team.id, user_id))
    if target is None or target.role == "owner":
        raise HTTPException(404, "Member not found")
    if actor.role != "owner" and (target.role == "admin" or body.role == "admin"):
        raise HTTPException(403, "Only the owner can manage administrators")
    target.role = body.role
    audit(db, device.user_id, "team_role_changed")
    audit(db, user_id, "team_role_updated")
    db.commit()
    return {"ok": True}


@app.get("/teams/{team_id}/sync")
def sync_team(team_id: uuid.UUID, db: DB, device: Auth, after: int = 0):
    team, _ = team_access(db, team_id, device, lock=True)
    if after < 0 or after > team.sequence:
        raise HTTPException(400, "Invalid sync cursor")
    rows = list(
        db.scalars(
            select(TeamItem)
            .where(TeamItem.team_id == team.id, TeamItem.sequence > after)
            .order_by(TeamItem.sequence)
            .limit(500)
        )
    )
    cursor = rows[-1].sequence if rows else team.sequence
    result = {
        "cursor": cursor,
        "has_more": cursor < team.sequence,
        "key_version": team.key_version,
        "items": [serialize_team_item(item) for item in rows],
    }
    db.commit()
    return result


@app.put("/teams/{team_id}/items/{item_id}")
def write_team_item(
    team_id: uuid.UUID,
    item_id: uuid.UUID,
    body: s.TeamWrite,
    db: DB,
    device: Auth,
):
    team, membership = team_access(db, team_id, device, lock=True)
    if membership.role == "read_only":
        raise HTTPException(403, "Read-only members cannot edit")
    if body.expected_key_version != team.key_version:
        raise HTTPException(409, "Team key changed; refresh and re-encrypt")
    item = db.get(TeamItem, item_id)
    if item and item.team_id != team.id:
        raise HTTPException(404, "Item not found")
    if (
        item
        and not item.purged
        and item.version == body.expected_version + 1
        and item.payload == body.payload.model_dump()
        and item.deleted == body.deleted
    ):
        return serialize_team_item(item)
    if (item.version if item else 0) != body.expected_version or (item and item.purged):
        raise HTTPException(409, "Revision conflict; fetch remote and preserve your local edit")
    if item is None:
        item_count = db.scalar(select(func.count(TeamItem.id)).where(TeamItem.team_id == team.id))
        if item_count is not None and item_count >= settings.max_vault_items:
            raise HTTPException(409, "Team vault item limit reached")
        item = TeamItem(id=item_id, team_id=team.id)
        db.add(item)
    else:
        db.add(TeamRevision(item_id=item.id, version=item.version, payload=item.payload))
    team.sequence += 1
    item.payload = body.payload.model_dump()
    item.deleted = body.deleted
    item.version = body.expected_version + 1
    item.sequence = team.sequence
    item.updated = now()
    db.flush()
    old = list(
        db.scalars(
            select(TeamRevision)
            .where(TeamRevision.item_id == item_id)
            .order_by(TeamRevision.version.desc())
            .offset(20)
        )
    )
    for revision in old:
        db.delete(revision)
    db.commit()
    return serialize_team_item(item)


@app.get("/teams/{team_id}/items/{item_id}/history")
def team_item_history(team_id: uuid.UUID, item_id: uuid.UUID, db: DB, device: Auth):
    team_access(db, team_id, device)
    item = db.get(TeamItem, item_id)
    if item is None or item.team_id != team_id:
        raise HTTPException(404, "Item not found")
    return [
        {"version": row.version, "payload": row.payload, "created": row.created}
        for row in db.scalars(
            select(TeamRevision)
            .where(TeamRevision.item_id == item_id)
            .order_by(TeamRevision.version.desc())
        )
    ]


@app.delete("/teams/{team_id}/items/{item_id}")
def purge_team_item(
    team_id: uuid.UUID,
    item_id: uuid.UUID,
    expected_version: int,
    expected_key_version: int,
    db: DB,
    device: Auth,
):
    team, membership = team_access(db, team_id, device, lock=True)
    if membership.role == "read_only":
        raise HTTPException(403, "Read-only members cannot edit")
    if expected_key_version != team.key_version:
        raise HTTPException(409, "Team key changed; refresh before editing")
    item = db.get(TeamItem, item_id)
    if item is None or item.team_id != team.id:
        raise HTTPException(404, "Item not found")
    if not item.deleted or item.version != expected_version:
        raise HTTPException(409, "Trash revision conflict")
    team.sequence += 1
    item.payload = {}
    item.purged = True
    item.sequence = team.sequence
    item.version += 1
    item.updated = now()
    db.execute(delete(TeamRevision).where(TeamRevision.item_id == item.id))
    db.commit()
    return {"ok": True}


def rotation_job(
    db: Session,
    team_id: uuid.UUID,
    rotation_id: uuid.UUID,
    device: DeviceSession,
    lock: bool = False,
) -> TeamRotationJob:
    query = select(TeamRotationJob).where(
        TeamRotationJob.id == rotation_id,
        TeamRotationJob.team_id == team_id,
        TeamRotationJob.initiator_id == device.user_id,
    )
    if lock:
        query = query.with_for_update()
    job = db.scalar(query)
    if job is None:
        raise HTTPException(404, "Rotation not found")
    if job.expires <= now():
        raise HTTPException(410, "Rotation expired")
    return job


def validate_rotation_target(actor: TeamMember, target: TeamMember | None):
    if target is None or target.role == "owner":
        raise HTTPException(404, "Member not found")
    if target.user_id == actor.user_id:
        raise HTTPException(409, "Administrators cannot remove themselves")
    if actor.role != "owner" and target.role == "admin":
        raise HTTPException(403, "Only the owner can remove administrators")


@app.post("/teams/{team_id}/rotations", status_code=201)
def begin_team_rotation(
    team_id: uuid.UUID,
    body: s.TeamRotationStart,
    db: DB,
    device: Auth,
):
    team, actor = team_access(db, team_id, device, lock=True)
    require_team_admin(team, actor)
    target = db.get(TeamMember, (team.id, body.target_id))
    validate_rotation_target(actor, target)
    if body.expected_key_version != team.key_version:
        raise HTTPException(409, "Team key changed; restart rotation")
    existing = db.scalar(
        select(TeamRotationJob).where(TeamRotationJob.team_id == team.id).with_for_update()
    )
    if existing is not None and existing.expires > now():
        raise HTTPException(409, "A team key rotation is already in progress")
    if existing is not None:
        db.delete(existing)
        db.flush()
    job = TeamRotationJob(
        id=body.id,
        team_id=team.id,
        initiator_id=device.user_id,
        target_id=body.target_id,
        expected_key_version=team.key_version,
        new_key_version=team.key_version + 1,
        expires=now() + 3600,
    )
    db.add(job)
    audit(db, device.user_id, "team_key_rotation_started")
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Rotation already exists") from exc
    return {
        "id": str(job.id),
        "new_key_version": job.new_key_version,
        "expires": job.expires,
    }


@app.put("/teams/{team_id}/rotations/{rotation_id}/members/{user_id}")
def stage_team_rotation_member(
    team_id: uuid.UUID,
    rotation_id: uuid.UUID,
    user_id: uuid.UUID,
    body: s.TeamRotationMember,
    db: DB,
    device: Auth,
):
    team, actor = team_access(db, team_id, device)
    require_team_admin(team, actor)
    job = rotation_job(db, team_id, rotation_id, device, lock=True)
    member = db.get(TeamMember, (team.id, user_id))
    if member is None or user_id == job.target_id:
        raise HTTPException(404, "Remaining member not found")
    if db.get(SharingKey, user_id) is None:
        raise HTTPException(409, "Remaining member has no sharing identity")
    staged = db.get(TeamRotationMember, (job.id, user_id))
    if staged is None:
        staged = TeamRotationMember(rotation_id=job.id, user_id=user_id)
        db.add(staged)
    staged.wrapped_key = body.wrapped_key
    db.commit()
    return {"ok": True}


@app.put("/teams/{team_id}/rotations/{rotation_id}/items/{item_id}")
def stage_team_rotation_item(
    team_id: uuid.UUID,
    rotation_id: uuid.UUID,
    item_id: uuid.UUID,
    body: s.TeamRotationItem,
    db: DB,
    device: Auth,
):
    team, actor = team_access(db, team_id, device)
    require_team_admin(team, actor)
    job = rotation_job(db, team_id, rotation_id, device, lock=True)
    item = db.get(TeamItem, item_id)
    if item is None or item.team_id != team.id or item.purged:
        raise HTTPException(404, "Item not found")
    if item.version != body.expected_version:
        raise HTTPException(409, "Item changed; refresh before staging")
    staged = db.get(TeamRotationItem, (job.id, item_id))
    if staged is None:
        staged = TeamRotationItem(rotation_id=job.id, item_id=item_id)
        db.add(staged)
    staged.expected_version = body.expected_version
    staged.payload = body.payload.model_dump()
    db.commit()
    return {"ok": True}


@app.get("/teams/{team_id}/rotations/{rotation_id}")
def team_rotation_status(
    team_id: uuid.UUID,
    rotation_id: uuid.UUID,
    db: DB,
    device: Auth,
):
    team, actor = team_access(db, team_id, device)
    require_team_admin(team, actor)
    job = rotation_job(db, team_id, rotation_id, device)
    member_ids = list(
        db.scalars(
            select(TeamRotationMember.user_id)
            .where(TeamRotationMember.rotation_id == job.id)
            .order_by(TeamRotationMember.user_id)
        )
    )
    staged_items = db.execute(
        select(TeamRotationItem.item_id, TeamRotationItem.expected_version)
        .where(TeamRotationItem.rotation_id == job.id)
        .order_by(TeamRotationItem.item_id)
    ).all()
    expected_members = db.scalar(
        select(func.count(TeamMember.user_id)).where(
            TeamMember.team_id == team.id,
            TeamMember.user_id != job.target_id,
        )
    )
    expected_items = db.scalar(
        select(func.count(TeamItem.id)).where(
            TeamItem.team_id == team.id,
            TeamItem.purged.is_(False),
        )
    )
    return {
        "id": str(job.id),
        "target_id": str(job.target_id),
        "expected_key_version": job.expected_key_version,
        "new_key_version": job.new_key_version,
        "expires": job.expires,
        "expected_members": expected_members or 0,
        "staged_member_ids": [str(value) for value in member_ids],
        "expected_items": expected_items or 0,
        "staged_items": [
            {"id": str(item_id), "expected_version": version} for item_id, version in staged_items
        ],
    }


@app.delete("/teams/{team_id}/rotations/{rotation_id}")
def cancel_team_rotation(
    team_id: uuid.UUID,
    rotation_id: uuid.UUID,
    db: DB,
    device: Auth,
):
    team, actor = team_access(db, team_id, device, lock=True)
    require_team_admin(team, actor)
    job = db.scalar(
        select(TeamRotationJob)
        .where(TeamRotationJob.id == rotation_id, TeamRotationJob.team_id == team.id)
        .with_for_update()
    )
    if job is None or (job.initiator_id != device.user_id and actor.role != "owner"):
        raise HTTPException(404, "Rotation not found")
    db.delete(job)
    audit(db, device.user_id, "team_key_rotation_cancelled")
    db.commit()
    return {"ok": True}


@app.post("/teams/{team_id}/rotations/{rotation_id}/finalize")
def finalize_team_rotation(
    team_id: uuid.UUID,
    rotation_id: uuid.UUID,
    db: DB,
    device: Auth,
):
    team, actor = team_access(db, team_id, device, lock=True)
    require_team_admin(team, actor)
    job = rotation_job(db, team_id, rotation_id, device, lock=True)
    target = db.get(TeamMember, (team.id, job.target_id))
    validate_rotation_target(actor, target)
    if team.key_version != job.expected_key_version:
        raise HTTPException(409, "Team key changed; restart rotation")
    members = list(
        db.scalars(select(TeamMember).where(TeamMember.team_id == team.id).with_for_update())
    )
    expected_members = {member.user_id for member in members if member.user_id != job.target_id}
    staged_members = {
        row.user_id: row
        for row in db.scalars(
            select(TeamRotationMember).where(TeamRotationMember.rotation_id == job.id)
        )
    }
    if set(staged_members) != expected_members:
        raise HTTPException(409, "Stage a wrapped key for every remaining member")
    if any(db.get(SharingKey, member_id) is None for member_id in expected_members):
        raise HTTPException(409, "A remaining member has no sharing identity")
    items = list(
        db.scalars(
            select(TeamItem)
            .where(TeamItem.team_id == team.id, TeamItem.purged.is_(False))
            .with_for_update()
        )
    )
    staged_items = {
        row.item_id: row
        for row in db.scalars(
            select(TeamRotationItem).where(TeamRotationItem.rotation_id == job.id)
        )
    }
    if set(staged_items) != {item.id for item in items}:
        raise HTTPException(409, "Stage replacement ciphertext for every retained item")
    if any(staged_items[item.id].expected_version != item.version for item in items):
        raise HTTPException(409, "An item changed; restage current ciphertext")
    for member in members:
        if member.user_id != job.target_id:
            member.wrapped_key = staged_members[member.user_id].wrapped_key
            member.key_version = job.new_key_version
    for item in items:
        team.sequence += 1
        item.payload = staged_items[item.id].payload
        item.version += 1
        item.sequence = team.sequence
        item.updated = now()
        db.execute(delete(TeamRevision).where(TeamRevision.item_id == item.id))
    assert target is not None
    db.delete(target)
    pending = list(
        db.scalars(
            select(TeamInvitation).where(
                TeamInvitation.team_id == team.id,
                TeamInvitation.accepted.is_(False),
                TeamInvitation.revoked.is_(False),
            )
        )
    )
    for invitation in pending:
        invitation.revoked = True
        invitation.wrapped_key = ""
    team.key_version = job.new_key_version
    db.delete(job)
    audit(db, device.user_id, "team_member_removed_and_key_rotated")
    audit(db, target.user_id, "team_membership_removed")
    db.commit()
    return {"ok": True, "key_version": team.key_version}
