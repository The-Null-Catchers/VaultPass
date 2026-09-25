import time
import uuid
from typing import Any

from sqlalchemy import JSON, Boolean, ForeignKey, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def uid() -> uuid.UUID:
    return uuid.uuid4()


def now() -> int:
    return int(time.time())


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uid)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    auth_hash: Mapped[str] = mapped_column(String(256))
    bundle: Mapped[dict[str, Any]] = mapped_column(JSON)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created: Mapped[int] = mapped_column(default=now)


class Vault(Base):
    __tablename__ = "vaults"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    wrapped_key: Mapped[dict[str, Any]] = mapped_column(JSON)
    sequence: Mapped[int] = mapped_column(Integer, default=0)


class DeviceSession(Base):
    __tablename__ = "sessions"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uid)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    access_hash: Mapped[str] = mapped_column(String(64), unique=True)
    access_expires: Mapped[int]
    expires: Mapped[int]
    revoked: Mapped[bool] = mapped_column(default=False)
    name: Mapped[str] = mapped_column(String(80))
    created: Mapped[int] = mapped_column(default=now)
    latest: Mapped[int] = mapped_column(default=now)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), index=True
    )
    used: Mapped[bool] = mapped_column(default=False)


class Item(Base):
    __tablename__ = "vault_items"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    vault_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("vaults.id", ondelete="CASCADE"), index=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    version: Mapped[int]
    sequence: Mapped[int]
    deleted: Mapped[bool] = mapped_column(default=False)
    purged: Mapped[bool] = mapped_column(default=False)
    updated: Mapped[int] = mapped_column(default=now)


class Revision(Base):
    __tablename__ = "vault_item_versions"
    __table_args__ = (UniqueConstraint("item_id", "version"),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uid)
    item_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("vault_items.id", ondelete="CASCADE"), index=True
    )
    version: Mapped[int]
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    created: Mapped[int] = mapped_column(default=now)


class Audit(Base):
    __tablename__ = "audit_events"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uid)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    event: Mapped[str] = mapped_column(String(64))
    created: Mapped[int] = mapped_column(default=now)


class Verification(Base):
    __tablename__ = "email_verifications"
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    expires: Mapped[int]


class RecoveryKey(Base):
    __tablename__ = "recovery_keys"
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    auth_hash: Mapped[str] = mapped_column(String(256))
    account_key: Mapped[dict[str, Any]] = mapped_column(JSON)
    version: Mapped[uuid.UUID] = mapped_column(Uuid, default=uid)
    created: Mapped[int] = mapped_column(default=now)


class RecoveryAttempt(Base):
    __tablename__ = "recovery_attempts"
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    recovery_version: Mapped[uuid.UUID] = mapped_column(Uuid)
    expires: Mapped[int]


class PasskeyCredential(Base):
    __tablename__ = "passkey_credentials"
    id: Mapped[str] = mapped_column(String(1024), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    public_key: Mapped[str] = mapped_column(String(4096))
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(80))
    transports: Mapped[list[str]] = mapped_column(JSON, default=list)
    aaguid: Mapped[str] = mapped_column(String(64))
    device_type: Mapped[str] = mapped_column(String(32))
    backed_up: Mapped[bool] = mapped_column(Boolean, default=False)
    created: Mapped[int] = mapped_column(default=now)
    latest: Mapped[int] = mapped_column(default=now)


class PasskeyChallenge(Base):
    __tablename__ = "passkey_challenges"
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), nullable=True
    )
    challenge: Mapped[str] = mapped_column(String(128))
    purpose: Mapped[str] = mapped_column(String(16))
    name: Mapped[str] = mapped_column(String(80))
    expires: Mapped[int]


class SharingKey(Base):
    __tablename__ = "sharing_keys"
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    public_key: Mapped[str] = mapped_column(String(2048))
    private_key: Mapped[dict[str, Any]] = mapped_column(JSON)


class Share(Base):
    __tablename__ = "shares"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    sender_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    recipient_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    wrapped_key: Mapped[str] = mapped_column(String(1024))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    expires: Mapped[int]
    revoked: Mapped[bool] = mapped_column(default=False)
    created: Mapped[int] = mapped_column(default=now)


class Team(Base):
    __tablename__ = "teams"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    created: Mapped[int] = mapped_column(default=now)


class TeamMember(Base):
    __tablename__ = "team_members"
    team_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    role: Mapped[str] = mapped_column(String(16))
    wrapped_key: Mapped[str] = mapped_column(String(1024))
    key_version: Mapped[int] = mapped_column(Integer)
    joined: Mapped[int] = mapped_column(default=now)


class TeamInvitation(Base):
    __tablename__ = "team_invitations"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    team_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("teams.id", ondelete="CASCADE"), index=True
    )
    inviter_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    recipient_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(String(16))
    wrapped_key: Mapped[str] = mapped_column(String(1024))
    key_version: Mapped[int] = mapped_column(Integer)
    expires: Mapped[int]
    revoked: Mapped[bool] = mapped_column(default=False)
    accepted: Mapped[bool] = mapped_column(default=False)
    created: Mapped[int] = mapped_column(default=now)


class TeamItem(Base):
    __tablename__ = "team_items"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    team_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("teams.id", ondelete="CASCADE"), index=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    version: Mapped[int]
    sequence: Mapped[int]
    deleted: Mapped[bool] = mapped_column(default=False)
    purged: Mapped[bool] = mapped_column(default=False)
    updated: Mapped[int] = mapped_column(default=now)


class TeamRevision(Base):
    __tablename__ = "team_item_versions"
    __table_args__ = (UniqueConstraint("item_id", "version"),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uid)
    item_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("team_items.id", ondelete="CASCADE"), index=True
    )
    version: Mapped[int]
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    created: Mapped[int] = mapped_column(default=now)


class TeamRotationJob(Base):
    __tablename__ = "team_rotation_jobs"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    team_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("teams.id", ondelete="CASCADE"), unique=True
    )
    initiator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    expected_key_version: Mapped[int] = mapped_column(Integer)
    new_key_version: Mapped[int] = mapped_column(Integer)
    expires: Mapped[int]
    created: Mapped[int] = mapped_column(default=now)


class TeamRotationMember(Base):
    __tablename__ = "team_rotation_members"
    rotation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("team_rotation_jobs.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    wrapped_key: Mapped[str] = mapped_column(String(1024))


class TeamRotationItem(Base):
    __tablename__ = "team_rotation_items"
    rotation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("team_rotation_jobs.id", ondelete="CASCADE"), primary_key=True
    )
    item_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("team_items.id", ondelete="CASCADE"), primary_key=True
    )
    expected_version: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
