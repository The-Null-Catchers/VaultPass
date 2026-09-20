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
