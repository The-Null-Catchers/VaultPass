import base64
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Envelope(Strict):
    v: Literal[1] = 1
    nonce: str = Field(min_length=16, max_length=16)
    ciphertext: str = Field(min_length=24, max_length=350000)

    @field_validator("nonce", "ciphertext")
    @classmethod
    def valid_b64(cls, value: str, info):
        try:
            decoded = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise ValueError("Invalid encoding") from exc
        if info.field_name == "nonce" and len(decoded) != 12:
            raise ValueError("Expected a 96-bit nonce")
        if info.field_name == "ciphertext" and len(decoded) < 16:
            raise ValueError("Missing authentication tag")
        return value


class Bundle(Strict):
    salt: str = Field(pattern=r"^[0-9a-f]{32}$")
    profile: Literal["argon2id-m65536-t3-p4-v1"]
    account_key: Envelope


class Register(Strict):
    id: UUID
    email: EmailStr
    auth_secret: str = Field(pattern=r"^[0-9a-f]{64}$")
    bundle: Bundle
    vault_id: UUID
    wrapped_vault_key: Envelope
    device: str = Field(default="New device", min_length=1, max_length=80)


class Login(Strict):
    email: EmailStr
    auth_secret: str = Field(pattern=r"^[0-9a-f]{64}$")
    device: str = Field(default="New device", min_length=1, max_length=80)


class Lookup(Strict):
    email: EmailStr


class Refresh(Strict):
    token: str = Field(min_length=40, max_length=128)


class Write(Strict):
    expected_version: int = Field(ge=0)
    payload: Envelope
    deleted: bool = False


class Rewrap(Strict):
    current_auth_secret: str = Field(pattern=r"^[0-9a-f]{64}$")
    auth_secret: str = Field(pattern=r"^[0-9a-f]{64}$")
    bundle: Bundle


class Confirm(Strict):
    auth_secret: str = Field(pattern=r"^[0-9a-f]{64}$")


class Verify(Strict):
    token: str = Field(min_length=40, max_length=128)


class SharingKey(Strict):
    public_key: str = Field(min_length=128, max_length=2048, pattern=r"^[A-Za-z0-9+/]+=*$")
    private_key: Envelope


class Share(Strict):
    id: UUID
    recipient_id: UUID
    wrapped_key: str = Field(min_length=512, max_length=1024, pattern=r"^[A-Za-z0-9+/]+=*$")
    payload: Envelope
    expires: int
