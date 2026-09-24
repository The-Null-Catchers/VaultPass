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


class PasskeyEnrollmentBegin(Strict):
    current_auth_secret: str = Field(pattern=r"^[0-9a-f]{64}$")
    name: str = Field(min_length=1, max_length=80)


class WebAuthnResponse(Strict):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    client_data_json: str = Field(alias="clientDataJSON", min_length=16, max_length=16384)
    attestation_object: str | None = Field(
        default=None, alias="attestationObject", min_length=16, max_length=131072
    )
    authenticator_data: str | None = Field(
        default=None, alias="authenticatorData", min_length=16, max_length=4096
    )
    signature: str | None = Field(default=None, min_length=16, max_length=4096)
    user_handle: str | None = Field(default=None, alias="userHandle", max_length=2048)
    transports: list[str] | None = Field(default=None, max_length=8)


class WebAuthnCredential(Strict):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    id: str = Field(min_length=1, max_length=1024, pattern=r"^[A-Za-z0-9_-]+$")
    raw_id: str = Field(alias="rawId", min_length=1, max_length=2048, pattern=r"^[A-Za-z0-9_-]+$")
    type: Literal["public-key"]
    authenticator_attachment: str | None = Field(
        default=None, alias="authenticatorAttachment", max_length=32
    )
    response: WebAuthnResponse

    @field_validator("id", "raw_id")
    @classmethod
    def valid_b64url_length(cls, value: str):
        if len(value) % 4 == 1:
            raise ValueError("Invalid base64url encoding")
        return value


class PasskeyComplete(Strict):
    token: str = Field(min_length=40, max_length=128)
    credential: WebAuthnCredential


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


class RecoveryEnroll(Strict):
    current_auth_secret: str = Field(pattern=r"^[0-9a-f]{64}$")
    recovery_auth_secret: str = Field(pattern=r"^[0-9a-f]{64}$")
    account_key: Envelope


class RecoveryLookup(Strict):
    email: EmailStr


class RecoveryVerify(Strict):
    email: EmailStr
    recovery_auth_secret: str = Field(pattern=r"^[0-9a-f]{64}$")


class RecoveryComplete(Strict):
    token: str = Field(min_length=40, max_length=128)
    auth_secret: str = Field(pattern=r"^[0-9a-f]{64}$")
    bundle: Bundle


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
