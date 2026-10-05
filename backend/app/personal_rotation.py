import base64
import binascii
import uuid

from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import settings
from .models import (
    Item,
    PersonalVaultRotationItem,
    PersonalVaultRotationJob,
    Revision,
    Vault,
    now,
)

ROTATION_TTL_SECONDS = 30 * 60


def _ciphertext_bytes(payload: dict) -> int:
    value = payload.get("ciphertext")
    if not isinstance(value, str) or not value:
        return 0
    try:
        return len(base64.b64decode(value, validate=True))
    except (ValueError, binascii.Error):
        return 0


def validate_personal_write_epoch(vault: Vault, expected_key_version: int | None) -> None:
    """Reject stale personal-vault clients after the first successful key rotation."""
    if expected_key_version is None:
        if vault.key_version != 1:
            raise HTTPException(409, "Vault key changed; refresh and unlock with the current key")
        return
    if expected_key_version != vault.key_version:
        raise HTTPException(409, "Vault key changed; refresh and unlock with the current key")


def rotation_snapshot(db: Session, vault: Vault) -> list[dict]:
    return [
        {
            "id": str(item.id),
            "version": item.version,
            "deleted": item.deleted,
        }
        for item in db.scalars(
            select(Item)
            .where(Item.vault_id == vault.id, Item.purged.is_(False))
            .order_by(Item.id)
        )
    ]


def start_rotation(
    db: Session,
    vault: Vault,
    initiator_id: uuid.UUID,
    rotation_id: uuid.UUID,
    expected_key_version: int,
    wrapped_key: dict,
) -> PersonalVaultRotationJob:
    if expected_key_version != vault.key_version:
        raise HTTPException(409, "Vault key changed; restart rotation")
    existing = db.scalar(
        select(PersonalVaultRotationJob)
        .where(PersonalVaultRotationJob.vault_id == vault.id)
        .with_for_update()
    )
    if existing is not None and existing.expires > now():
        raise HTTPException(409, "A personal vault key rotation is already in progress")
    if existing is not None:
        db.delete(existing)
        db.flush()
    job = PersonalVaultRotationJob(
        id=rotation_id,
        vault_id=vault.id,
        initiator_id=initiator_id,
        expected_key_version=vault.key_version,
        new_key_version=vault.key_version + 1,
        wrapped_key=wrapped_key,
        expires=now() + ROTATION_TTL_SECONDS,
    )
    db.add(job)
    db.flush()
    return job


def get_rotation(
    db: Session,
    vault: Vault,
    rotation_id: uuid.UUID,
    *,
    lock: bool = False,
) -> PersonalVaultRotationJob:
    query = select(PersonalVaultRotationJob).where(
        PersonalVaultRotationJob.id == rotation_id,
        PersonalVaultRotationJob.vault_id == vault.id,
    )
    if lock:
        query = query.with_for_update()
    job = db.scalar(query)
    if job is None:
        raise HTTPException(404, "Personal vault rotation not found")
    if job.expires <= now():
        db.delete(job)
        db.flush()
        raise HTTPException(410, "Personal vault rotation expired")
    if job.expected_key_version != vault.key_version:
        raise HTTPException(409, "Vault key changed; restart rotation")
    return job


def stage_item(
    db: Session,
    vault: Vault,
    job: PersonalVaultRotationJob,
    item_id: uuid.UUID,
    expected_version: int,
    payload: dict,
) -> PersonalVaultRotationItem:
    item = db.get(Item, item_id)
    if item is None or item.vault_id != vault.id or item.purged:
        raise HTTPException(404, "Item not found")
    if item.version != expected_version:
        raise HTTPException(409, "Item changed during rotation; refresh and re-encrypt it")
    row = db.get(PersonalVaultRotationItem, (job.id, item.id))
    if row is None:
        row = PersonalVaultRotationItem(
            rotation_id=job.id,
            item_id=item.id,
            expected_version=expected_version,
            payload=payload,
        )
        db.add(row)
    else:
        row.expected_version = expected_version
        row.payload = payload
    db.flush()
    return row


def rotation_progress(db: Session, vault: Vault, job: PersonalVaultRotationJob) -> dict:
    required = rotation_snapshot(db, vault)
    uploaded = list(
        db.scalars(
            select(PersonalVaultRotationItem).where(
                PersonalVaultRotationItem.rotation_id == job.id
            )
        )
    )
    return {
        "id": str(job.id),
        "expected_key_version": job.expected_key_version,
        "new_key_version": job.new_key_version,
        "expires": job.expires,
        "required_items": required,
        "uploaded_items": len(uploaded),
        "complete": len(uploaded) == len(required),
    }


def finalize_rotation(db: Session, vault: Vault, job: PersonalVaultRotationJob) -> dict:
    current_items = list(
        db.scalars(
            select(Item)
            .where(Item.vault_id == vault.id, Item.purged.is_(False))
            .order_by(Item.id)
            .with_for_update()
        )
    )
    staged = list(
        db.scalars(
            select(PersonalVaultRotationItem).where(
                PersonalVaultRotationItem.rotation_id == job.id
            )
        )
    )
    staged_by_id = {row.item_id: row for row in staged}
    if {item.id for item in current_items} != set(staged_by_id):
        raise HTTPException(409, "Rotation is incomplete; re-encrypt every current vault item")
    projected_bytes = 0
    for item in current_items:
        replacement = staged_by_id[item.id]
        if replacement.expected_version != item.version:
            raise HTTPException(409, "Item changed during rotation; refresh and re-encrypt it")
        projected_bytes += _ciphertext_bytes(replacement.payload)
    if projected_bytes > settings.max_vault_ciphertext_bytes:
        raise HTTPException(409, "Vault ciphertext quota reached")

    for item in current_items:
        replacement = staged_by_id[item.id]
        vault.sequence += 1
        item.payload = replacement.payload
        item.version += 1
        item.sequence = vault.sequence
        item.updated = now()
        db.execute(delete(Revision).where(Revision.item_id == item.id))

    vault.wrapped_key = job.wrapped_key
    vault.key_version = job.new_key_version
    new_key_version = vault.key_version
    db.delete(job)
    db.flush()
    return {
        "ok": True,
        "key_version": new_key_version,
        "sequence": vault.sequence,
        "rotated_items": len(current_items),
    }


def cancel_rotation(db: Session, vault: Vault, rotation_id: uuid.UUID) -> None:
    job = get_rotation(db, vault, rotation_id, lock=True)
    db.delete(job)
    db.flush()
