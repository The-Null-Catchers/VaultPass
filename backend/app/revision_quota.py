import base64
import binascii
import uuid
from collections import defaultdict
from typing import Any, Iterable, TypeVar

from fastapi import HTTPException
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from .config import settings
from .models import Item, Revision, TeamItem, TeamRevision

RevisionRow = TypeVar("RevisionRow", Revision, TeamRevision)


def _ciphertext_bytes(payload: dict[str, Any]) -> int:
    value = payload.get("ciphertext")
    if not isinstance(value, str) or not value:
        return 0
    try:
        return len(base64.b64decode(value, validate=True))
    except (ValueError, binascii.Error):
        return 0


def _retained_bytes_after_item_cap(
    rows: Iterable[RevisionRow],
    pending: Iterable[RevisionRow],
    affected_item_ids: set[uuid.UUID],
) -> int:
    grouped: dict[uuid.UUID, list[RevisionRow]] = defaultdict(list)
    for row in rows:
        grouped[row.item_id].append(row)
    for row in pending:
        grouped[row.item_id].append(row)

    total = 0
    for item_id, revisions in grouped.items():
        revisions.sort(key=lambda row: row.version, reverse=True)
        retained = revisions[:20] if item_id in affected_item_ids else revisions
        total += sum(_ciphertext_bytes(row.payload) for row in retained)
    return total


def _enforce_personal_revision_quota(session: Session, pending: list[Revision]) -> None:
    affected_by_vault: dict[uuid.UUID, list[Revision]] = defaultdict(list)
    for revision in pending:
        item = session.get(Item, revision.item_id)
        if item is not None:
            affected_by_vault[item.vault_id].append(revision)

    deleted = set(session.deleted)
    for vault_id, new_rows in affected_by_vault.items():
        existing = [
            row
            for row in session.scalars(
                select(Revision)
                .join(Item, Revision.item_id == Item.id)
                .where(Item.vault_id == vault_id)
            )
            if row not in deleted
        ]
        projected = _retained_bytes_after_item_cap(
            existing,
            new_rows,
            {row.item_id for row in new_rows},
        )
        if projected > settings.max_vault_revision_ciphertext_bytes:
            raise HTTPException(409, "Vault revision ciphertext quota reached")


def _enforce_team_revision_quota(session: Session, pending: list[TeamRevision]) -> None:
    affected_by_team: dict[uuid.UUID, list[TeamRevision]] = defaultdict(list)
    for revision in pending:
        item = session.get(TeamItem, revision.item_id)
        if item is not None:
            affected_by_team[item.team_id].append(revision)

    deleted = set(session.deleted)
    for team_id, new_rows in affected_by_team.items():
        existing = [
            row
            for row in session.scalars(
                select(TeamRevision)
                .join(TeamItem, TeamRevision.item_id == TeamItem.id)
                .where(TeamItem.team_id == team_id)
            )
            if row not in deleted
        ]
        projected = _retained_bytes_after_item_cap(
            existing,
            new_rows,
            {row.item_id for row in new_rows},
        )
        if projected > settings.max_vault_revision_ciphertext_bytes:
            raise HTTPException(409, "Team vault revision ciphertext quota reached")


@event.listens_for(Session, "before_flush")
def enforce_revision_ciphertext_quota(
    session: Session,
    flush_context: object,
    instances: object,
) -> None:
    del flush_context, instances
    personal = [row for row in session.new if isinstance(row, Revision)]
    teams = [row for row in session.new if isinstance(row, TeamRevision)]
    if personal:
        _enforce_personal_revision_quota(session, personal)
    if teams:
        _enforce_team_revision_quota(session, teams)
