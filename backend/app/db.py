import base64
import binascii
import uuid
from collections import defaultdict

from fastapi import HTTPException
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

from .config import settings
from .models import Item, Revision, TeamItem, TeamRevision

engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)


def _ciphertext_bytes(payload: dict | None) -> int:
    if not payload:
        return 0
    value = payload.get("ciphertext")
    if not isinstance(value, str) or not value:
        return 0
    try:
        return len(base64.b64decode(value, validate=True))
    except (ValueError, binascii.Error):
        return 0


def _vault_storage_bytes(connection, vault_id) -> int:
    current = connection.execute(
        select(Item.payload).where(Item.vault_id == vault_id, Item.purged.is_(False))
    ).scalars()
    history = connection.execute(
        select(Revision.payload)
        .join(Item, Revision.item_id == Item.id)
        .where(Item.vault_id == vault_id, Item.purged.is_(False))
    ).scalars()
    return sum(_ciphertext_bytes(payload) for payload in current) + sum(
        _ciphertext_bytes(payload) for payload in history
    )


def _team_storage_bytes(connection, team_id) -> int:
    current = connection.execute(
        select(TeamItem.payload).where(
            TeamItem.team_id == team_id,
            TeamItem.purged.is_(False),
        )
    ).scalars()
    history = connection.execute(
        select(TeamRevision.payload)
        .join(TeamItem, TeamRevision.item_id == TeamItem.id)
        .where(TeamItem.team_id == team_id, TeamItem.purged.is_(False))
    ).scalars()
    return sum(_ciphertext_bytes(payload) for payload in current) + sum(
        _ciphertext_bytes(payload) for payload in history
    )


def _current_team_bytes(connection, team_id) -> int:
    rows = connection.execute(
        select(TeamItem.payload).where(
            TeamItem.team_id == team_id,
            TeamItem.purged.is_(False),
        )
    ).scalars()
    return sum(_ciphertext_bytes(payload) for payload in rows)


def _revision_eviction_credit(connection, model, item_id) -> int:
    # A normal item write retains only the newest 20 historical revisions. Before
    # the pending revision is inserted, every existing revision after the newest
    # 19 will be evicted by that write and can be credited against the projection.
    rows = connection.execute(
        select(model.payload)
        .where(model.item_id == item_id)
        .order_by(model.version.desc())
        .offset(19)
    ).scalars()
    return sum(_ciphertext_bytes(payload) for payload in rows)


@event.listens_for(Session, "before_flush")
def enforce_ciphertext_storage_quota(session: Session, flush_context, instances):
    """Keep current ciphertext plus retained history inside each vault quota.

    The API's request-time checks bound current ciphertext. This persistence-level
    guard closes the remaining gap where repeated updates could grow encrypted
    revision history without consuming that quota. It also preserves the rolling
    20-revision window by crediting revisions that the same write will evict.
    """

    connection = session.connection()
    vault_deltas: defaultdict[uuid.UUID, int] = defaultdict(int)
    team_deltas: defaultdict[uuid.UUID, int] = defaultdict(int)
    team_current_replacements: defaultdict[uuid.UUID, int] = defaultdict(int)

    dirty_items: dict[uuid.UUID, Item] = {
        value.id: value for value in session.dirty if isinstance(value, Item) and not value.purged
    }
    dirty_team_items: dict[uuid.UUID, TeamItem] = {
        value.id: value
        for value in session.dirty
        if isinstance(value, TeamItem) and not value.purged
    }

    # Do not persist a historical ciphertext copy when a version bump carries the
    # exact same encrypted payload. It adds no recoverable state and would consume
    # quota solely because the client repeated a no-op update.
    personal_revisions = [value for value in session.new if isinstance(value, Revision)]
    for revision in personal_revisions:
        personal_item = dirty_items.get(revision.item_id)
        if personal_item is not None and personal_item.payload == revision.payload:
            session.expunge(revision)
    team_revisions = [value for value in session.new if isinstance(value, TeamRevision)]
    for team_revision in team_revisions:
        team_item = dirty_team_items.get(team_revision.item_id)
        if team_item is not None and team_item.payload == team_revision.payload:
            session.expunge(team_revision)

    revised_item_ids: set[uuid.UUID] = {
        value.item_id for value in session.new if isinstance(value, Revision)
    }
    revised_team_item_ids: set[uuid.UUID] = {
        value.item_id for value in session.new if isinstance(value, TeamRevision)
    }

    for value in session.new:
        if isinstance(value, Item) and not value.purged:
            vault_deltas[value.vault_id] += _ciphertext_bytes(value.payload)
        elif isinstance(value, TeamItem) and not value.purged:
            team_deltas[value.team_id] += _ciphertext_bytes(value.payload)

    for item_id in revised_item_ids:
        personal_item = dirty_items.get(item_id)
        if personal_item is None:
            continue
        vault_deltas[personal_item.vault_id] += _ciphertext_bytes(personal_item.payload)
        vault_deltas[personal_item.vault_id] -= _revision_eviction_credit(
            connection, Revision, item_id
        )

    for item_id in revised_team_item_ids:
        team_item = dirty_team_items.get(item_id)
        if team_item is None:
            continue
        team_deltas[team_item.team_id] += _ciphertext_bytes(team_item.payload)
        team_deltas[team_item.team_id] -= _revision_eviction_credit(
            connection, TeamRevision, item_id
        )

    # Team key-rotation finalization replaces current ciphertext and deliberately
    # drops old TeamRevision rows instead of creating a new revision. Keep the
    # existing current-ciphertext cap enforced for that internal replacement path
    # without charging history that is removed by the same transaction.
    for item_id, team_item in dirty_team_items.items():
        if item_id in revised_team_item_ids:
            continue
        old_payload = connection.execute(
            select(TeamItem.payload).where(TeamItem.id == item_id)
        ).scalar_one_or_none()
        if old_payload is None:
            continue
        team_current_replacements[team_item.team_id] += _ciphertext_bytes(team_item.payload)
        team_current_replacements[team_item.team_id] -= _ciphertext_bytes(old_payload)

    for vault_id, delta in vault_deltas.items():
        if _vault_storage_bytes(connection, vault_id) + delta > settings.max_vault_ciphertext_bytes:
            raise HTTPException(409, "Vault ciphertext quota reached")

    for team_id, delta in team_deltas.items():
        if _team_storage_bytes(connection, team_id) + delta > settings.max_vault_ciphertext_bytes:
            raise HTTPException(409, "Team vault ciphertext quota reached")

    for team_id, delta in team_current_replacements.items():
        if _current_team_bytes(connection, team_id) + delta > settings.max_vault_ciphertext_bytes:
            raise HTTPException(409, "Team vault ciphertext quota reached")


def db():
    with SessionLocal() as session:
        yield session
