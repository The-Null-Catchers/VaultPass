import base64
import binascii
import uuid
from collections import defaultdict

from fastapi import HTTPException
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

from .config import settings
from .models import DeviceSession, Item, Revision, TeamItem, TeamRevision, User

engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)

_NEW_DEVICE_EMAILS = "new_device_security_emails"


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
    personal_revisions: dict[uuid.UUID, Revision] = {
        value.item_id: value for value in session.new if isinstance(value, Revision)
    }
    team_revisions: dict[uuid.UUID, TeamRevision] = {
        value.item_id: value for value in session.new if isinstance(value, TeamRevision)
    }
    revised_item_ids = set(personal_revisions)
    revised_team_item_ids = set(team_revisions)

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

    for vault_id, delta in list(vault_deltas.items()):
        stored = _vault_storage_bytes(connection, vault_id)
        if stored + delta > settings.max_vault_ciphertext_bytes:
            # A version bump that carries byte-for-byte identical ciphertext adds
            # no recoverable secret state. Under quota pressure, omit only that
            # redundant pending history row rather than blocking the existing item
            # update. Normal writes still retain the revision and consume quota.
            for item_id, revision in list(personal_revisions.items()):
                personal_item = dirty_items.get(item_id)
                if (
                    personal_item is not None
                    and personal_item.vault_id == vault_id
                    and personal_item.payload == revision.payload
                    and revision in session.new
                ):
                    session.expunge(revision)
                    delta -= _ciphertext_bytes(personal_item.payload)
            vault_deltas[vault_id] = delta
        if stored + delta > settings.max_vault_ciphertext_bytes:
            raise HTTPException(409, "Vault ciphertext quota reached")

    for team_id, delta in list(team_deltas.items()):
        stored = _team_storage_bytes(connection, team_id)
        if stored + delta > settings.max_vault_ciphertext_bytes:
            for item_id, team_revision in list(team_revisions.items()):
                team_item = dirty_team_items.get(item_id)
                if (
                    team_item is not None
                    and team_item.team_id == team_id
                    and team_item.payload == team_revision.payload
                    and team_revision in session.new
                ):
                    session.expunge(team_revision)
                    delta -= _ciphertext_bytes(team_item.payload)
            team_deltas[team_id] = delta
        if stored + delta > settings.max_vault_ciphertext_bytes:
            raise HTTPException(409, "Team vault ciphertext quota reached")

    for team_id, delta in team_current_replacements.items():
        if _current_team_bytes(connection, team_id) + delta > settings.max_vault_ciphertext_bytes:
            raise HTTPException(409, "Team vault ciphertext quota reached")


@event.listens_for(Session, "before_flush")
def queue_new_device_security_email(session: Session, flush_context, instances):
    """Queue a post-commit security email for additional device sessions.

    Registration creates the account's first session and must not look like a
    suspicious new-device event. Later password or passkey sign-ins create a new
    DeviceSession and are eligible when the user has left the notification on.
    The SMTP/Celery side effect is deferred until after the transaction commits so
    failed logins and rolled-back session creation never generate false alerts.
    """

    connection = session.connection()
    queued: list[tuple[str, str]] = session.info.setdefault(_NEW_DEVICE_EMAILS, [])
    for value in session.new:
        if not isinstance(value, DeviceSession):
            continue
        user = session.get(User, value.user_id)
        if user is None or not user.new_device_email_enabled:
            continue
        prior_session = connection.execute(
            select(DeviceSession.id).where(DeviceSession.user_id == value.user_id).limit(1)
        ).scalar_one_or_none()
        if prior_session is None:
            continue
        queued.append((user.email, value.name))


@event.listens_for(Session, "after_commit")
def dispatch_new_device_security_email(session: Session):
    queued = session.info.pop(_NEW_DEVICE_EMAILS, [])
    if not queued:
        return
    # Import lazily to avoid the tasks -> db import cycle during module loading.
    from .tasks import send_email

    for recipient, device_name in queued:
        send_email.delay(
            recipient,
            "New VaultPass sign-in",
            (
                f"A new device signed in to your VaultPass account: {device_name}.\n\n"
                "If this was you, no action is required. If you do not recognize "
                "this sign-in, revoke the device from VaultPass and change your "
                "master password. VaultPass never includes vault contents in "
                "security emails."
            ),
        )


@event.listens_for(Session, "after_rollback")
def discard_new_device_security_email(session: Session):
    session.info.pop(_NEW_DEVICE_EMAILS, None)


def db():
    with SessionLocal() as session:
        yield session
