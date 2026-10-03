import uuid
from unittest.mock import patch

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.models import (
    Base,
    Item,
    Revision,
    Share,
    Team,
    TeamItem,
    TeamRevision,
    User,
    Vault,
)
from app.tasks import cleanup_session


def envelope():
    return {"v": 1, "nonce": "bm5ubm5ubm5ubm5u", "ciphertext": "Y2lwaGVydGV4dA=="}


def test_retention_cleanup_preserves_sync_tombstones_and_recent_share_metadata():
    engine = create_engine("sqlite://")
    factory = sessionmaker(engine, expire_on_commit=False)
    Base.metadata.create_all(engine)

    owner_id = uuid.uuid4()
    recipient_id = uuid.uuid4()
    vault_id = uuid.uuid4()
    item_id = uuid.uuid4()
    team_id = uuid.uuid4()
    team_item_id = uuid.uuid4()
    old_share_id = uuid.uuid4()
    recent_share_id = uuid.uuid4()
    current = 200000

    with factory.begin() as session:
        session.add_all(
            [
                User(id=owner_id, email="owner@example.com", auth_hash="hash", bundle={}),
                User(id=recipient_id, email="recipient@example.com", auth_hash="hash", bundle={}),
                Vault(id=vault_id, owner_id=owner_id, wrapped_key=envelope(), sequence=4),
                Item(
                    id=item_id,
                    vault_id=vault_id,
                    payload=envelope(),
                    version=3,
                    sequence=4,
                    deleted=True,
                    purged=False,
                    updated=100,
                ),
                Revision(item_id=item_id, version=2, payload=envelope()),
                Team(id=team_id, name="Retention team", owner_id=owner_id, sequence=7),
                TeamItem(
                    id=team_item_id,
                    team_id=team_id,
                    payload=envelope(),
                    version=5,
                    sequence=7,
                    deleted=True,
                    purged=False,
                    updated=100,
                ),
                TeamRevision(item_id=team_item_id, version=4, payload=envelope()),
                Share(
                    id=old_share_id,
                    sender_id=owner_id,
                    recipient_id=recipient_id,
                    wrapped_key="wrapped",
                    payload=envelope(),
                    expires=100,
                ),
                Share(
                    id=recent_share_id,
                    sender_id=owner_id,
                    recipient_id=recipient_id,
                    wrapped_key="wrapped",
                    payload=envelope(),
                    expires=current - 3600,
                ),
            ]
        )

    with factory.begin() as session:
        with (
            patch.object(settings, "trash_retention_days", 1),
            patch.object(settings, "expired_share_retention_days", 1),
        ):
            result = cleanup_session(session, current_time=current)

        item = session.get(Item, item_id)
        team_item = session.get(TeamItem, team_item_id)
        vault = session.get(Vault, vault_id)
        team = session.get(Team, team_id)

        assert result == {
            "personal_trash_purged": 1,
            "team_trash_purged": 1,
            "expired_shares_deleted": 1,
        }
        assert item is not None and item.purged is True and item.payload == {}
        assert item.version == 4 and item.sequence == 5 and item.updated == current
        assert vault is not None and vault.sequence == 5
        assert session.scalar(select(Revision).where(Revision.item_id == item_id)) is None

        assert team_item is not None and team_item.purged is True and team_item.payload == {}
        assert team_item.version == 6 and team_item.sequence == 8 and team_item.updated == current
        assert team is not None and team.sequence == 8
        assert (
            session.scalar(select(TeamRevision).where(TeamRevision.item_id == team_item_id)) is None
        )

        assert session.get(Share, old_share_id) is None
        assert session.get(Share, recent_share_id) is not None

    engine.dispose()
