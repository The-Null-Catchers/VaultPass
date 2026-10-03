import smtplib
from email.message import EmailMessage

from celery import Celery
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import settings
from .db import SessionLocal
from .models import (
    Audit,
    DeviceSession,
    Item,
    PasskeyChallenge,
    RecoveryAttempt,
    Revision,
    Share,
    Team,
    TeamItem,
    TeamRevision,
    TeamRotationJob,
    Vault,
    Verification,
    now,
)

celery = Celery("vaultpass", broker=settings.redis_url)
celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    worker_hijack_root_logger=False,
    beat_schedule={"expire-sessions": {"task": "app.tasks.cleanup", "schedule": 3600.0}},
)


@celery.task(autoretry_for=(OSError,), retry_backoff=True, max_retries=5)
def send_email(recipient: str, subject: str, body: str):
    # Only transactional account messages; never vault content. Do not log arguments.
    message = EmailMessage()
    message["From"] = settings.mail_from
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
        if settings.environment == "production":
            smtp.starttls()
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)


def cleanup_session(session: Session, current_time: int | None = None):
    current = current_time if current_time is not None else now()
    trash_cutoff = current - settings.trash_retention_days * 86400
    share_cutoff = current - settings.expired_share_retention_days * 86400

    personal_items = list(
        session.scalars(
            select(Item)
            .where(
                Item.deleted.is_(True),
                Item.purged.is_(False),
                Item.updated < trash_cutoff,
            )
            .order_by(Item.vault_id, Item.updated, Item.id)
            .with_for_update()
        )
    )
    for personal_item in personal_items:
        vault = session.scalar(
            select(Vault).where(Vault.id == personal_item.vault_id).with_for_update()
        )
        if vault is None:
            continue
        vault.sequence += 1
        personal_item.payload = {}
        personal_item.purged = True
        personal_item.sequence = vault.sequence
        personal_item.version += 1
        personal_item.updated = current
        session.execute(delete(Revision).where(Revision.item_id == personal_item.id))

    team_items = list(
        session.scalars(
            select(TeamItem)
            .where(
                TeamItem.deleted.is_(True),
                TeamItem.purged.is_(False),
                TeamItem.updated < trash_cutoff,
            )
            .order_by(TeamItem.team_id, TeamItem.updated, TeamItem.id)
            .with_for_update()
        )
    )
    for team_item in team_items:
        team = session.scalar(select(Team).where(Team.id == team_item.team_id).with_for_update())
        if team is None:
            continue
        team.sequence += 1
        team_item.payload = {}
        team_item.purged = True
        team_item.sequence = team.sequence
        team_item.version += 1
        team_item.updated = current
        session.execute(delete(TeamRevision).where(TeamRevision.item_id == team_item.id))

    expired_share_ids = list(session.scalars(select(Share.id).where(Share.expires < share_cutoff)))
    if expired_share_ids:
        session.execute(delete(Share).where(Share.id.in_(expired_share_ids)))
    return {
        "personal_trash_purged": len(personal_items),
        "team_trash_purged": len(team_items),
        "expired_shares_deleted": len(expired_share_ids),
    }


@celery.task
def cleanup():
    with SessionLocal.begin() as session:
        current = now()
        session.execute(delete(Verification).where(Verification.expires < current))
        session.execute(delete(RecoveryAttempt).where(RecoveryAttempt.expires < current))
        session.execute(delete(PasskeyChallenge).where(PasskeyChallenge.expires < current))
        session.execute(delete(TeamRotationJob).where(TeamRotationJob.expires < current))
        session.execute(delete(DeviceSession).where(DeviceSession.expires < current))
        cleanup_session(session, current)
        session.execute(
            delete(Audit).where(Audit.created < current - settings.audit_retention_days * 86400)
        )
