import smtplib
from email.message import EmailMessage

from celery import Celery
from sqlalchemy import delete

from .config import settings
from .db import SessionLocal
from .models import (
    Audit,
    DeviceSession,
    PasskeyChallenge,
    RecoveryAttempt,
    TeamRotationJob,
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


@celery.task
def cleanup():
    with SessionLocal.begin() as session:
        session.execute(delete(Verification).where(Verification.expires < now()))
        session.execute(delete(RecoveryAttempt).where(RecoveryAttempt.expires < now()))
        session.execute(delete(PasskeyChallenge).where(PasskeyChallenge.expires < now()))
        session.execute(delete(TeamRotationJob).where(TeamRotationJob.expires < now()))
        session.execute(delete(DeviceSession).where(DeviceSession.expires < now()))
        session.execute(
            delete(Audit).where(Audit.created < now() - settings.audit_retention_days * 86400)
        )
