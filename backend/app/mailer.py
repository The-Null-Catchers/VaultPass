import smtplib
import ssl
from email.message import EmailMessage

from .config import settings


def deliver_email(recipient: str, subject: str, body: str) -> None:
    """Deliver one transactional account email without logging message contents."""
    message = EmailMessage()
    message["From"] = settings.mail_from
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
        if settings.environment == "production":
            smtp.starttls(context=ssl.create_default_context())
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)
