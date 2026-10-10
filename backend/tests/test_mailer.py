from unittest.mock import MagicMock, patch

from app.config import settings
from app.mailer import deliver_email


def test_delivery_uses_tls_and_authentication_in_production(monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.com")
    monkeypatch.setattr(settings, "smtp_port", 587)
    monkeypatch.setattr(settings, "smtp_username", "vaultpass")
    monkeypatch.setattr(settings, "smtp_password", "secret")
    monkeypatch.setattr(settings, "mail_from", "VaultPass <security@example.com>")

    smtp = MagicMock()
    smtp.__enter__.return_value = smtp
    with patch("app.mailer.smtplib.SMTP", return_value=smtp) as smtp_factory:
        deliver_email("user@example.com", "Security alert", "No vault contents.")

    smtp_factory.assert_called_once_with("smtp.example.com", 587, timeout=15)
    smtp.starttls.assert_called_once()
    smtp.login.assert_called_once_with("vaultpass", "secret")
    smtp.send_message.assert_called_once()
    message = smtp.send_message.call_args.args[0]
    assert message["From"] == "VaultPass <security@example.com>"
    assert message["To"] == "user@example.com"
    assert message["Subject"] == "Security alert"
    assert "No vault contents." in message.get_content()


def test_delivery_skips_tls_and_login_for_local_mailpit(monkeypatch):
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "smtp_host", "mailpit")
    monkeypatch.setattr(settings, "smtp_port", 1025)
    monkeypatch.setattr(settings, "smtp_username", "")
    monkeypatch.setattr(settings, "smtp_password", "")

    smtp = MagicMock()
    smtp.__enter__.return_value = smtp
    with patch("app.mailer.smtplib.SMTP", return_value=smtp):
        deliver_email("user@example.com", "Local test", "Body")

    smtp.starttls.assert_not_called()
    smtp.login.assert_not_called()
    smtp.send_message.assert_called_once()
