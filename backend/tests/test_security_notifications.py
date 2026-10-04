import base64
import uuid
from unittest.mock import patch


def envelope():
    return {
        "v": 1,
        "nonce": base64.b64encode(b"n" * 12).decode(),
        "ciphertext": base64.b64encode(b"c" * 48).decode(),
    }


def register(client, email="alerts@example.com"):
    body = {
        "id": str(uuid.uuid4()),
        "email": email,
        "auth_secret": "a" * 64,
        "bundle": {
            "salt": "b" * 32,
            "profile": "argon2id-m65536-t3-p4-v1",
            "account_key": envelope(),
        },
        "vault_id": str(uuid.uuid4()),
        "wrapped_vault_key": envelope(),
        "device": "First device",
    }
    result = client.post("/auth/register", json=body)
    assert result.status_code == 201, result.text
    return body, result.json()


def test_additional_device_login_dispatches_security_email_after_commit(client):
    from app.db import db
    from app.main import app
    from app.models import User

    body, _ = register(client)
    login = {
        "email": body["email"],
        "auth_secret": body["auth_secret"],
        "device": "Pixel 7",
    }

    with patch("app.tasks.send_email.delay") as send:
        result = client.post("/auth/login", json=login)
        assert result.status_code == 200, result.text
        send.assert_called_once()
        recipient, subject, message = send.call_args.args
        assert recipient == body["email"]
        assert subject == "New VaultPass sign-in"
        assert "Pixel 7" in message
        assert "vault contents" in message.lower()

    session_generator = app.dependency_overrides[db]()
    database = next(session_generator)
    user = database.get(User, uuid.UUID(body["id"]))
    assert user is not None
    user.new_device_email_enabled = False
    database.commit()
    session_generator.close()

    with patch("app.tasks.send_email.delay") as send:
        result = client.post("/auth/login", json={**login, "device": "Laptop"})
        assert result.status_code == 200, result.text
        send.assert_not_called()


def test_registration_first_session_does_not_dispatch_new_device_email(client):
    with patch("app.tasks.send_email.delay") as send:
        register(client, "first-session@example.com")
        send.assert_not_called()
