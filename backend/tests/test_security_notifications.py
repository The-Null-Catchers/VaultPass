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


def auth_headers(session):
    return {"Authorization": f"Bearer {session['access_token']}"}


def test_security_notification_preference_defaults_on_and_can_be_updated(client):
    _, session = register(client, "preferences@example.com")
    headers = auth_headers(session)

    current = client.get("/account/security-notifications", headers=headers)
    assert current.status_code == 200, current.text
    assert current.json() == {"new_device_email_enabled": True}

    updated = client.patch(
        "/account/security-notifications",
        headers=headers,
        json={"new_device_email_enabled": False},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json() == {"new_device_email_enabled": False}

    persisted = client.get("/account/security-notifications", headers=headers)
    assert persisted.status_code == 200, persisted.text
    assert persisted.json() == {"new_device_email_enabled": False}

    events = client.get("/events", headers=headers)
    assert events.status_code == 200, events.text
    assert any(row["event"] == "security_notifications_updated" for row in events.json())


def test_security_notification_preference_rejects_unknown_fields(client):
    _, session = register(client, "strict-preferences@example.com")
    result = client.patch(
        "/account/security-notifications",
        headers=auth_headers(session),
        json={"new_device_email_enabled": False, "unexpected": True},
    )
    assert result.status_code == 422


def test_additional_device_login_dispatches_security_email_after_commit(client):
    body, session = register(client)
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

    disabled = client.patch(
        "/account/security-notifications",
        headers=auth_headers(session),
        json={"new_device_email_enabled": False},
    )
    assert disabled.status_code == 200, disabled.text

    with patch("app.tasks.send_email.delay") as send:
        result = client.post("/auth/login", json={**login, "device": "Laptop"})
        assert result.status_code == 200, result.text
        send.assert_not_called()


def test_registration_first_session_does_not_dispatch_new_device_email(client):
    with patch("app.tasks.send_email.delay") as send:
        register(client, "first-session@example.com")
        send.assert_not_called()
