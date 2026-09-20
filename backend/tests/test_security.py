import base64
import uuid
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request

from app.security import rate_limit


def envelope():
    return {
        "v": 1,
        "nonce": base64.b64encode(b"n" * 12).decode(),
        "ciphertext": base64.b64encode(b"c" * 48).decode(),
    }


def register(client, email="test@example.com"):
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
        "device": "Test device",
    }
    result = client.post("/auth/register", json=body)
    assert result.status_code == 201, result.text
    return body, result.json(), {"Authorization": "Bearer " + result.json()["access_token"]}


def test_ownership_and_conflict(client):
    body, _, auth = register(client)
    _, _, other = register(client, "other@example.com")
    path = f"/vaults/{body['vault_id']}/items/{uuid.uuid4()}"
    data = {"expected_version": 0, "payload": envelope(), "deleted": False}
    assert client.put(path, json=data, headers=other).status_code == 404
    first = client.put(path, json=data, headers=auth)
    assert first.status_code == 200, first.text
    assert first.json()["version"] == 1
    assert client.put(path, json=data, headers=auth).status_code == 200  # lost-response retry
    changed = {**data, "deleted": True}
    assert client.put(path, json=changed, headers=auth).status_code == 409
    data["expected_version"] = 1
    assert client.put(path, json=data, headers=auth).status_code == 200
    history = client.get(path + "/history", headers=auth).json()
    assert len(history) == 1 and history[0]["version"] == 1
    assert client.get(path + "/history", headers=other).status_code == 404
    sync = client.get(f"/vaults/{body['vault_id']}/sync", headers=auth).json()
    assert sync["cursor"] == 2 and len(sync["items"]) == 1
    assert (
        client.get(f"/vaults/{body['vault_id']}/sync?after=2", headers=auth).json()["items"] == []
    )


def test_refresh_rotation_replay_revokes_family(client):
    _, session, auth = register(client)
    rotated = client.post("/auth/refresh", json={"token": session["refresh_token"]})
    assert rotated.status_code == 200
    assert client.get("/vaults", headers=auth).status_code == 401
    new_auth = {"Authorization": "Bearer " + rotated.json()["access_token"]}
    assert client.get("/vaults", headers=new_auth).status_code == 200
    assert client.post("/auth/refresh", json={"token": session["refresh_token"]}).status_code == 401
    assert client.get("/vaults", headers=new_auth).status_code == 401
    assert (
        client.post("/auth/refresh", json={"token": rotated.json()["refresh_token"]}).status_code
        == 401
    )


def test_revocation_and_device_authorization(client):
    _, session, auth = register(client)
    _, _, other = register(client, "other@example.com")
    path = "/devices/" + session["session_id"]
    assert client.delete(path, headers=other).status_code == 404
    assert client.delete(path, headers=auth).status_code == 200
    assert client.get("/vaults", headers=auth).status_code == 401


def test_password_change_revokes_sessions_and_preserves_vault(client):
    body, _, auth = register(client)
    new_bundle = {**body["bundle"], "salt": "c" * 32}
    result = client.post(
        "/account/password",
        json={"current_auth_secret": "a" * 64, "auth_secret": "d" * 64, "bundle": new_bundle},
        headers=auth,
    )
    assert result.status_code == 200
    assert client.get("/vaults", headers=auth).status_code == 401
    assert (
        client.post(
            "/auth/login", json={"email": body["email"], "auth_secret": "a" * 64}
        ).status_code
        == 401
    )
    login = client.post("/auth/login", json={"email": body["email"], "auth_secret": "d" * 64})
    assert login.status_code == 200 and login.json()["bundle"] == new_bundle
    assert (
        client.get(
            "/vaults", headers={"Authorization": "Bearer " + login.json()["access_token"]}
        ).json()[0]["id"]
        == body["vault_id"]
    )


def test_plaintext_extra_fields_rejected_and_not_reflected(client):
    body, _, auth = register(client)
    secret = "NEVER_REFLECT_THIS_SECRET"
    result = client.put(
        f"/vaults/{body['vault_id']}/items/{uuid.uuid4()}",
        headers=auth,
        json={"expected_version": 0, "payload": envelope(), "password": secret},
    )
    assert result.status_code == 422 and secret not in result.text
    assert client.get("/vaults").status_code == 401
    assert (
        client.post(
            "/auth/lookup",
            json={"email": "test@example.com"},
            headers={"Origin": "https://evil.example"},
        ).status_code
        == 403
    )


def test_trash_purge_tombstone_and_account_deletion(client):
    body, _, auth = register(client)
    path = f"/vaults/{body['vault_id']}/items/{uuid.uuid4()}"
    assert (
        client.put(
            path, headers=auth, json={"expected_version": 0, "payload": envelope(), "deleted": True}
        ).status_code
        == 200
    )
    assert client.delete(path + "?expected_version=1", headers=auth).status_code == 200
    item = client.get(f"/vaults/{body['vault_id']}/sync", headers=auth).json()["items"][0]
    assert item["purged"] is True and item["payload"] == {}
    assert (
        client.post("/account/delete", headers=auth, json={"auth_secret": "f" * 64}).status_code
        == 401
    )
    assert (
        client.post("/account/delete", headers=auth, json={"auth_secret": "a" * 64}).status_code
        == 200
    )
    assert client.get("/vaults", headers=auth).status_code == 401


def test_redis_limit_and_fail_closed():
    import pytest
    from redis.exceptions import ConnectionError

    request = Request({"type": "http", "client": ("127.0.0.1", 1234), "headers": []})
    with patch("app.security.redis") as redis:
        redis.pipeline.return_value.__enter__.return_value.execute.return_value = [100, True]
        with pytest.raises(HTTPException) as exc:
            rate_limit(request)
        assert exc.value.status_code == 429
        redis.pipeline.side_effect = ConnectionError("unavailable")
        with pytest.raises(HTTPException) as exc:
            rate_limit(request)
        assert exc.value.status_code == 503


def test_sharing_authorization_expiry_and_revocation(client):
    import time

    from app.db import db
    from app.main import app
    from app.models import User

    sender, _, sender_auth = register(client)
    recipient, _, recipient_auth = register(client, "recipient@example.com")
    _, _, outsider = register(client, "outsider@example.com")
    session_generator = app.dependency_overrides[db]()
    session = next(session_generator)
    for user_id in [sender["id"], recipient["id"]]:
        session.get(User, uuid.UUID(user_id)).verified = True
    session.commit()
    session_generator.close()
    keys = {"public_key": base64.b64encode(b"p" * 384).decode(), "private_key": envelope()}
    assert client.post("/sharing/keys", json=keys, headers=recipient_auth).status_code == 200
    assert client.post("/sharing/keys", json=keys, headers=recipient_auth).status_code == 409
    found = client.post("/sharing/lookup", json={"email": recipient["email"]}, headers=sender_auth)
    assert found.status_code == 200 and found.json()["user_id"] == recipient["id"]
    share = {
        "id": str(uuid.uuid4()),
        "recipient_id": recipient["id"],
        "wrapped_key": base64.b64encode(b"w" * 384).decode(),
        "payload": envelope(),
        "expires": int(time.time()) + 3600,
    }
    assert (
        client.post("/shares", json={**share, "expires": 1}, headers=sender_auth).status_code == 422
    )
    assert client.post("/shares", json=share, headers=sender_auth).status_code == 201
    assert client.get("/shares", headers=outsider).json() == []
    assert "payload" in client.get("/shares", headers=recipient_auth).json()[0]
    assert client.delete("/shares/" + share["id"], headers=recipient_auth).status_code == 404
    assert client.delete("/shares/" + share["id"], headers=sender_auth).status_code == 200
    assert "payload" not in client.get("/shares", headers=recipient_auth).json()[0]
