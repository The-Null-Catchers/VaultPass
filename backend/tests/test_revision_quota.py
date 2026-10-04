import base64
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from app.config import settings
from app.db import db
from app.main import app
from app.models import User
from app.revision_quota import _retained_bytes_after_item_cap


def envelope(size: int = 48):
    return {
        "v": 1,
        "nonce": base64.b64encode(b"n" * 12).decode(),
        "ciphertext": base64.b64encode(b"c" * size).decode(),
    }


def register(client, email: str):
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
        "device": "Revision quota test",
    }
    response = client.post("/auth/register", json=body)
    assert response.status_code == 201, response.text
    auth = {"Authorization": "Bearer " + response.json()["access_token"]}
    return body, auth


def enable_sharing(client, body, auth):
    session_generator = app.dependency_overrides[db]()
    database = next(session_generator)
    user = database.get(User, uuid.UUID(body["id"]))
    assert user is not None
    user.verified = True
    database.commit()
    session_generator.close()
    response = client.post(
        "/sharing/keys",
        headers=auth,
        json={"public_key": "A" * 128, "private_key": envelope()},
    )
    assert response.status_code == 200, response.text


def test_personal_revision_ciphertext_quota_blocks_history_growth(client):
    body, auth = register(client, "revision-personal@example.com")
    item_id = uuid.uuid4()
    path = f"/vaults/{body['vault_id']}/items/{item_id}"
    first = {"expected_version": 0, "payload": envelope(), "deleted": False}
    assert client.put(path, headers=auth, json=first).status_code == 200

    with patch.object(settings, "max_vault_revision_ciphertext_bytes", 47):
        rejected = client.put(
            path,
            headers=auth,
            json={**first, "expected_version": 1},
        )

    assert rejected.status_code == 409
    assert rejected.json()["detail"] == "Vault revision ciphertext quota reached"
    history = client.get(path + "/history", headers=auth)
    assert history.status_code == 200 and history.json() == []


def test_team_revision_ciphertext_quota_blocks_history_growth(client):
    owner, owner_auth = register(client, "revision-team@example.com")
    enable_sharing(client, owner, owner_auth)
    team_id = uuid.uuid4()
    created = client.post(
        "/teams",
        headers=owner_auth,
        json={"id": str(team_id), "name": "Revision quota", "wrapped_key": "B" * 512},
    )
    assert created.status_code == 201, created.text

    item_id = uuid.uuid4()
    path = f"/teams/{team_id}/items/{item_id}"
    first = {
        "expected_key_version": 1,
        "expected_version": 0,
        "payload": envelope(),
        "deleted": False,
    }
    assert client.put(path, headers=owner_auth, json=first).status_code == 200

    with patch.object(settings, "max_vault_revision_ciphertext_bytes", 47):
        rejected = client.put(
            path,
            headers=owner_auth,
            json={**first, "expected_version": 1},
        )

    assert rejected.status_code == 409
    assert rejected.json()["detail"] == "Team vault revision ciphertext quota reached"
    history = client.get(path + "/history", headers=owner_auth)
    assert history.status_code == 200 and history.json() == []


def test_projection_applies_existing_twenty_revision_retention_cap():
    item_id = uuid.uuid4()
    rows = [
        SimpleNamespace(item_id=item_id, version=version, payload=envelope(10))
        for version in range(1, 21)
    ]
    pending = [SimpleNamespace(item_id=item_id, version=21, payload=envelope(12))]

    projected = _retained_bytes_after_item_cap(rows, pending, {item_id})

    assert projected == 12 + 19 * 10
