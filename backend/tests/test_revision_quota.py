import base64
import time
import uuid
from unittest.mock import patch

from app.config import settings


def envelope(byte: bytes = b"c"):
    return {
        "v": 1,
        "nonce": base64.b64encode(b"n" * 12).decode(),
        "ciphertext": base64.b64encode(byte * 48).decode(),
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
        "device": "Quota test",
    }
    response = client.post("/auth/register", json=body)
    assert response.status_code == 201, response.text
    auth = {"Authorization": "Bearer " + response.json()["access_token"]}
    return body, auth


def enable_sharing(client, body, auth):
    from app.db import db
    from app.main import app
    from app.models import User

    generator = app.dependency_overrides[db]()
    database = next(generator)
    user = database.get(User, uuid.UUID(body["id"]))
    assert user is not None
    user.verified = True
    database.commit()
    generator.close()
    response = client.post(
        "/sharing/keys",
        headers=auth,
        json={"public_key": "A" * 128, "private_key": envelope()},
    )
    assert response.status_code == 200, response.text


def test_personal_revision_history_consumes_ciphertext_quota(client):
    with patch.object(settings, "max_vault_ciphertext_bytes", 48):
        body, auth = register(client, "history-cap@example.com")
        path = f"/vaults/{body['vault_id']}/items/{uuid.uuid4()}"
        first = {
            "expected_version": 0,
            "payload": envelope(b"a"),
            "deleted": False,
        }
        assert client.put(path, json=first, headers=auth).status_code == 200

        # Replacing a 48-byte current ciphertext with another 48-byte ciphertext
        # used to pass the current-only check while silently retaining another
        # 48-byte encrypted revision. The history-aware guard must reject it.
        second = {
            "expected_version": 1,
            "payload": envelope(b"b"),
            "deleted": False,
        }
        rejected = client.put(path, json=second, headers=auth)
        assert rejected.status_code == 409
        assert rejected.json()["detail"] == "Vault ciphertext quota reached"
        assert client.get(path + "/history", headers=auth).json() == []


def test_personal_revision_window_credit_prevents_false_quota_growth(client):
    # One current payload plus 20 retained historical revisions is the maximum
    # steady-state footprint for one item. Once the window is full, replacing the
    # item should evict the oldest revision and keep storage flat.
    with patch.object(settings, "max_vault_ciphertext_bytes", 21 * 48):
        body, auth = register(client, "history-window@example.com")
        path = f"/vaults/{body['vault_id']}/items/{uuid.uuid4()}"
        payload = {
            "expected_version": 0,
            "payload": envelope(b"a"),
            "deleted": False,
        }
        assert client.put(path, json=payload, headers=auth).status_code == 200
        for version in range(1, 22):
            updated = {
                "expected_version": version,
                "payload": envelope(bytes([97 + (version % 20)])),
                "deleted": False,
            }
            response = client.put(path, json=updated, headers=auth)
            assert response.status_code == 200, response.text

        history = client.get(path + "/history", headers=auth)
        assert history.status_code == 200
        assert len(history.json()) == 20


def test_team_revision_history_consumes_ciphertext_quota(client):
    with patch.object(settings, "max_vault_ciphertext_bytes", 48):
        owner, owner_auth = register(client, "team-history-cap@example.com")
        enable_sharing(client, owner, owner_auth)
        team_id = uuid.uuid4()
        created = client.post(
            "/teams",
            headers=owner_auth,
            json={"id": str(team_id), "name": "Quota team", "wrapped_key": "B" * 512},
        )
        assert created.status_code == 201, created.text

        item_id = uuid.uuid4()
        path = f"/teams/{team_id}/items/{item_id}"
        first = {
            "expected_key_version": 1,
            "expected_version": 0,
            "payload": envelope(b"x"),
            "deleted": False,
        }
        assert client.put(path, json=first, headers=owner_auth).status_code == 200
        second = {
            **first,
            "expected_version": 1,
            "payload": envelope(b"y"),
        }
        rejected = client.put(path, json=second, headers=owner_auth)
        assert rejected.status_code == 409
        assert rejected.json()["detail"] == "Team vault ciphertext quota reached"
        assert client.get(path + "/history", headers=owner_auth).json() == []


def test_team_rotation_replacement_still_obeys_current_ciphertext_cap(client):
    # Regression coverage for the internal rotation path, which replaces current
    # TeamItem ciphertext without creating TeamRevision rows.
    owner, owner_auth = register(client, "rotation-quota-owner@example.com")
    member, member_auth = register(client, "rotation-quota-member@example.com")
    enable_sharing(client, owner, owner_auth)
    enable_sharing(client, member, member_auth)
    team_id = uuid.uuid4()
    assert (
        client.post(
            "/teams",
            headers=owner_auth,
            json={"id": str(team_id), "name": "Rotation quota", "wrapped_key": "B" * 512},
        ).status_code
        == 201
    )
    invitation_id = uuid.uuid4()
    assert (
        client.post(
            f"/teams/{team_id}/invitations",
            headers=owner_auth,
            json={
                "id": str(invitation_id),
                "recipient_id": member["id"],
                "role": "member",
                "wrapped_key": "C" * 512,
                "expected_key_version": 1,
                "expires": int(time.time()) + 3600,
            },
        ).status_code
        == 201
    )
    assert (
        client.post(f"/team-invitations/{invitation_id}/accept", headers=member_auth).status_code
        == 200
    )

    item_id = uuid.uuid4()
    path = f"/teams/{team_id}/items/{item_id}"
    first = {
        "expected_key_version": 1,
        "expected_version": 0,
        "payload": envelope(b"q"),
        "deleted": False,
    }
    assert client.put(path, json=first, headers=owner_auth).status_code == 200

    rotation_id = uuid.uuid4()
    rotation_path = f"/teams/{team_id}/rotations/{rotation_id}"
    assert (
        client.post(
            f"/teams/{team_id}/rotations",
            headers=owner_auth,
            json={
                "id": str(rotation_id),
                "target_id": member["id"],
                "expected_key_version": 1,
            },
        ).status_code
        == 201
    )
    assert (
        client.put(
            rotation_path + f"/members/{owner['id']}",
            headers=owner_auth,
            json={"wrapped_key": "D" * 512},
        ).status_code
        == 200
    )
    # Payload syntax allows larger ciphertext. Staging itself is not the final
    # write; finalization is where the current-vault cap must remain enforced.
    oversized = {
        "v": 1,
        "nonce": base64.b64encode(b"n" * 12).decode(),
        "ciphertext": base64.b64encode(b"z" * 96).decode(),
    }
    assert (
        client.put(
            rotation_path + f"/items/{item_id}",
            headers=owner_auth,
            json={"expected_version": 1, "payload": oversized},
        ).status_code
        == 200
    )
    with patch.object(settings, "max_vault_ciphertext_bytes", 48):
        finalized = client.post(rotation_path + "/finalize", headers=owner_auth)
    assert finalized.status_code == 409
    assert finalized.json()["detail"] == "Team vault ciphertext quota reached"
