import base64
import uuid

import pytest
from fastapi import HTTPException

from app.db import db
from app.main import app
from app.models import Item, PersonalVaultRotationJob, Revision, Vault
from app.personal_rotation import (
    finalize_rotation,
    get_rotation,
    rotation_progress,
    stage_item,
    start_rotation,
    validate_personal_write_epoch,
)


def envelope(byte: bytes = b"c"):
    return {
        "v": 1,
        "nonce": base64.b64encode(b"n" * 12).decode(),
        "ciphertext": base64.b64encode(byte * 48).decode(),
    }


def register(client):
    body = {
        "id": str(uuid.uuid4()),
        "email": "rotation@example.com",
        "auth_secret": "a" * 64,
        "bundle": {
            "salt": "b" * 32,
            "profile": "argon2id-m65536-t3-p4-v1",
            "account_key": envelope(),
        },
        "vault_id": str(uuid.uuid4()),
        "wrapped_vault_key": envelope(b"w"),
        "device": "Rotation test",
    }
    result = client.post("/auth/register", json=body)
    assert result.status_code == 201, result.text
    auth = {"Authorization": "Bearer " + result.json()["access_token"]}
    return body, auth


def session_from_fixture():
    session_generator = app.dependency_overrides[db]()
    database = next(session_generator)
    return session_generator, database


def test_staged_rotation_replaces_all_current_ciphertext_atomically(client):
    body, auth = register(client)
    item_id = uuid.uuid4()
    item_path = f"/vaults/{body['vault_id']}/items/{item_id}"
    assert (
        client.put(
            item_path,
            headers=auth,
            json={"expected_version": 0, "payload": envelope(b"o"), "deleted": False},
        ).status_code
        == 200
    )

    session_generator, database = session_from_fixture()
    try:
        vault = database.get(Vault, uuid.UUID(body["vault_id"]))
        assert vault is not None and vault.key_version == 1
        rotation_id = uuid.uuid4()
        job = start_rotation(
            database,
            vault,
            uuid.UUID(body["id"]),
            rotation_id,
            1,
            envelope(b"k"),
        )
        progress = rotation_progress(database, vault, job)
        assert progress["new_key_version"] == 2
        assert progress["uploaded_items"] == 0
        assert progress["required_items"] == [{"id": str(item_id), "version": 1, "deleted": False}]

        stage_item(database, vault, job, item_id, 1, envelope(b"r"))
        assert rotation_progress(database, vault, job)["complete"] is True
        result = finalize_rotation(
            database, vault, get_rotation(database, vault, rotation_id, lock=True)
        )
        database.commit()

        assert result["key_version"] == 2
        assert result["rotated_items"] == 1
        assert vault.key_version == 2
        assert vault.wrapped_key == envelope(b"k")
        item = database.get(Item, item_id)
        assert item is not None
        assert item.version == 2
        assert item.payload == envelope(b"r")
        assert database.get(PersonalVaultRotationJob, rotation_id) is None
        assert list(database.query(Revision).filter(Revision.item_id == item_id)) == []
    finally:
        session_generator.close()


def test_rotation_detects_item_changed_after_staging(client):
    body, auth = register(client)
    item_id = uuid.uuid4()
    item_path = f"/vaults/{body['vault_id']}/items/{item_id}"
    assert (
        client.put(
            item_path,
            headers=auth,
            json={"expected_version": 0, "payload": envelope(b"1"), "deleted": False},
        ).status_code
        == 200
    )

    session_generator, database = session_from_fixture()
    try:
        vault = database.get(Vault, uuid.UUID(body["vault_id"]))
        assert vault is not None
        rotation_id = uuid.uuid4()
        job = start_rotation(
            database,
            vault,
            uuid.UUID(body["id"]),
            rotation_id,
            1,
            envelope(b"k"),
        )
        stage_item(database, vault, job, item_id, 1, envelope(b"2"))
        database.commit()
    finally:
        session_generator.close()

    assert (
        client.put(
            item_path,
            headers=auth,
            json={"expected_version": 1, "payload": envelope(b"3"), "deleted": False},
        ).status_code
        == 200
    )

    session_generator, database = session_from_fixture()
    try:
        vault = database.get(Vault, uuid.UUID(body["vault_id"]))
        assert vault is not None
        job = get_rotation(database, vault, rotation_id, lock=True)
        with pytest.raises(HTTPException) as exc:
            finalize_rotation(database, vault, job)
        assert exc.value.status_code == 409
        database.rollback()
        assert database.get(Vault, vault.id).key_version == 1
    finally:
        session_generator.close()


def test_personal_rotation_api_rotates_and_enforces_epoch(client):
    body, auth = register(client)
    vault_id = body["vault_id"]
    item_id = uuid.uuid4()
    item_path = f"/vaults/{vault_id}/items/{item_id}"
    create = client.put(
        item_path,
        headers=auth,
        json={"expected_version": 0, "payload": envelope(b"o"), "deleted": False},
    )
    assert create.status_code == 200, create.text

    vaults = client.get("/vaults", headers=auth)
    assert vaults.status_code == 200
    assert vaults.json() == [
        {"id": vault_id, "wrapped_key": body["wrapped_vault_key"], "key_version": 1}
    ]

    rotation_id = str(uuid.uuid4())
    start = client.post(
        f"/vaults/{vault_id}/rotations",
        headers=auth,
        json={
            "id": rotation_id,
            "expected_key_version": 1,
            "wrapped_key": envelope(b"k"),
        },
    )
    assert start.status_code == 201, start.text
    assert start.json()["new_key_version"] == 2
    assert start.json()["required_items"] == [
        {"id": str(item_id), "version": 1, "deleted": False}
    ]

    listed = client.get(f"/vaults/{vault_id}/rotations", headers=auth)
    assert listed.status_code == 200
    assert [row["id"] for row in listed.json()] == [rotation_id]

    staged = client.put(
        f"/vaults/{vault_id}/rotations/{rotation_id}/items/{item_id}",
        headers=auth,
        json={"expected_version": 1, "payload": envelope(b"r")},
    )
    assert staged.status_code == 200, staged.text

    status = client.get(f"/vaults/{vault_id}/rotations/{rotation_id}", headers=auth)
    assert status.status_code == 200
    assert status.json()["complete"] is True

    finalized = client.post(
        f"/vaults/{vault_id}/rotations/{rotation_id}/finalize",
        headers=auth,
    )
    assert finalized.status_code == 200, finalized.text
    assert finalized.json()["key_version"] == 2
    assert finalized.json()["rotated_items"] == 1

    sync = client.get(f"/vaults/{vault_id}/sync", headers=auth)
    assert sync.status_code == 200
    assert sync.json()["key_version"] == 2
    assert sync.json()["items"][0]["payload"] == envelope(b"r")
    assert client.get(f"/vaults/{vault_id}/rotations", headers=auth).json() == []

    stale = client.put(
        item_path,
        headers=auth,
        json={
            "expected_version": 2,
            "expected_key_version": 1,
            "payload": envelope(b"s"),
            "deleted": False,
        },
    )
    assert stale.status_code == 409

    missing_epoch = client.put(
        item_path,
        headers=auth,
        json={"expected_version": 2, "payload": envelope(b"s"), "deleted": False},
    )
    assert missing_epoch.status_code == 409

    current = client.put(
        item_path,
        headers=auth,
        json={
            "expected_version": 2,
            "expected_key_version": 2,
            "payload": envelope(b"s"),
            "deleted": False,
        },
    )
    assert current.status_code == 200, current.text


def test_personal_rotation_api_can_cancel(client):
    body, auth = register(client)
    rotation_id = str(uuid.uuid4())
    path = f"/vaults/{body['vault_id']}/rotations/{rotation_id}"
    started = client.post(
        f"/vaults/{body['vault_id']}/rotations",
        headers=auth,
        json={
            "id": rotation_id,
            "expected_key_version": 1,
            "wrapped_key": envelope(b"k"),
        },
    )
    assert started.status_code == 201, started.text
    assert client.delete(path, headers=auth).status_code == 200
    assert client.get(path, headers=auth).status_code == 404


def test_old_clients_are_rejected_after_first_rotation_epoch():
    vault = Vault(
        id=uuid.uuid4(),
        owner_id=uuid.uuid4(),
        wrapped_key=envelope(),
        key_version=2,
    )
    with pytest.raises(HTTPException) as missing:
        validate_personal_write_epoch(vault, None)
    assert missing.value.status_code == 409
    with pytest.raises(HTTPException) as stale:
        validate_personal_write_epoch(vault, 1)
    assert stale.value.status_code == 409
    validate_personal_write_epoch(vault, 2)
