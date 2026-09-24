import asyncio
import base64
import uuid
from types import SimpleNamespace
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


def test_recovery_key_is_one_time_and_revokes_sessions(client):
    body, _, auth = register(client)
    recovery = {
        "current_auth_secret": "a" * 64,
        "recovery_auth_secret": "e" * 64,
        "account_key": envelope(),
    }
    assert client.post("/account/recovery", json=recovery, headers=auth).status_code == 201
    from app.db import db
    from app.main import app
    from app.models import PasskeyCredential

    session_generator = app.dependency_overrides[db]()
    database = next(session_generator)
    database.add(
        PasskeyCredential(
            id="recovery-test-passkey",
            user_id=uuid.UUID(body["id"]),
            public_key="cHVibGljLWtleQ",
            name="Lost authenticator",
            transports=["internal"],
            aaguid="test",
            device_type="single_device",
        )
    )
    database.commit()
    session_generator.close()
    status = client.get("/account/recovery", headers=auth).json()
    assert status["enabled"] is True and len(status["context"]) == 64
    assert client.post("/account/recovery", json=recovery, headers=auth).status_code == 409
    lookup = client.post("/auth/recovery/lookup", json={"email": body["email"]})
    assert lookup.status_code == 200
    assert lookup.json() == {"context": status["context"], "account_key": recovery["account_key"]}
    new_bundle = {**body["bundle"], "salt": "c" * 32}
    verify = {"email": body["email"], "recovery_auth_secret": "e" * 64}
    assert (
        client.post(
            "/auth/recovery/verify", json={**verify, "recovery_auth_secret": "f" * 64}
        ).status_code
        == 401
    )
    challenge = client.post("/auth/recovery/verify", json=verify)
    assert challenge.status_code == 200 and challenge.json()["user_id"] == body["id"]
    stale = {
        "token": challenge.json()["token"],
        "auth_secret": "d" * 64,
        "bundle": new_bundle,
    }
    assert (
        client.request(
            "DELETE", "/account/recovery", headers=auth, json={"auth_secret": "a" * 64}
        ).status_code
        == 200
    )
    assert client.post("/account/recovery", json=recovery, headers=auth).status_code == 201
    assert client.post("/auth/recovery/complete", json=stale).status_code == 401
    challenge = client.post("/auth/recovery/verify", json=verify)
    assert challenge.status_code == 200
    complete = {
        "token": challenge.json()["token"],
        "auth_secret": "d" * 64,
        "bundle": new_bundle,
    }
    result = client.post("/auth/recovery/complete", json=complete)
    assert result.status_code == 200 and result.json()["recovery_key_consumed"] is True
    assert client.get("/vaults", headers=auth).status_code == 401
    assert (
        client.post(
            "/auth/login", json={"email": body["email"], "auth_secret": "a" * 64}
        ).status_code
        == 401
    )
    recovered_login = client.post(
        "/auth/login", json={"email": body["email"], "auth_secret": "d" * 64}
    )
    assert recovered_login.status_code == 200 and "access_token" in recovered_login.json()
    recovered_auth = {"Authorization": "Bearer " + recovered_login.json()["access_token"]}
    assert client.get("/account/passkeys", headers=recovered_auth).json() == []
    assert client.post("/auth/recovery/complete", json=complete).status_code == 401
    fake = client.post("/auth/recovery/lookup", json={"email": "missing@example.com"}).json()
    assert set(fake) == {"context", "account_key"} and len(fake["context"]) == 64
    assert (
        fake["context"]
        == client.post("/auth/recovery/lookup", json={"email": "missing@example.com"}).json()[
            "context"
        ]
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


def test_request_boundary_and_security_headers(client):
    from app.config import settings
    from app.main import headers

    health = client.get("/health")
    assert health.status_code == 200
    assert health.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"
    assert client.get("/health", headers={"Host": "evil.example"}).status_code == 400
    too_large = client.post(
        "/auth/lookup",
        content=b"{}",
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(settings.max_request_bytes + 1),
        },
    )
    assert too_large.status_code == 413

    async def oversized_chunk():
        return {
            "type": "http.request",
            "body": b"x" * (settings.max_request_bytes + 1),
            "more_body": False,
        }

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "headers": [(b"transfer-encoding", b"chunked")],
            "client": ("127.0.0.1", 1),
        },
        oversized_chunk,
    )
    chunked = asyncio.run(headers(request, None))
    assert chunked.status_code == 413


def test_resource_caps_preserve_existing_access(client):
    from app.config import settings
    from app.db import db
    from app.main import app
    from app.models import PasskeyCredential

    with patch.object(settings, "max_vault_items", 1):
        body, _, auth = register(client)
        first_id, second_id = uuid.uuid4(), uuid.uuid4()
        first_path = f"/vaults/{body['vault_id']}/items/{first_id}"
        payload = {"expected_version": 0, "payload": envelope(), "deleted": False}
        assert client.put(first_path, json=payload, headers=auth).status_code == 200
        assert (
            client.put(
                f"/vaults/{body['vault_id']}/items/{second_id}", json=payload, headers=auth
            ).status_code
            == 409
        )
        assert (
            client.put(
                first_path, json={**payload, "expected_version": 1}, headers=auth
            ).status_code
            == 200
        )

    with patch.object(settings, "max_active_sessions", 2):
        _, original, original_auth = register(client, "sessions@example.com")
        login_body = {
            "email": "sessions@example.com",
            "auth_secret": "a" * 64,
            "device": "Additional device",
        }
        second = client.post("/auth/login", json=login_body).json()
        third = client.post("/auth/login", json=login_body).json()
        third_auth = {"Authorization": "Bearer " + third["access_token"]}
        sessions = client.get("/devices", headers=third_auth).json()
        assert len([row for row in sessions if not row["revoked"]]) == 2
        assert len([row for row in sessions if row["revoked"]]) == 1
        assert client.get("/vaults", headers=third_auth).status_code == 200
        old_auths = [original_auth, {"Authorization": "Bearer " + second["access_token"]}]
        assert (
            sum(client.get("/vaults", headers=value).status_code == 401 for value in old_auths) == 1
        )
        assert original["session_id"] in {row["id"] for row in sessions}

    passkey_body, _, passkey_auth = register(client, "passkey-cap@example.com")
    session_generator = app.dependency_overrides[db]()
    database = next(session_generator)
    database.add(
        PasskeyCredential(
            id="quota-passkey",
            user_id=uuid.UUID(passkey_body["id"]),
            public_key="cHVibGljLWtleQ",
            name="Existing passkey",
            transports=["internal"],
            aaguid="test",
            device_type="single_device",
        )
    )
    database.commit()
    session_generator.close()
    with patch.object(settings, "max_passkeys", 1):
        result = client.post(
            "/account/passkeys/options",
            json={"current_auth_secret": "a" * 64, "name": "One too many"},
            headers=passkey_auth,
        )
    assert result.status_code == 409 and result.json()["detail"] == "Passkey limit reached"


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


def test_passkey_enrollment_login_replay_and_removal(client):
    body, _, auth = register(client)
    begin_body = {"current_auth_secret": "a" * 64, "name": "Test passkey"}
    assert (
        client.post(
            "/account/passkeys/options",
            json={**begin_body, "current_auth_secret": "f" * 64},
            headers=auth,
        ).status_code
        == 401
    )
    begin = client.post("/account/passkeys/options", json=begin_body, headers=auth)
    assert begin.status_code == 201
    assert begin.json()["public_key"]["user"]["name"] == body["email"]
    raw_id = base64.urlsafe_b64encode(b"test-credential-id").rstrip(b"=").decode()
    registration = {
        "id": raw_id,
        "rawId": raw_id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": base64.urlsafe_b64encode(b"client-data-json").decode(),
            "attestationObject": base64.urlsafe_b64encode(b"attestation-object").decode(),
            "transports": ["internal"],
        },
    }
    verified_registration = SimpleNamespace(
        credential_id=b"test-credential-id",
        credential_public_key=b"credential-public-key",
        sign_count=0,
        aaguid="00000000-0000-0000-0000-000000000000",
        credential_device_type=SimpleNamespace(value="single_device"),
        credential_backed_up=False,
    )
    with patch("app.main.verify_registration_response", return_value=verified_registration):
        enrolled = client.post(
            "/account/passkeys",
            json={"token": begin.json()["token"], "credential": registration},
            headers=auth,
        )
    assert enrolled.status_code == 201, enrolled.text
    passkeys = client.get("/account/passkeys", headers=auth).json()
    assert len(passkeys) == 1 and passkeys[0]["name"] == "Test passkey"

    first = client.post("/auth/login", json={"email": body["email"], "auth_secret": "a" * 64})
    assert first.status_code == 200
    assert first.json()["mfa_required"] is True and "access_token" not in first.json()
    assertion = {
        "id": raw_id,
        "rawId": raw_id,
        "type": "public-key",
        "response": {
            "clientDataJSON": base64.urlsafe_b64encode(b"client-data-json").decode(),
            "authenticatorData": base64.urlsafe_b64encode(b"authenticator-data").decode(),
            "signature": base64.urlsafe_b64encode(b"credential-signature").decode(),
            "userHandle": None,
        },
    }
    verified_authentication = SimpleNamespace(
        new_sign_count=1,
        credential_device_type=SimpleNamespace(value="single_device"),
        credential_backed_up=False,
    )
    with patch("app.main.verify_authentication_response", return_value=verified_authentication):
        completed = client.post(
            "/auth/passkey/complete",
            json={"token": first.json()["token"], "credential": assertion},
        )
    assert completed.status_code == 200 and "access_token" in completed.json()
    assert (
        client.post(
            "/auth/passkey/complete",
            json={"token": first.json()["token"], "credential": assertion},
        ).status_code
        == 401
    )
    assert (
        client.request(
            "DELETE",
            "/account/passkeys/" + raw_id,
            headers=auth,
            json={"auth_secret": "f" * 64},
        ).status_code
        == 401
    )
    assert (
        client.request(
            "DELETE",
            "/account/passkeys/" + raw_id,
            headers=auth,
            json={"auth_secret": "a" * 64},
        ).status_code
        == 200
    )


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
