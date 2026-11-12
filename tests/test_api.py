"""API tests against a throwaway SQLite database (no network, no real secrets)."""
import importlib
import os

import pytest
from fastapi.testclient import TestClient

ADMIN_PASSWORD = "admin-password-123"
USER_PASSWORD = "user-password-1234"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("JWT_SECRET", "t" * 48)
    monkeypatch.setenv("ADMIN_PASSWORD", ADMIN_PASSWORD)
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5173")
    import main
    importlib.reload(main)
    return TestClient(main.app)


def login(client, username, password):
    r = client.post("/api/login", json={"username": username, "password": password})
    return r


def auth(client, username, password):
    token = login(client, username, password).json()["token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def setup(client):
    admin = auth(client, "admin", ADMIN_PASSWORD)
    client.post("/api/users", json={"username": "alice", "password": USER_PASSWORD}, headers=admin)
    client.post("/api/users", json={"username": "bob", "password": USER_PASSWORD}, headers=admin)
    users = {u["username"]: u["id"] for u in client.get("/api/users", headers=admin).json()}
    folder = client.post("/api/folders", json={"name": "prod", "allowed_user_ids": [users["alice"]]}, headers=admin).json()["id"]
    return admin, auth(client, "alice", USER_PASSWORD), auth(client, "bob", USER_PASSWORD), folder


def test_login_wrong_password_and_unknown_user(client):
    assert login(client, "admin", "nope").status_code == 401
    assert login(client, "ghost", "nope").status_code == 401


def test_endpoints_require_token(client):
    assert client.get("/api/folders").status_code == 401
    assert client.get("/api/users").status_code == 401
    assert client.post("/api/iamhere").status_code == 401


def test_forged_role_query_param_does_not_grant_admin(client, setup):
    _, alice, _, folder = setup
    # the old API trusted ?role=admin from the client; it must be ignored now
    assert client.delete("/api/items/1?role=admin", headers=alice).status_code == 403


def test_non_admin_cannot_manage_users_or_folders(client, setup):
    _, alice, _, _ = setup
    assert client.post("/api/users", json={"username": "evil", "password": USER_PASSWORD}, headers=alice).status_code == 403
    assert client.post("/api/folders", json={"name": "x", "allowed_user_ids": []}, headers=alice).status_code == 403


def test_folder_access_is_enforced(client, setup):
    admin, alice, bob, folder = setup
    assert [f["id"] for f in client.get("/api/folders", headers=alice).json()] == [folder]
    assert client.get("/api/folders", headers=bob).json() == []
    assert client.get(f"/api/folders/{folder}/items", headers=bob).status_code == 404
    r = client.post("/api/encrypt", json={"server_name": "db", "password": "s3cret", "master_password": "master-pass-1", "folder_id": folder}, headers=bob)
    assert r.status_code == 404


def test_encrypt_list_decrypt_flow_never_leaks_ciphertext(client, setup):
    _, alice, bob, folder = setup
    r = client.post("/api/encrypt", json={"server_name": "db", "password": "s3cret", "master_password": "master-pass-1", "folder_id": folder}, headers=alice)
    assert r.status_code == 201
    items = client.get(f"/api/folders/{folder}/items", headers=alice).json()
    assert items == [{"id": items[0]["id"], "server_name": "db"}]
    item_id = items[0]["id"]
    ok = client.post("/api/decrypt", json={"item_id": item_id, "master_password": "master-pass-1"}, headers=alice)
    assert ok.json() == {"password": "s3cret"}
    bad = client.post("/api/decrypt", json={"item_id": item_id, "master_password": "wrong-master"}, headers=alice)
    assert bad.status_code == 400
    # a user without folder access cannot decrypt even with the right master password
    denied = client.post("/api/decrypt", json={"item_id": item_id, "master_password": "master-pass-1"}, headers=bob)
    assert denied.status_code == 404


def test_users_listing_has_no_password_fields(client, setup):
    admin, *_ = setup
    for u in client.get("/api/users", headers=admin).json():
        assert set(u) == {"id", "username", "role"}


def test_weak_user_password_rejected(client, setup):
    admin, *_ = setup
    assert client.post("/api/users", json={"username": "carol", "password": "short"}, headers=admin).status_code == 422
