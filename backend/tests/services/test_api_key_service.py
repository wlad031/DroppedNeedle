from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
import pytest_asyncio

from infrastructure.persistence.api_key_store import ApiKeyStore
from infrastructure.persistence.auth_store import AuthStore
from services.api_key_service import ApiKeyService


@pytest_asyncio.fixture
async def service(tmp_path: Path):
    db = tmp_path / "api-keys.sqlite"
    auth = AuthStore(db)
    # AuthStore.delete_user also removes the legacy playlists table before the
    # FK cascade; production initialization creates it, so mirror that minimum
    # prerequisite in this isolated persistence test.
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS playlists (id TEXT PRIMARY KEY, user_id TEXT)")
    await auth.create_user(id="user", display_name="User", role="user")
    return ApiKeyService(ApiKeyStore(db), auth), auth, db


@pytest.mark.asyncio
async def test_key_is_one_time_hash_only_and_revocable(service):
    keys, _auth, db = service
    created = await keys.create("user", "automation", ["catalog:read"], None)
    assert created.key.startswith("dnk_")
    assert (await keys.verify(created.key))[0].id == "user"
    with sqlite3.connect(db) as conn:
        stored = conn.execute("SELECT secret_hash FROM auth_api_keys").fetchone()[0]
    assert created.key not in stored
    await keys.revoke("user", created.api_key.id)
    assert await keys.verify(created.key) is None


@pytest.mark.asyncio
async def test_user_deletion_cascades_api_keys(service):
    keys, auth, db = service
    created = await keys.create("user", "automation", ["catalog:read"], None)
    assert await auth.delete_user("user")
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM auth_api_keys").fetchone()[0] == 0
    assert await keys.verify(created.key) is None


@pytest.mark.asyncio
async def test_rejects_empty_or_unknown_scopes(service):
    keys, _auth, _db = service
    with pytest.raises(ValueError):
        await keys.create("user", "bad", [], None)
    with pytest.raises(ValueError):
        await keys.create("user", "bad", ["admin:all"], None)
