from __future__ import annotations

"""Persistence for scoped REST API credentials.

Only a SHA-256 digest is retained; the plaintext is returned during creation and
never recoverable.  This intentionally stays separate from Connect Apps
passwords, whose encrypted secret is required by the Subsonic protocol.
"""

import sqlite3
import threading
from pathlib import Path

import msgspec

from infrastructure.persistence._database import PersistenceBase


class ApiKeyRow(msgspec.Struct, frozen=True):
    id: str
    user_id: str
    name: str
    secret_hash: str
    scopes_json: str
    created_at: str
    expires_at: str | None = None
    last_used_at: str | None = None
    revoked_at: str | None = None


class ApiKeyStore(PersistenceBase):
    foreign_keys = True

    def __init__(self, db_path: Path, write_lock: threading.Lock | None = None) -> None:
        super().__init__(db_path, write_lock or threading.Lock())

    def _ensure_tables(self) -> None:
        conn = self._connect()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS auth_api_keys (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    secret_hash TEXT NOT NULL UNIQUE,
                    scopes_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    last_used_at TEXT,
                    revoked_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_auth_api_keys_user ON auth_api_keys(user_id);
                CREATE INDEX IF NOT EXISTS idx_auth_api_keys_active ON auth_api_keys(id, expires_at)
                    WHERE revoked_at IS NULL;
            """)
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _row(row: sqlite3.Row | None) -> ApiKeyRow | None:
        if row is None:
            return None
        return ApiKeyRow(
            id=str(row["id"]), user_id=str(row["user_id"]), name=str(row["name"]),
            secret_hash=str(row["secret_hash"]), scopes_json=str(row["scopes_json"]),
            created_at=str(row["created_at"]), expires_at=row["expires_at"],
            last_used_at=row["last_used_at"], revoked_at=row["revoked_at"],
        )

    async def insert(self, row: ApiKeyRow) -> None:
        await self._write(lambda conn: conn.execute(
            "INSERT INTO auth_api_keys (id,user_id,name,secret_hash,scopes_json,created_at,expires_at,last_used_at,revoked_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (row.id,row.user_id,row.name,row.secret_hash,row.scopes_json,row.created_at,row.expires_at,row.last_used_at,row.revoked_at),
        ))

    async def get_active(self, key_id: str, now: str) -> ApiKeyRow | None:
        return await self._read(lambda conn: self._row(conn.execute(
            "SELECT * FROM auth_api_keys WHERE id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)",
            (key_id, now),
        ).fetchone()))

    async def list_active_for_user(self, user_id: str, now: str) -> list[ApiKeyRow]:
        def op(conn: sqlite3.Connection) -> list[ApiKeyRow]:
            rows = conn.execute("SELECT * FROM auth_api_keys WHERE user_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?) ORDER BY created_at DESC", (user_id, now)).fetchall()
            return [item for r in rows if (item := self._row(r)) is not None]
        return await self._read(op)

    async def revoke_owned(self, key_id: str, user_id: str, when: str) -> bool:
        return await self._write(lambda conn: conn.execute(
            "UPDATE auth_api_keys SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL", (when,key_id,user_id)
        ).rowcount > 0)

    async def revoke_any(self, key_id: str, when: str) -> bool:
        return await self._write(lambda conn: conn.execute(
            "UPDATE auth_api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL", (when,key_id)
        ).rowcount > 0)

    async def touch(self, key_id: str, when: str) -> None:
        await self._write(lambda conn: conn.execute("UPDATE auth_api_keys SET last_used_at = ? WHERE id = ?", (when,key_id)))
