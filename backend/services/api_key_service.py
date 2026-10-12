"""Scoped REST API-key lifecycle and verification."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from uuid import uuid4

import msgspec

from core.exceptions import ConflictError, PermissionDeniedError, ResourceNotFoundError
from infrastructure.persistence.api_key_store import ApiKeyRow, ApiKeyStore
from infrastructure.persistence.auth_store import AuthStore, UserRecord

KEY_PREFIX = "dnk"
MAX_ACTIVE_API_KEYS = 25
ALLOWED_SCOPES = frozenset({"catalog:read", "requests:read", "requests:write", "playlists:read", "playlists:write", "scrobble:write"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ApiKeyView(msgspec.Struct):
    id: str
    name: str
    scopes: list[str]
    created_at: str
    expires_at: str | None = None
    last_used_at: str | None = None


class ApiKeyCreated(msgspec.Struct):
    key: str
    api_key: ApiKeyView


class ApiKeyService:
    def __init__(self, store: ApiKeyStore, auth_store: AuthStore) -> None:
        self._store, self._auth_store = store, auth_store

    @staticmethod
    def _view(row: ApiKeyRow) -> ApiKeyView:
        return ApiKeyView(row.id, row.name, json.loads(row.scopes_json), row.created_at, row.expires_at, row.last_used_at)

    async def create(self, user_id: str, name: str, scopes: list[str], expires_at: str | None) -> ApiKeyCreated:
        normalized = sorted(set(scopes))
        if not normalized or not set(normalized).issubset(ALLOWED_SCOPES):
            raise ValueError("Invalid API key scopes")
        if expires_at is not None:
            try:
                parsed_expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                if parsed_expiry.tzinfo is None or parsed_expiry <= datetime.now(timezone.utc):
                    raise ValueError
                expires_at = parsed_expiry.astimezone(timezone.utc).isoformat()
            except (TypeError, ValueError):
                raise ValueError("Expiry must be an ISO-8601 timestamp in the future")
        if len(await self._store.list_active_for_user(user_id, _now())) >= MAX_ACTIVE_API_KEYS:
            raise ConflictError(f"API-key limit reached ({MAX_ACTIVE_API_KEYS})")
        key_id, secret = uuid4().hex, secrets.token_urlsafe(32)
        plaintext = f"{KEY_PREFIX}_{key_id}_{secret}"
        row = ApiKeyRow(key_id, user_id, name.strip() or "API key", _hash(plaintext), json.dumps(normalized), _now(), expires_at)
        await self._store.insert(row)
        return ApiKeyCreated(plaintext, self._view(row))

    async def list_for_user(self, user_id: str) -> list[ApiKeyView]:
        return [self._view(row) for row in await self._store.list_active_for_user(user_id, _now())]

    async def revoke(self, user_id: str, key_id: str) -> None:
        if not await self._store.revoke_owned(key_id, user_id, _now()):
            raise PermissionDeniedError("API key not found")

    async def admin_revoke(self, key_id: str) -> None:
        if not await self._store.revoke_any(key_id, _now()):
            raise ResourceNotFoundError("API key not found")

    async def verify(self, raw: str) -> tuple[UserRecord, ApiKeyRow] | None:
        parts = raw.split("_", 2)
        if len(parts) != 3 or parts[0] != KEY_PREFIX or len(raw) > 1024:
            return None
        row = await self._store.get_active(parts[1], _now())
        if row is None or not hmac.compare_digest(row.secret_hash, _hash(raw)):
            return None
        user = await self._auth_store.get_user_by_id(row.user_id)
        if user is None:
            return None
        await self._store.touch(row.id, _now())
        return user, row
