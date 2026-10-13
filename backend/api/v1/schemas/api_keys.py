from __future__ import annotations

from infrastructure.msgspec_fastapi import AppStruct
from services.api_key_service import ApiKeyCreated, ApiKeyView


class ApiKeyCreateRequest(AppStruct):
    name: str
    scopes: list[str]
    expires_at: str | None = None


class ApiKeyListResponse(AppStruct):
    cap: int
    active_count: int
    items: list[ApiKeyView] = []


class ApiKeyCreateResponse(AppStruct):
    key: str
    api_key: ApiKeyView


class AdminApiKeyRevokeResponse(AppStruct):
    revoked: bool = True
