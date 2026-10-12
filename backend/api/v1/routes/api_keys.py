"""Owner API-key management; API keys themselves can never manage credentials."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from api.v1.schemas.api_keys import ApiKeyCreateRequest, ApiKeyCreateResponse, ApiKeyListResponse
from core.dependencies.auth_providers import get_api_key_service
from core.exceptions import ConflictError, PermissionDeniedError
from infrastructure.msgspec_fastapi import MsgSpecBody, MsgSpecRoute
from middleware import CurrentAdminDep, CurrentUserDep
from services.api_key_service import ApiKeyService, MAX_ACTIVE_API_KEYS

router = APIRouter(route_class=MsgSpecRoute, prefix="/profile/api-keys", tags=["api-keys"])


@router.get("", response_model=ApiKeyListResponse)
async def list_api_keys(current_user: CurrentUserDep, service: ApiKeyService = Depends(get_api_key_service)) -> ApiKeyListResponse:
    items = await service.list_for_user(current_user.id)
    return ApiKeyListResponse(cap=MAX_ACTIVE_API_KEYS, active_count=len(items), items=items)


@router.post("", response_model=ApiKeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(current_user: CurrentUserDep, body: ApiKeyCreateRequest = MsgSpecBody(ApiKeyCreateRequest), service: ApiKeyService = Depends(get_api_key_service)) -> ApiKeyCreateResponse:
    if not body.name.strip():
        raise HTTPException(400, "A name is required")
    try:
        result = await service.create(current_user.id, body.name, body.scopes, body.expires_at)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except ConflictError as exc:
        raise HTTPException(409, str(exc))
    return ApiKeyCreateResponse(key=result.key, api_key=result.api_key)


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(current_user: CurrentUserDep, key_id: str, service: ApiKeyService = Depends(get_api_key_service)) -> None:
    try:
        await service.revoke(current_user.id, key_id)
    except PermissionDeniedError:
        raise HTTPException(404, "API key not found")


@router.delete("/admin/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def admin_revoke_api_key(_: CurrentAdminDep, key_id: str, service: ApiKeyService = Depends(get_api_key_service)) -> None:
    await service.admin_revoke(key_id)
