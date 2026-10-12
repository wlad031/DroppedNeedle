import json
from types import SimpleNamespace

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from infrastructure.persistence.auth_store import UserRecord
from middleware import AuthMiddleware


def test_api_key_scope_registry_is_allowlisted():
    assert AuthMiddleware._api_key_allows("GET", "/api/v1/albums/abc", {"catalog:read"})
    assert AuthMiddleware._api_key_allows("POST", "/api/v1/playlists", {"playlists:write"})
    assert AuthMiddleware._api_key_allows("POST", "/api/v1/scrobble", {"scrobble:write"})
    assert not AuthMiddleware._api_key_allows("GET", "/api/v1/stream/abc", {"catalog:read"})
    assert not AuthMiddleware._api_key_allows("POST", "/api/v1/playlists/p/request-missing", {"playlists:write"})
    assert AuthMiddleware._api_key_allows("POST", "/api/v1/playlists/p/request-missing", {"requests:write"})
    assert not AuthMiddleware._api_key_allows("POST", "/api/v1/anything/request-missing", {"requests:write"})
    assert not AuthMiddleware._api_key_allows("POST", "/api/v1/settings", {"catalog:read"})
    assert not AuthMiddleware._api_key_allows("DELETE", "/api/v1/downloads/abc", {"requests:write"})
    assert not AuthMiddleware._api_key_allows("GET", "/api/v1/profile/api-keys", {"catalog:read"})


def test_scoped_api_key_preserves_session_auth_and_denies_unregistered_routes(monkeypatch):
    """Exercise the middleware boundary, not just the route registry helper."""
    user = UserRecord("owner", "Owner", "user", "2026-01-01T00:00:00Z")

    class FakeAuth:
        async def verify_token(self, raw: str):
            return (user, SimpleNamespace(id="session")) if raw == "session-token" else None

    valid_key = "dnk_0123456789abcdef0123456789abcdef_secret"
    key_with_underscore = f"{valid_key}_with_underscore"

    class FakeApiKeys:
        async def verify(self, raw: str):
            if raw in {valid_key, key_with_underscore}:
                return user, SimpleNamespace(scopes_json=json.dumps(["catalog:read"]))
            return None

    import core.dependencies.auth_providers as providers

    monkeypatch.setattr(providers, "get_auth_service", lambda: FakeAuth())
    monkeypatch.setattr(providers, "get_api_key_service", lambda: FakeApiKeys())

    app = FastAPI()
    app.add_middleware(AuthMiddleware)

    @app.get("/api/v1/albums/demo")
    async def catalog(request: Request):
        return {"user": request.state.user.id, "api_key": request.state.api_key is not None}

    @app.get("/api/v1/stream/demo")
    async def stream():
        return {"stream": True}

    @app.get("/api/v1/admin/unknown")
    async def unregistered():
        return {"unexpected": True}

    client = TestClient(app)
    session = client.get("/api/v1/albums/demo", headers={"Authorization": "Bearer session-token"})
    assert session.status_code == 200
    assert session.json() == {"user": "owner", "api_key": False}

    scoped = client.get("/api/v1/albums/demo", headers={"Authorization": f"Bearer {valid_key}"})
    assert scoped.status_code == 200
    assert scoped.json() == {"user": "owner", "api_key": True}
    assert client.get("/api/v1/albums/demo", headers={"Authorization": f"Bearer {key_with_underscore}"}).status_code == 200

    invalid_key = "dnk_0123456789abcdef0123456789abcdef_invalid_secret"
    assert client.get("/api/v1/albums/demo", headers={"Authorization": f"Bearer {invalid_key}"}).status_code == 401
    assert client.get("/api/v1/stream/demo", headers={"Authorization": f"Bearer {valid_key}"}).status_code == 403
    assert client.get("/api/v1/admin/unknown", headers={"Authorization": f"Bearer {valid_key}"}).status_code == 403
