from middleware import AuthMiddleware


def test_api_key_scope_registry_is_allowlisted():
    assert AuthMiddleware._api_key_allows("GET", "/api/v1/albums/abc", {"catalog:read"})
    assert AuthMiddleware._api_key_allows("POST", "/api/v1/playlists", {"playlists:write"})
    assert AuthMiddleware._api_key_allows("POST", "/api/v1/scrobble", {"scrobble:write"})
    assert not AuthMiddleware._api_key_allows("GET", "/api/v1/stream/abc", {"catalog:read"})
    assert not AuthMiddleware._api_key_allows("POST", "/api/v1/playlists/p/request-missing", {"playlists:write"})
    assert AuthMiddleware._api_key_allows("POST", "/api/v1/playlists/p/request-missing", {"requests:write"})
    assert not AuthMiddleware._api_key_allows("POST", "/api/v1/settings", {"catalog:read"})
    assert not AuthMiddleware._api_key_allows("DELETE", "/api/v1/downloads/abc", {"requests:write"})
    assert not AuthMiddleware._api_key_allows("GET", "/api/v1/profile/api-keys", {"catalog:read"})
