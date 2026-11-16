"""Operations of an API document sit under its base path (Swagger 2.0 basePath, OpenAPI 3 server path)."""
from extractor.openapi_discovery import _operations, base_path


def test_swagger_base_path_is_applied():
    doc = {"swagger": "2.0", "basePath": "/api/v1", "paths": {"/products": {"get": {}}, "/products/{id}": {"get": {}}}}
    assert base_path(doc) == "/api/v1"
    assert sorted(o["path"] for o in _operations(doc)) == ["/api/v1/products", "/api/v1/products/{id}"]


def test_root_and_host_only_servers_change_nothing():
    assert base_path({"swagger": "2.0", "basePath": "/"}) == ""
    assert base_path({"openapi": "3.0.1", "servers": [{"url": "http://customer-core:8110"}]}) == ""
    assert base_path({"openapi": "3.0.1", "servers": [{"url": "https://example.org/v2/"}]}) == "/v2"
    assert base_path({"openapi": "3.0.1", "servers": [{"url": "/api"}]}) == "/api"
    assert base_path({"openapi": "3.0.1", "servers": [{"url": "https://h/{base}"}]}) == ""
