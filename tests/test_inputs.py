from __future__ import annotations

import json

from authdiff.core.models import Identity, RequestTag
from authdiff.inputs import parse_file
from authdiff.inputs.base import tag_request
from authdiff.inputs.registry import detect_format

ALICE = Identity("alice")


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def test_tag_request_object_ref() -> None:
    tags = tag_request("GET", "https://x/api/orders/123")
    assert RequestTag.OBJECT_REF in tags and RequestTag.READ in tags


def test_har_parse_and_dedup(tmp_path) -> None:
    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "https://x/api/orders/1", "headers": []}},
        {"request": {"method": "GET", "url": "https://x/api/orders/1", "headers": []}},
        {"request": {"method": "GET", "url": "https://x/static/app.js", "headers": []}},
    ]}}
    path = _write(tmp_path, "c.har", har)
    reqs = parse_file(path, ALICE)
    urls = [r.url for r in reqs]
    assert "https://x/api/orders/1" in urls
    assert all(not u.endswith(".js") for u in urls)  # static skipped
    assert len(urls) == 1  # deduped


def test_postman_parse(tmp_path) -> None:
    coll = {"info": {"name": "c"}, "item": [
        {"request": {"method": "GET", "url": {"raw": "https://x/api/users/9"}, "header": []}},
    ]}
    path = _write(tmp_path, "c.postman.json", coll)
    assert detect_format(path) == "postman"
    reqs = parse_file(path, ALICE)
    assert reqs[0].url.endswith("/users/9")


def test_openapi_parse(tmp_path) -> None:
    spec = {"openapi": "3.0.0", "servers": [{"url": "https://x"}], "paths": {
        "/orders/{id}": {"get": {}},
    }}
    path = _write(tmp_path, "oas.json", spec)
    assert detect_format(path) == "openapi"
    reqs = parse_file(path, ALICE)
    assert any("/orders/" in r.url for r in reqs)
