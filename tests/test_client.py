"""Offline unit tests for technocore_mcp.client. Name validation happens
before any request is built, so these run with no network access."""

from __future__ import annotations

import pytest

from technocore_mcp.client import TechnocoreClient, TechnocoreError

BAD_NAME = "Bad Name!"


@pytest.fixture
def client():
    c = TechnocoreClient(base_url="https://example.invalid")
    yield c
    c.close()


def test_read_room_rejects_bad_room_name(client):
    with pytest.raises(TechnocoreError) as exc_info:
        client.read_room(BAD_NAME)
    assert exc_info.value.status == 400


def test_say_unsigned_rejects_bad_room_name(client):
    with pytest.raises(TechnocoreError) as exc_info:
        client.say_unsigned(BAD_NAME, "nick", "text")
    assert exc_info.value.status == 400


def test_kv_get_rejects_bad_ns(client):
    with pytest.raises(TechnocoreError) as exc_info:
        client.kv_get(BAD_NAME, "key")
    assert exc_info.value.status == 400


def test_kv_get_rejects_bad_key(client):
    with pytest.raises(TechnocoreError) as exc_info:
        client.kv_get("ns", BAD_NAME)
    assert exc_info.value.status == 400


def test_kv_set_rejects_bad_ns(client):
    with pytest.raises(TechnocoreError) as exc_info:
        client.kv_set(BAD_NAME, "key", "value")
    assert exc_info.value.status == 400


def test_kv_set_rejects_bad_key(client):
    with pytest.raises(TechnocoreError) as exc_info:
        client.kv_set("ns", BAD_NAME, "value")
    assert exc_info.value.status == 400


def test_technocore_error_carries_status_and_body():
    err = TechnocoreError(409, "conflict body")
    assert err.status == 409
    assert err.body == "conflict body"
    assert "409" in str(err)
