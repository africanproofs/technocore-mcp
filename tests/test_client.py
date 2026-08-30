"""Offline unit tests for technocore_mcp.client. Name validation happens
before any request is built, so these run with no network access."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_mcp import identity
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


class _FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "ok"):
        self.status_code = status_code
        self.text = text


def test_say_signed_uses_the_passed_key_not_the_configured_one(tmp_path, monkeypatch):
    """FIX A: `say_signed(..., key=...)` must sign with the EXACT key object
    passed in, never silently falling back to whatever `identity.load_key()`
    would resolve from disk -- even when a DIFFERENT identity is configured
    there. This is what replaces the old `identity.load_key` monkeypatch in
    observatory's CLI: the parameter closes the same TOCTOU window without
    rebinding a process-global secret loader."""
    configured_seed = tmp_path / "identity.seed"
    configured_seed.write_text(("aa" * 32) + "\n")
    monkeypatch.setenv("TECHNOCORE_SEED_FILE", str(configured_seed))
    monkeypatch.setenv("TECHNOCORE_STATE_FILE", str(tmp_path / "state.json"))

    configured_key = identity.load_key()
    passed_key = Ed25519PrivateKey.generate()
    assert identity.did_of(passed_key) != identity.did_of(configured_key)

    client = TechnocoreClient(base_url="https://example.invalid")
    captured: dict[str, str] = {}

    def fake_get(url: str, timeout: float | None = None) -> _FakeResponse:
        captured["url"] = url
        return _FakeResponse(200, "posted")

    monkeypatch.setattr(client._client, "get", fake_get)

    result = client.say_signed("african-proofs", "hello", key=passed_key)

    assert result["did"] == identity.did_of(passed_key)
    assert identity.did_of(passed_key) in captured["url"]
    assert identity.did_of(configured_key) not in captured["url"]
    client.close()
