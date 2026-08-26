"""Offline unit tests for technocore_mcp.identity. No network access is used
or required — everything here is pure crypto/string logic plus a tmp-file
guarded nonce/seed store."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_mcp import identity

KNOWN_SEED = "aa" * 32
KNOWN_DID = "did:key:z6Mkv1o2GEgtXjFdEMfLtupcKhGRydM8V7VHzii7Uh4aHoqH"


def test_did_of_known_vector():
    """Cross-verified against the reference did:key derivation."""
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(KNOWN_SEED))
    assert identity.did_of(key) == KNOWN_DID


def test_sweep_and_signature_roundtrip():
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(KNOWN_SEED))
    text = "hello‍ wor\nld ‮ end"  # ZWJ, newline (Cc), RLO
    cleaned = identity.swept(text)

    assert "‍" not in cleaned
    assert "\n" not in cleaned
    assert "‮" not in cleaned
    assert cleaned == cleaned.strip()

    canonical = f"room|123|{cleaned}"
    sig = identity.sign_canonical(key, canonical)
    padded = sig + "=" * (-len(sig) % 4)
    raw = base64.urlsafe_b64decode(padded)
    # Raises on a bad signature — a clean return is the assertion.
    key.public_key().verify(raw, canonical.encode("utf-8"))


def test_signature_length_and_decoded_size():
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(KNOWN_SEED))
    sig = identity.sign_canonical(key, "room|1|some canonical text")
    assert len(sig) == 86

    padded = sig + "=" * (-len(sig) % 4)
    raw = base64.urlsafe_b64decode(padded)
    assert len(raw) == 64


def test_next_nonce_is_monotonic(tmp_path, monkeypatch):
    state_path = tmp_path / "state.json"
    monkeypatch.setenv("TECHNOCORE_STATE_FILE", str(state_path))

    first = identity.next_nonce()
    second = identity.next_nonce()

    assert int(second) > int(first)


def test_keygen_cli_refuses_existing_seed(tmp_path, monkeypatch):
    seed_path = tmp_path / "identity.seed"
    seed_path.write_text("bb" * 32 + "\n")
    monkeypatch.setenv("TECHNOCORE_SEED_FILE", str(seed_path))

    with pytest.raises(SystemExit):
        identity.keygen_cli()
