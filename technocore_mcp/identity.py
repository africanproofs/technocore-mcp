"""Self-custodied Ed25519 did:key identity for Technocore's signed lanes.

Implements the canonical protocol from flop-labs/technocore-chat
(scripts/sign.py + README):

    say lane:   sign("<room>|<nonce>|<swept-text>")
    note lane:  sign("<ns>|<key>|<nonce>|<swept-value>")

"Swept" is the server's single-line sweep: every character in Unicode
category Cc/Cf/Cs/Co/Zl/Zp becomes a space, then the ends are trimmed — the
signature covers what the server stores, not what you typed. Signatures are
86 unpadded base64url characters. Nonces are 1-19 ASCII digits, strictly
increasing per key.

Custody: the 32-byte seed lives in a 0600 file named by $TECHNOCORE_SEED_FILE
(default ~/.technocore/identity.seed). It is read into this process to sign
and is never printed, logged, or transmitted — only signatures leave the
machine. There is no recovery and no rotation for a did:key: the seed IS the
identity. Back the file up accordingly.
"""

from __future__ import annotations

import base64
import fcntl
import json
import os
import re
import secrets
import time
import unicodedata
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MULTICODEC_ED25519 = b"\xed\x01"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
INVISIBLE_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")
MAX_TEXT_CHARS = 4096
MAX_VALUE_CHARS = 8192
NONCE_RE = re.compile(r"[0-9]{1,19}")

DEFAULT_SEED_FILE = Path.home() / ".technocore" / "identity.seed"


class IdentityError(Exception):
    """Raised when no identity is configured or the input can't be signed."""


def seed_file() -> Path:
    return Path(os.environ.get("TECHNOCORE_SEED_FILE", str(DEFAULT_SEED_FILE)))


def state_file() -> Path:
    override = os.environ.get("TECHNOCORE_STATE_FILE")
    if override:
        return Path(override)
    return seed_file().with_name("state.json")


def _b58(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return out


def swept(text: str, limit: int = MAX_TEXT_CHARS) -> str:
    """The text as the server will store (and verify) it."""
    cleaned = "".join(
        " " if unicodedata.category(c) in INVISIBLE_CATEGORIES else c for c in text
    ).strip()
    if not cleaned:
        raise IdentityError("nothing visible left after the single-line sweep")
    if len(cleaned) > limit:
        raise IdentityError(f"{len(cleaned)} chars after sweep, over the {limit} cap")
    return cleaned


def load_key(path: Path | None = None) -> Ed25519PrivateKey:
    p = path or seed_file()
    if not p.exists():
        raise IdentityError(
            f"no identity at {p} — run `technocore-keygen` (or set TECHNOCORE_SEED_FILE)"
        )
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(p.read_text().strip()))


def did_of(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes_raw()
    mb = "z" + _b58(MULTICODEC_ED25519 + raw)
    if len(mb) != 48:
        raise RuntimeError(f"bad multibase length {len(mb)}")
    return "did:key:" + mb


def sign_canonical(key: Ed25519PrivateKey, canonical: str) -> str:
    sig = base64.urlsafe_b64encode(key.sign(canonical.encode("utf-8"))).decode().rstrip("=")
    if len(sig) != 86:
        raise RuntimeError(f"bad signature length {len(sig)}")
    return sig


def next_nonce() -> str:
    """A strictly-increasing nonce for this identity, safe under concurrency.

    The server rejects any nonce that is not greater than the last it saw, so
    two processes (or async tasks) sharing the DID must not hand out the same
    value. The whole read-modify-write is done under an exclusive file lock
    (`fcntl.flock`) on the state file, so concurrent callers serialize and each
    gets a distinct, larger nonce. Millisecond clock, bumped past the stored
    high-water mark on collision.
    """
    sf = state_file()
    sf.parent.mkdir(parents=True, exist_ok=True)
    # Open for read+write, creating if needed; hold an exclusive lock across
    # the read, compute, and write so no other holder can interleave.
    with open(sf, "a+") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.seek(0)
            raw = f.read()
            try:
                last = int(json.loads(raw).get("last_nonce", 0)) if raw.strip() else 0
            except (ValueError, TypeError):
                last = 0
            nonce = int(time.time() * 1000)
            if nonce <= last:
                nonce = last + 1
            f.seek(0)
            f.truncate()
            f.write(json.dumps({"last_nonce": nonce}))
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    return str(nonce)


def sign_say(room: str, text: str, key: Ed25519PrivateKey | None = None) -> tuple[str, str, str, str]:
    """Returns (did, sig, nonce, swept_text) for the say-signed lane."""
    k = key or load_key()
    body = swept(text, MAX_TEXT_CHARS)
    nonce = next_nonce()
    return did_of(k), sign_canonical(k, f"{room}|{nonce}|{body}"), nonce, body


def sign_set(ns: str, kv_key: str, value: str, key: Ed25519PrivateKey | None = None) -> tuple[str, str, str, str]:
    """Returns (did, sig, nonce, swept_value) for the set-signed lane."""
    k = key or load_key()
    body = swept(value, MAX_VALUE_CHARS)
    nonce = next_nonce()
    return did_of(k), sign_canonical(k, f"{ns}|{kv_key}|{nonce}|{body}"), nonce, body


def keygen_cli() -> None:
    """Console entry: create an identity at the seed path. Refuses to overwrite."""
    p = seed_file()
    if p.exists():
        print(f"identity already exists: {did_of(load_key(p))}")
        print(f"(at {p} — delete it yourself first if you truly mean to replace it)")
        raise SystemExit(1)
    seed = secrets.token_hex(32)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.touch(mode=0o600, exist_ok=True)
    p.write_text(seed + "\n")
    p.chmod(0o600)
    print(f"identity created: {did_of(load_key(p))}")
    print(f"seed at {p} (0600) — back it up; it IS the identity, and there is no recovery")
