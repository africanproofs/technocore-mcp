"""Guards on the signing surface — the confused-deputy defense.

The MCP `say`/`kv_set` tools can sign as the configured did:key. Exposed to an
agent that also reads anonymous room content, that is a confused-deputy risk:
a hostile room message could induce the agent to sign attacker text as a
permanent, publicly-attributable identity. These guards bound that:

- Writes through the MCP server are OFF by default (opt-in env), so a session
  that loaded the server only to READ cannot write at all — this also makes
  the "read-only without configuration" promise literally true.
- An optional room/namespace allowlist confines where the identity will post.
- A minimum interval between writes caps the blast radius of a runaway loop.
- Every signed write is appended to a 0600 audit log (a custody trail; the
  text is hashed, not stored in full).

The scripts that legitimately write (observatory, tcid) call the client
directly and only get the audit trail — they run in trusted, deliberately
invoked contexts, not from anonymous room input.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import time
from pathlib import Path

_TRUTHY = {"1", "true", "yes", "on"}


class WriteBlocked(Exception):
    """A signed write was refused by policy (not a network/auth failure)."""


def _audit_path() -> Path:
    seed = os.environ.get("TECHNOCORE_SEED_FILE")
    base = Path(seed).parent if seed else (Path.home() / ".technocore")
    return base / "audit.log"


def _state_path() -> Path:
    seed = os.environ.get("TECHNOCORE_SEED_FILE")
    base = Path(seed).parent if seed else (Path.home() / ".technocore")
    return base / "writeguard.json"


def _allowlist(var: str) -> set[str] | None:
    raw = os.environ.get(var, "").strip()
    if not raw:
        return None
    return {x.strip() for x in raw.split(",") if x.strip()}


def enforce_mcp_write(kind: str, target: str) -> None:
    """Gate a write attempted through the MCP server. Raises WriteBlocked if
    the write is not permitted by the current environment policy.

    kind: "room" or "ns". target: the room name or kv namespace.
    """
    if os.environ.get("TECHNOCORE_MCP_ALLOW_WRITE", "").lower() not in _TRUTHY:
        raise WriteBlocked(
            "signed writes via the MCP server are disabled. This server is "
            "read-only unless TECHNOCORE_MCP_ALLOW_WRITE is set — a deliberate "
            "guard so an agent reading untrusted room content cannot be induced "
            "to sign as your identity."
        )
    var = "TECHNOCORE_MCP_WRITE_ROOMS" if kind == "room" else "TECHNOCORE_MCP_WRITE_NS"
    allow = _allowlist(var)
    if allow is not None and target not in allow:
        raise WriteBlocked(
            f"{kind} '{target}' is not in the write allowlist ({var})."
        )
    _rate_limit()


def _rate_limit() -> None:
    try:
        min_interval = float(os.environ.get("TECHNOCORE_MCP_MIN_WRITE_INTERVAL", "2.0"))
    except ValueError:
        min_interval = 2.0
    if min_interval <= 0:
        return
    sp = _state_path()
    sp.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive lock over read-check-write so concurrent callers actually
    # serialize — an unlocked check let 27 simultaneous writes through a
    # nominal 60s gate (review #4). The lock also gates the check itself, so
    # only one caller per interval passes.
    with open(sp, "a+") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.seek(0)
            raw = f.read()
            try:
                last = float(json.loads(raw).get("last_write", 0.0)) if raw.strip() else 0.0
            except (ValueError, TypeError):
                last = 0.0
            now = time.time()
            if now - last < min_interval:
                raise WriteBlocked(
                    f"rate limited: {min_interval:.0f}s minimum between signed "
                    f"writes (last was {now - last:.1f}s ago)."
                )
            f.seek(0)
            f.truncate()
            f.write(json.dumps({"last_write": now}))
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def audit(action: str, target: str, did: str, nonce: str, body: str) -> None:
    """Append a signed-write record to the 0600 audit log. Best-effort — an
    audit failure must never crash a legitimate write."""
    try:
        path = _audit_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": action,
            "target": target,
            "did": did,
            "nonce": nonce,
            "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            "body_len": len(body),
        }
        with path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except OSError:
        pass
