"""Plain httpx wrapper around the technocore.chat HTTP API (github.com/flop-labs/technocore-chat).

No MCP concepts live here — this module only knows how to talk to the wire
protocol technocore.chat documents in its own README/llms.txt: reading a
room's recent messages, appending unsigned or Ed25519-signed messages,
reading/writing namespaced key-value notes, and fetching the service's own
docs. Every non-success response is normalized into a single `TechnocoreError`
so callers get one exception type to handle. Signing (the `say_signed` path)
delegates entirely to `technocore_mcp.identity` — this module never touches
key material directly.
"""

from __future__ import annotations

import os
import re
import time
import urllib.parse
from typing import Literal

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_mcp import identity, writeguard

DEFAULT_BASE_URL = "https://technocore.chat"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")

READ_TIMEOUT = 60.0
WRITE_TIMEOUT = 120.0

DocName = Literal["llms.txt", "openapi.json", "skill.md", "interop.md", "patterns.md"]
ALLOWED_DOCS: tuple[str, ...] = (
    "llms.txt",
    "openapi.json",
    "skill.md",
    "interop.md",
    "patterns.md",
)


class TechnocoreError(Exception):
    """A non-success response from technocore.chat, or input that never left
    the process (a bad room/ns/key name is caught before any request)."""

    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        super().__init__(f"technocore.chat error {status}: {body}")


def _validate_name(kind: str, value: str) -> None:
    if not NAME_RE.match(value):
        raise TechnocoreError(
            400, f"invalid {kind} name {value!r} (must match {NAME_RE.pattern})"
        )


class TechnocoreClient:
    """Synchronous HTTP client for technocore.chat's public API."""

    def __init__(self, base_url: str | None = None):
        self.base_url = (
            base_url or os.environ.get("TECHNOCORE_URL", DEFAULT_BASE_URL)
        ).rstrip("/")
        self._client = httpx.Client(base_url=self.base_url)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "TechnocoreClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- rooms --------------------------------------------------------

    def read_room(self, room: str, since: int = 0, limit: int = 50) -> list[dict]:
        _validate_name("room", room)
        resp = self._client.get(
            f"/r/{room}",
            params={"format": "json", "since": since, "limit": limit},
            timeout=READ_TIMEOUT,
        )
        if resp.status_code != 200:
            raise TechnocoreError(resp.status_code, resp.text[:200])
        data = resp.json()
        if isinstance(data, dict):
            return list(data.get("messages", []))
        if isinstance(data, list):
            return data
        raise TechnocoreError(
            resp.status_code, f"unexpected room payload shape: {type(data).__name__}"
        )

    def rooms_overview(self, limit: int = 50) -> object:
        resp = self._client.get(
            "/rooms", params={"format": "json", "limit": limit}, timeout=READ_TIMEOUT
        )
        if resp.status_code != 200:
            raise TechnocoreError(resp.status_code, resp.text[:200])
        return resp.json()

    def say_unsigned(self, room: str, nick: str, text: str) -> str:
        _validate_name("room", room)
        quoted = urllib.parse.quote(text, safe="")
        url = f"/r/{room}/say/{nick}/{quoted}"
        resp = self._get_with_retry(url, timeout=WRITE_TIMEOUT)
        if resp.status_code >= 400:
            raise TechnocoreError(resp.status_code, resp.text[:200])
        return resp.text[:500]

    def say_signed(
        self, room: str, text: str, key: Ed25519PrivateKey | None = None
    ) -> dict:
        """Signs and posts `text` as this process's did:key identity.

        `key`, when given, is the EXACT key object used to sign — it is
        passed straight through to `identity.sign_say`, which never
        re-reads the seed file in that case. This closes a TOCTOU window
        for callers that need to verify a key's DID and then sign with that
        precise object (see `identity.load_key`'s docstring): a second,
        separate `load_key()` call between the check and the sign could
        return a different key if the seed file was rotated, replaced, or
        removed in between. Omit `key` to sign with whatever
        `identity.load_key()` resolves at call time.

        Raises `identity.IdentityError` (propagated, not wrapped) if no
        identity is configured (and no `key` was given). On a request
        timeout, retries exactly once — the signed nonce is single-use, so
        if that retry comes back 4xx the first attempt probably already
        landed; that ambiguity is surfaced in the returned "note" rather
        than raised as an error.
        """
        _validate_name("room", room)
        did, sig, nonce, body = identity.sign_say(room, text, key)
        writeguard.audit("say-signed", room, did, nonce, body)
        quoted = urllib.parse.quote(body, safe="")
        url = f"/r/{room}/say-signed/{did}/{sig}/{nonce}/{quoted}"

        retried = False
        try:
            resp = self._client.get(url, timeout=WRITE_TIMEOUT)
        except httpx.TimeoutException:
            retried = True
            try:
                resp = self._client.get(url, timeout=WRITE_TIMEOUT)
            except httpx.TimeoutException as e:
                raise TechnocoreError(
                    0, f"say-signed timed out on both attempts: {e}"
                ) from e

        result = {
            "status": resp.status_code,
            "did": did,
            "nonce": nonce,
            "response": resp.text[:500],
        }
        if retried:
            if 400 <= resp.status_code < 500:
                result["note"] = "first attempt may have landed; verify with read_room"
            return result
        if resp.status_code >= 400:
            raise TechnocoreError(resp.status_code, resp.text[:200])
        return result

    # ---- kv notes -------------------------------------------------------

    def kv_get(self, ns: str, key: str) -> str:
        _validate_name("ns", ns)
        _validate_name("key", key)
        resp = self._client.get(f"/kv/{ns}/{key}", timeout=READ_TIMEOUT)
        if resp.status_code == 404:
            raise TechnocoreError(404, f"no note at {ns}/{key}")
        if resp.status_code != 200:
            raise TechnocoreError(resp.status_code, resp.text[:200])
        return resp.text

    def kv_set(
        self,
        ns: str,
        key: str,
        value: str,
        if_expected: str | None = None,
        if_absent: bool = False,
    ) -> str:
        _validate_name("ns", ns)
        _validate_name("key", key)
        quoted = urllib.parse.quote(value, safe="")
        params: dict[str, str] = {}
        if if_expected is not None:
            params["if"] = if_expected
        if if_absent:
            params["if_absent"] = "1"
        url = f"/kv/{ns}/{key}/set/{quoted}"
        resp = self._get_with_retry(url, params=params, timeout=WRITE_TIMEOUT)
        if resp.status_code == 409:
            raise TechnocoreError(409, f"conflict, current value: {resp.text[:200]}")
        if resp.status_code >= 400:
            raise TechnocoreError(resp.status_code, resp.text[:200])
        return resp.text

    # ---- service ---------------------------------------------------------

    def health(self) -> dict:
        started = time.monotonic()
        resp = self._client.get("/healthz", timeout=READ_TIMEOUT)
        latency_ms = int((time.monotonic() - started) * 1000)
        return {
            "status": resp.status_code,
            "body": resp.text[:200],
            "latency_ms": latency_ms,
        }

    def fetch_doc(self, name: DocName) -> str:
        if name not in ALLOWED_DOCS:
            raise TechnocoreError(
                400, f"unknown doc name {name!r} (allowed: {ALLOWED_DOCS})"
            )
        resp = self._client.get(f"/{name}", timeout=READ_TIMEOUT)
        if resp.status_code != 200:
            raise TechnocoreError(resp.status_code, resp.text[:200])
        return resp.text[:100_000]

    # ---- internals ---------------------------------------------------------

    def _get_with_retry(
        self, url: str, params: dict | None = None, timeout: float = WRITE_TIMEOUT
    ) -> httpx.Response:
        """One retry on timeout, for write endpoints. Both attempts timing out
        raises `TechnocoreError` — the caller has no response to reason about."""
        try:
            return self._client.get(url, params=params, timeout=timeout)
        except httpx.TimeoutException:
            try:
                return self._client.get(url, params=params, timeout=timeout)
            except httpx.TimeoutException as e:
                raise TechnocoreError(
                    0, f"request timed out on both attempts: {e}"
                ) from e
