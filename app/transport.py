"""Strictly read-only HTTP transport for configured Technocore origins."""

from __future__ import annotations

import http.client
import json
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Protocol, cast
from urllib.parse import urlencode, urlsplit

ROOM_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
READ_ROOM_PATH_RE = re.compile(r"^/r/[a-z0-9][a-z0-9_-]{0,47}$")
USER_AGENT = "technocore-watchtower/0.1.0"


class HTTPResponseLike(Protocol):
    status: int
    reason: str

    def getheader(self, name: str, default: str | None = None) -> str | None: ...
    def read(self, amount: int | None = None) -> bytes: ...


class HTTPSConnectionLike(Protocol):
    def request(
        self, method: str, url: str, body: bytes | None = None, headers: dict[str, str] | None = None
    ) -> None: ...
    def getresponse(self) -> HTTPResponseLike: ...
    def close(self) -> None: ...


ConnectionFactory = Callable[[str, int, float, ssl.SSLContext], HTTPSConnectionLike]


@dataclass(frozen=True, slots=True)
class TransportResult:
    ok: bool
    status: int | None
    data: Any = None
    error: str | None = None
    retry_after_seconds: int | None = None


def _default_connection(
    host: str, port: int, timeout: float, context: ssl.SSLContext
) -> HTTPSConnectionLike:
    return cast(
        HTTPSConnectionLike,
        http.client.HTTPSConnection(host, port, timeout=timeout, context=context),
    )


class TechnocoreTransport:
    """GET-only client whose public API exposes only known read endpoints.

    The configured base URL must be a pathless HTTPS origin. Redirects are never
    followed. A single bounded socket timeout covers connection and response reads.
    """

    def __init__(
        self,
        base_url: str = "https://technocore.chat",
        *,
        timeout_seconds: float = 15.0,
        max_response_bytes: int = 2_000_000,
        connection_factory: ConnectionFactory = _default_connection,
    ) -> None:
        parts = urlsplit(base_url)
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.path not in ("", "/")
            or parts.query
            or parts.fragment
        ):
            raise ValueError("base_url must be a pathless HTTPS origin")
        if not 1 <= timeout_seconds <= 60:
            raise ValueError("timeout_seconds must be between 1 and 60")
        if not 1 <= max_response_bytes <= 10_000_000:
            raise ValueError("max_response_bytes is outside the allowed bound")
        self._host = parts.hostname
        self._port = parts.port or 443
        self._timeout = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._connection_factory = connection_factory
        self._tls_context = ssl.create_default_context()

    @staticmethod
    def validate_room(room: str) -> str:
        if not isinstance(room, str) or ROOM_RE.fullmatch(room) is None:
            raise ValueError("invalid Technocore room name")
        return room

    def read_room(
        self,
        room: str,
        *,
        since: int | None = None,
        wait: int = 0,
        limit: int | None = None,
    ) -> TransportResult:
        room = self.validate_room(room)
        if since is not None and (isinstance(since, bool) or not isinstance(since, int) or since < 0):
            raise ValueError("since must be a non-negative integer")
        if isinstance(wait, bool) or not isinstance(wait, int) or not 0 <= wait <= 10:
            raise ValueError("wait must be an integer from 0 through 10")
        if limit is not None and (
            isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100
        ):
            raise ValueError("limit must be an integer from 1 through 100")
        query: dict[str, str | int] = {"format": "json"}
        if since is not None:
            query["since"] = since
        if wait:
            query["wait"] = wait
        if limit is not None:
            query["limit"] = limit
        return self._get_json(f"/r/{room}", query)

    def list_rooms(self) -> TransportResult:
        return self._get_json("/rooms", {"format": "json"})

    def health(self) -> TransportResult:
        return self._get("/healthz", {}, expect_json=False)

    def _get_json(self, path: str, query: dict[str, str | int]) -> TransportResult:
        return self._get(path, query, expect_json=True)

    def _get(
        self, path: str, query: dict[str, str | int], *, expect_json: bool
    ) -> TransportResult:
        if path == "/healthz":
            allowed_query_keys: set[str] = set()
        elif path == "/rooms":
            allowed_query_keys = {"format"}
        elif READ_ROOM_PATH_RE.fullmatch(path):
            allowed_query_keys = {"format", "since", "wait", "limit"}
        else:
            raise ValueError("path is not an allowed Technocore read endpoint")
        if not query.keys() <= allowed_query_keys:
            raise ValueError("query contains a parameter not allowed for this read endpoint")
        target = path + ("?" + urlencode(query) if query else "")
        connection = self._connection_factory(
            self._host, self._port, self._timeout, self._tls_context
        )
        try:
            connection.request(
                "GET",
                target,
                body=None,
                headers={"Accept": "application/json" if expect_json else "text/plain", "User-Agent": USER_AGENT},
            )
            response = connection.getresponse()
            body = response.read(self._max_response_bytes + 1)
            if len(body) > self._max_response_bytes:
                return TransportResult(False, response.status, error="response_too_large")
            if 300 <= response.status < 400:
                return TransportResult(False, response.status, error="redirect_blocked")
            if response.status == 429:
                return TransportResult(
                    False,
                    429,
                    error="rate_limited",
                    retry_after_seconds=self._retry_after(response.getheader("Retry-After")),
                )
            if not 200 <= response.status < 300:
                return TransportResult(False, response.status, error=f"http_{response.status}")
            if not expect_json:
                return TransportResult(True, response.status, data=body.decode("utf-8", errors="replace"))
            try:
                return TransportResult(True, response.status, data=json.loads(body))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return TransportResult(False, response.status, error="invalid_json")
        except (OSError, http.client.HTTPException) as exc:
            return TransportResult(False, None, error=f"transport_error:{type(exc).__name__}")
        finally:
            connection.close()

    @staticmethod
    def _retry_after(value: str | None) -> int | None:
        if not value:
            return None
        try:
            return max(0, int(value))
        except ValueError:
            try:
                when = parsedate_to_datetime(value)
                if when.tzinfo is None:
                    when = when.replace(tzinfo=UTC)
                return max(0, int((when - datetime.now(UTC)).total_seconds()))
            except (TypeError, ValueError, OverflowError):
                return None
