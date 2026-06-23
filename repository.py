"""
Supabase data-access layer for TEAM credentials.

Uses the async Supabase client so that `.execute()` is awaited as
non-blocking I/O — a synchronous client would block the event loop for
the duration of each network round-trip and serialise requests under load.

Keeps all knowledge of the (space-containing) column names and the
underlying client in one place. Query failures are surfaced as a typed
RepositoryError so routes can translate them into a clean 503.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from supabase import AsyncClient, create_async_client

logger = logging.getLogger(__name__)


class RepositoryError(RuntimeError):
    """Raised when the credential store cannot be reached or errors out."""


class CredentialRepository:
    TEAM_ID_COLUMN = "TEAM ID"
    PROVIDER_ID_COLUMN = "Provider ID"

    def __init__(self, client: AsyncClient, table_name: str) -> None:
        self._client = client
        self._table = table_name

    @classmethod
    async def create(cls, url: str, service_key: str, table_name: str) -> "CredentialRepository":
        """Async factory — `create_async_client` is a coroutine, so build here."""
        client = await create_async_client(url, service_key)
        return cls(client, table_name)

    async def get_by_provider_and_team(
        self, provider_id: str, team_id: str
    ) -> Optional[dict[str, Any]]:
        """
        Fetch the credential matching BOTH the provider and the TEAM ID.

        Requiring both enforces the provider<->credential binding: a valid
        TEAM ID paired with the wrong provider returns nothing, so a
        credential cannot be claimed for a seller it doesn't belong to.
        """
        try:
            result = await (
                self._client.table(self._table)
                .select("*")
                .eq(self.PROVIDER_ID_COLUMN, provider_id)
                .eq(self.TEAM_ID_COLUMN, team_id)
                .limit(1)
                .execute()
            )
        except Exception as exc:  # postgrest/httpx raise a range of error types
            logger.exception(
                "Credential lookup failed (provider=%r team=%r)", provider_id, team_id
            )
            raise RepositoryError(str(exc)) from exc

        return result.data[0] if result.data else None

    async def aclose(self) -> None:
        """Close the underlying HTTP connections. Call on app shutdown."""
        await self._client.postgrest.aclose()
