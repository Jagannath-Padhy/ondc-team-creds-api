"""
Builds signed TEAM credential documents from raw Supabase rows.

The signature covers everything except the `proof` block (a detached
proof): we build the payload, sign it, then attach `proof`.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from security import PROOF_TYPE, CredentialSigner

CREDENTIAL_TYPE = "MSME_TEAM"
ISSUER_NAME = "ONDC"
ISSUER_DID = "did:ondc:network"

# Database column names (with spaces / capitalisation) kept in one place.
COL_TEAM_ID = "TEAM ID"
COL_PROVIDER_ID = "Provider ID"
COL_UDYAM_NUMBER = "Udyam Number"
COL_UDYAM_STATUS = "Udyam Verification Status"
COL_MAJOR_ACTIVITY = "Major Activity"
COL_ENTERPRISE_TYPE = "Enterprise Type"
COL_VERIFIED_BY = "Verified by"
COL_VERIFIED_AT = "Verification timestamp"


def _iso_utc(moment: datetime) -> str:
    """ISO-8601 in UTC with a trailing Z (ONDC convention)."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_credential_id(team_id: str, provider_id: str) -> str:
    """
    Deterministic credential id from TEAM ID + Provider ID.

    Same inputs always yield the same id, so a given (seller, scheme)
    pair maps to exactly one credential id — a single Credit ID cannot
    legitimately belong to two different sellers.
    """
    digest = hashlib.sha256(f"{team_id}:{provider_id}".encode("utf-8")).hexdigest()[:12]
    return f"CRED-{digest}"


class CredentialService:
    """Turns a database row into a signed credential document."""

    def __init__(self, signer: CredentialSigner, base_url: str) -> None:
        self._signer = signer
        self._base_url = base_url.rstrip("/")

    def build(self, row: dict[str, Any]) -> dict[str, Any]:
        created = datetime.now(timezone.utc)

        team_id = row[COL_TEAM_ID]
        provider_id = row[COL_PROVIDER_ID]

        payload: dict[str, Any] = {
            "credential_id": generate_credential_id(team_id, provider_id),
            "credential_type": CREDENTIAL_TYPE,
            "entity": {
                "team_id": team_id,
                "provider_id": provider_id,
            },
            "verification": {
                "udyam_verified": row.get(COL_UDYAM_STATUS) or "",
                "udyam_id": row.get(COL_UDYAM_NUMBER) or "",
                "major_activity": row.get(COL_MAJOR_ACTIVITY) or "",
                "enterprise_type": row.get(COL_ENTERPRISE_TYPE) or "",
                "verified_by": row.get(COL_VERIFIED_BY) or "",
                "verified_at": row.get(COL_VERIFIED_AT) or "",
            },
            "issuer": {
                "name": ISSUER_NAME,
                "did": ISSUER_DID,
            },
        }

        # Detached proof — signature covers everything above.
        payload["proof"] = {
            "type": PROOF_TYPE,
            "created": _iso_utc(created),
            "verification_method": f"{self._base_url}/.well-known/jwks.json",
            "signature": self._signer.sign(payload),
        }
        return payload
