"""
Builds signed TEAM credential documents from raw Supabase rows.

The signature covers everything except the `proof` block (a detached
proof): we build the payload, sign it, then attach `proof`.

`credential_id` is the TEAM ID itself — a TEAM ID is globally unique and
maps to exactly one seller, so it doubles as the credential identifier.
"""

from __future__ import annotations

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


class CredentialService:
    """Turns a database row into a signed credential document."""

    def __init__(self, signer: CredentialSigner) -> None:
        self._signer = signer

    def build(self, row: dict[str, Any]) -> dict[str, Any]:
        created = datetime.now(timezone.utc)

        team_id = row[COL_TEAM_ID]
        provider_id = row[COL_PROVIDER_ID]

        payload: dict[str, Any] = {
            "credential_id": team_id,  # TEAM ID is the credential id
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
        # `key_id` identifies which ONDC public key verifies this signature;
        # Buyer Apps hold that key out-of-band.
        payload["proof"] = {
            "type": PROOF_TYPE,
            "created": _iso_utc(created),
            "key_id": self._signer.key_id,
            "signature": self._signer.sign(payload),
        }
        return payload
