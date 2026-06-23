"""
Cryptographic signing for TEAM credentials.

Signing scheme:
    canonical JSON (sorted keys, no whitespace) -> SHA-256 digest
    -> Ed25519 signature -> base64.

The same canonicalisation is used by the verifier (see verify_client.py),
so a Buyer App can independently reconstruct the signed bytes.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from nacl.encoding import Base64Encoder, HexEncoder
from nacl.signing import SigningKey, VerifyKey

PROOF_TYPE = "Ed25519Sha256"


class CredentialSigner:
    """Holds the Ed25519 key pair and produces signatures / public-key material."""

    def __init__(self, signing_key_hex: str, key_id: str = "team-creds-v1") -> None:
        self._signing_key = SigningKey(signing_key_hex, encoder=HexEncoder)
        self.verify_key: VerifyKey = self._signing_key.verify_key
        self.key_id = key_id

    @staticmethod
    def canonical_digest(payload: dict[str, Any]) -> bytes:
        """Deterministic SHA-256 digest of a payload's canonical JSON form."""
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).digest()

    def sign(self, payload: dict[str, Any]) -> str:
        """Return the base64 Ed25519 signature over the payload's canonical digest."""
        signature = self._signing_key.sign(self.canonical_digest(payload)).signature
        return Base64Encoder.encode(signature).decode()

    def jwks(self) -> dict[str, Any]:
        """Public key in JWKS format (with a hex convenience field)."""
        return {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": self.verify_key.encode(encoder=Base64Encoder).decode(),
                    "x_hex": self.verify_key.encode(encoder=HexEncoder).decode(),
                    "use": "sig",
                    "kid": self.key_id,
                }
            ]
        }
