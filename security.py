"""
Cryptographic signing for TEAM credentials.

Signing scheme:
    canonical JSON (sorted keys, no whitespace) -> SHA-256 digest
    -> Ed25519 signature -> base64.

The same canonicalisation is used by the verifier (see verify_client.py),
so a Buyer App can independently reconstruct the signed bytes.

Only the private key is configured (SIGNING_KEY_HEX); the public key is
derived from it (`public_key_hex` / `public_key_b64`) and distributed to
Buyer Apps out-of-band so they can verify signatures.
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

    def __init__(self, signing_key_hex: str) -> None:
        self._signing_key = SigningKey(signing_key_hex, encoder=HexEncoder)
        self.verify_key: VerifyKey = self._signing_key.verify_key

    @staticmethod
    def canonical_digest(payload: dict[str, Any]) -> bytes:
        """Deterministic SHA-256 digest of a payload's canonical JSON form."""
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).digest()

    def sign(self, payload: dict[str, Any]) -> str:
        """Return the base64 Ed25519 signature over the payload's canonical digest."""
        signature = self._signing_key.sign(self.canonical_digest(payload)).signature
        return Base64Encoder.encode(signature).decode()

    @property
    def public_key_hex(self) -> str:
        """Public key as hex — distribute this to Buyer Apps for verification."""
        return self.verify_key.encode(encoder=HexEncoder).decode()

    @property
    def public_key_b64(self) -> str:
        """Public key as base64."""
        return self.verify_key.encode(encoder=Base64Encoder).decode()
