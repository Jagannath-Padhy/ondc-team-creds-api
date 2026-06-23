"""
verify_client.py

Reference implementation for Buyer Apps to verify TEAM credentials.
Share this with Buyer App engineering teams.

What this does:
    1. Fetches the credential JSON from the verify_url
    2. Fetches ONDC's public key from /.well-known/jwks.json
    3. Verifies the Ed25519 signature to confirm ONDC issued it
    4. Cross-checks provider_id against the on_search response

CRITICAL: The Buyer App MUST check that the provider_id in the
signed credential matches the provider_id in the on_search response.
Without this check, a Seller App could reuse a valid verify_url
from Seller A for Seller B.
"""

import hashlib
import json

import requests
from nacl.encoding import Base64Encoder, HexEncoder
from nacl.signing import VerifyKey

DEFAULT_KEY_ID = "team-creds-v1"


def _public_key_hex(jwks: dict, key_id: str) -> str | None:
    """Find the hex public key for the given kid in a JWKS document."""
    for key in jwks.get("keys", []):
        if key.get("kid") == key_id:
            return key.get("x_hex")
    return None


def verify_team_credential(
    verify_url: str,
    expected_provider_id: str | None = None,
    key_id: str = DEFAULT_KEY_ID,
) -> dict:
    """
    Fetch and verify a TEAM credential from its verify_url.

    Args:
        verify_url: From on_search -> creds -> verify_url
                    e.g. "https://creds.ondc.org/v1/team/TEAM6419"
        expected_provider_id: The provider_id from the on_search response.
                              If provided, cross-checks against the credential.
        key_id: The JWKS key id to verify against (defaults to team-creds-v1).
    """
    # 1. Fetch the credential
    resp = requests.get(verify_url, timeout=10)
    resp.raise_for_status()
    data = resp.json()

    proof = data["proof"]

    # 2. Reconstruct the signed payload (everything except "proof")
    credential_payload = {k: v for k, v in data.items() if k != "proof"}

    # 3. Fetch ONDC's public key
    jwks_resp = requests.get(proof["verification_method"], timeout=10)
    jwks_resp.raise_for_status()
    pub_key_hex = _public_key_hex(jwks_resp.json(), key_id)
    if not pub_key_hex:
        return {"verified": False, "error": f"Public key '{key_id}' not found in JWKS"}

    # 4. Verify the signature
    verify_key = VerifyKey(pub_key_hex, encoder=HexEncoder)
    canonical = json.dumps(credential_payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    try:
        verify_key.verify(digest, Base64Encoder.decode(proof["signature"]))
        signature_valid = True
    except Exception:
        signature_valid = False

    # 5. Cross-check provider_id (CRITICAL for replay attack prevention)
    provider_id_match = True
    if expected_provider_id:
        provider_id_match = data["entity"]["provider_id"] == expected_provider_id

    return {
        "signature_valid": signature_valid,
        "provider_id_match": provider_id_match,
        "verified": signature_valid and provider_id_match,
        "credential_id": data.get("credential_id"),
        "team_id": data["entity"]["team_id"],
        "provider_id": data["entity"]["provider_id"],
        "udyam_id": data["verification"]["udyam_id"],
        "udyam_verified": data["verification"]["udyam_verified"],
        "major_activity": data["verification"]["major_activity"],
        "enterprise_type": data["verification"]["enterprise_type"],
        "verified_at": data["verification"]["verified_at"],
    }


# ── Example usage ────────────────────────────────────────────────────
if __name__ == "__main__":
    # Simulates what a Buyer App does when processing on_search.
    # These come from the on_search response:
    verify_url = "http://localhost:8000/v1/team/TEAM6419"
    provider_id_from_on_search = "merchant-176467997904410987"

    print(f"Fetching credential: {verify_url}")
    print(f"Expected provider:   {provider_id_from_on_search}\n")

    try:
        result = verify_team_credential(
            verify_url, expected_provider_id=provider_id_from_on_search
        )
        if result.get("verified"):
            print("✓ VERIFIED — credential is genuine and matches provider")
            print(f"  Credential ID:   {result['credential_id']}")
            print(f"  TEAM ID:         {result['team_id']}")
            print(f"  Provider:        {result['provider_id']}")
            print(f"  Udyam:           {result['udyam_id']}")
            print(f"  Udyam verified:  {result['udyam_verified']}")
            print(f"  Activity:        {result['major_activity']}")
            print(f"  Enterprise type: {result['enterprise_type']}")
        else:
            if "error" in result:
                print(f"✗ {result['error']}")
            if not result.get("signature_valid", True):
                print("✗ SIGNATURE INVALID — credential not issued by ONDC")
            if not result.get("provider_id_match", True):
                print("✗ PROVIDER MISMATCH — possible replay attack")
                print(f"  Credential says: {result['provider_id']}")
                print(f"  on_search says:  {provider_id_from_on_search}")
    except requests.exceptions.ConnectionError:
        print("(Cannot reach server — start it with: uvicorn app:app)")
