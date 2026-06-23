"""
verify_client.py

Reference implementation for Buyer Apps to verify TEAM credentials.
Share this with Buyer App engineering teams.

What this does:
    1. Fetches the credential JSON from the verify_url
    2. Verifies the Ed25519 signature using ONDC's public key
    3. Cross-checks provider_id against the on_search response

ONDC's public key is obtained out-of-band (it is not served by this API).
Pass it as `public_key_hex`; the `proof.key_id` field tells you which key
was used, so you can pick the right one if ONDC rotates keys.

CRITICAL: The Buyer App MUST check that the provider_id in the signed
credential matches the provider_id in the on_search response. The server
already binds them (the verify_url contains the provider id), but this is
defence-in-depth.
"""

import hashlib
import json

import requests
from nacl.encoding import Base64Encoder, HexEncoder
from nacl.signing import VerifyKey


def verify_team_credential(
    verify_url: str,
    public_key_hex: str,
    expected_provider_id: str | None = None,
) -> dict:
    """
    Fetch and verify a TEAM credential from its verify_url.

    Args:
        verify_url: From on_search -> creds -> verify_url
                    e.g. "https://creds.ondc.org/v1/merchant-123/TEAM6419"
        public_key_hex: ONDC's Ed25519 public key (hex), obtained out-of-band.
        expected_provider_id: The provider_id from the on_search response.
                              If provided, cross-checks against the credential.
    """
    # 1. Fetch the credential
    resp = requests.get(verify_url, timeout=10)
    resp.raise_for_status()
    data = resp.json()

    proof = data["proof"]

    # 2. Reconstruct the signed payload (everything except "proof")
    credential_payload = {k: v for k, v in data.items() if k != "proof"}

    # 3. Verify the signature with ONDC's public key
    verify_key = VerifyKey(public_key_hex, encoder=HexEncoder)
    canonical = json.dumps(credential_payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    try:
        verify_key.verify(digest, Base64Encoder.decode(proof["signature"]))
        signature_valid = True
    except Exception:
        signature_valid = False

    # 4. Cross-check provider_id (defence-in-depth against credential reuse)
    provider_id_match = True
    if expected_provider_id:
        provider_id_match = data["entity"]["provider_id"] == expected_provider_id

    return {
        "signature_valid": signature_valid,
        "provider_id_match": provider_id_match,
        "verified": signature_valid and provider_id_match,
        "credential_id": data.get("credential_id"),
        "key_id": proof.get("key_id"),
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
    provider_id = "merchant-176467997904410987"
    team_id = "TEAM6419"
    verify_url = f"http://localhost:8000/v1/{provider_id}/{team_id}"

    # ONDC's public key, obtained out-of-band (printed in the API's startup log).
    ondc_public_key_hex = (
        "54a0b3d04ee5aa17a9f83613473bbb4546c23766d68d1cbd62fc60463c27777f"
    )

    print(f"Fetching credential: {verify_url}")
    print(f"Expected provider:   {provider_id}\n")

    try:
        result = verify_team_credential(
            verify_url, ondc_public_key_hex, expected_provider_id=provider_id
        )
        if result["verified"]:
            print("✓ VERIFIED — credential is genuine and matches provider")
            print(f"  Credential ID:   {result['credential_id']}")
            print(f"  Key ID:          {result['key_id']}")
            print(f"  TEAM ID:         {result['team_id']}")
            print(f"  Provider:        {result['provider_id']}")
            print(f"  Udyam:           {result['udyam_id']}")
            print(f"  Udyam verified:  {result['udyam_verified']}")
            print(f"  Activity:        {result['major_activity']}")
            print(f"  Enterprise type: {result['enterprise_type']}")
        else:
            if not result["signature_valid"]:
                print("✗ SIGNATURE INVALID — credential not issued by ONDC")
            if not result["provider_id_match"]:
                print("✗ PROVIDER MISMATCH — possible credential reuse")
    except requests.exceptions.ConnectionError:
        print("(Cannot reach server — start it with: uvicorn app:app)")
