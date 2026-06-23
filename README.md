# ONDC TEAM Credential Verification API

ONDC-hosted, cryptographically signed verifiable credentials for the MSME **TEAM** scheme.

Buyer Network Providers (BNPs) hit a per-seller `verify_url` to confirm a seller's
MSME/TEAM eligibility. Each response is an Ed25519-signed JSON document so the BNP
can prove it was issued by ONDC and was not tampered with — and cross-check it against
the seller in the `on_search` response to stop a valid credential being reused for a
different seller.

## How it works

The problem: under the TEAM scheme, MSME sellers earn incentives, so a seller
app could falsely claim a seller is a verified MSME, or reuse one seller's proof
for another. This service lets a Buyer Network Provider (BNP) ask ONDC directly,
*"is this specific seller really a verified MSME — and can you prove ONDC said so?"*

The actors:

- **Seller** — an MSME on ONDC, identified by a `Provider ID` and a `TEAM ID`.
- **ONDC** — the neutral network operator. **This service is run by ONDC** and is
  the only party that can sign a credential.
- **BNP / Buyer App** — verifies a seller before honouring an incentive.

The flow:

1. **Onboarding.** ONDC verifies sellers' MSME/TEAM status (Udyam) and stores each
   as a row in Supabase: `Provider ID`, `TEAM ID`, Udyam number, activity, etc.
2. **Discovery.** For each verified seller, the `on_search` response carries a
   `verify_url` of the form `/v1/{provider_id}/{team_id}`. This URL is **hosted by
   ONDC**, not the seller app — a seller app cannot fake an ONDC-hosted URL.
3. **Lookup.** The BNP calls the `verify_url`. The API fetches the row matching
   **both** the provider id and the TEAM ID. No match → **404**. Match → it builds
   the credential JSON and **signs it with ONDC's private key**.
4. **Verification.** The BNP checks the signature with ONDC's public key, and
   confirms the credential's `provider_id` matches the seller from `on_search`.
   Both pass → the credential is trusted.

The trust model: only ONDC holds the private key, so only ONDC can produce a valid
signature. The data is public; the **signature** is what proves authenticity and
that nothing was altered. The `(provider_id, team_id)` binding in the URL stops a
valid credential being claimed for a seller it doesn't belong to.

## Architecture

| File | Responsibility |
|------|----------------|
| `config.py` | Environment loading + validation (fail-fast via pydantic-settings) |
| `security.py` | `CredentialSigner` — Ed25519 signing, derives the public key |
| `repository.py` | Async Supabase data access (`AsyncClient`), typed errors |
| `credentials.py` | Builds the signed credential document from a DB row |
| `schemas.py` | Pydantic response models (drive the OpenAPI docs) |
| `app.py` | FastAPI app: routes, rate limiting, CORS, error handling, lifespan |
| `verify_client.py` | Reference verifier for BNPs (signature + provider-match check) |

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/v1/{provider_id}/{team_id}` | The `verify_url` — signed credential for a `(provider, TEAM ID)` pair |
| `GET` | `/health` | Liveness probe |

Both the provider id and the TEAM ID must match a stored credential. A valid
TEAM ID paired with the wrong provider returns **404** — this binding stops a
credential being claimed for a seller it does not belong to. `credential_id`
equals the TEAM ID (globally unique).

## Signing & verification

Each credential is signed with **Ed25519**. The signature is a *detached proof*:
it covers the whole document **except** the `proof` block itself.

**How signing works (server side, `security.py` + `credentials.py`):**

1. **Build** the credential payload (everything except `proof`).
2. **Canonicalise** it to deterministic bytes — JSON with keys sorted and no
   whitespace (`json.dumps(payload, sort_keys=True, separators=(",", ":"))`). This
   guarantees the signer and verifier hash the exact same bytes.
3. **Hash** the canonical bytes with **SHA-256** → a fixed 32-byte digest.
4. **Sign** the digest with ONDC's **Ed25519 private key**.
5. **Encode** the signature as base64 and attach it under `proof`:

```json
"proof": {
  "type": "Ed25519Sha256",
  "created": "2026-06-23T11:28:34Z",
  "signature": "z+W5saiucmMg7RTnNjA/pZMkg8ZecRRCb..."
}
```

Credentials are signed **on demand** — freshly generated and signed on every
request, never stored — so there is always exactly one current key in play.

**How verification works (BNP side, `verify_client.py`):**

1. Fetch the credential; remove the `proof` block.
2. Canonicalise the rest the same way and SHA-256 it → the same digest.
3. base64-decode `proof.signature`.
4. Verify the signature against the digest using **ONDC's public key**. Pass → it
   was issued by ONDC and not a byte was altered (change any field and verification
   fails).
5. Confirm `entity.provider_id` matches the seller from `on_search`.

**Keys.** Only the **private** key is configured, as 64 hex characters in
`SIGNING_KEY_HEX` (hex is used because it is safe in env files and shells). The
**public** key is *derived* from it — no need to store it separately — and the
service logs it (hex + base64) at startup so the operator can distribute it to
BNPs out-of-band. The public key is **not** served by an endpoint.

> Production note: this implementation hashes with SHA-256 and returns the
> signature inside the JSON body. ONDC's network convention is BLAKE-512 with the
> signature in the HTTP `Authorization` header and the public key resolved via the
> ONDC Registry. Aligning to that convention is the main step before
> interoperating with standard ONDC verifiers. Also swap the dummy `SIGNING_KEY_HEX`
> for ONDC's real key in production.

## Setup

```bash
pip install -r requirements.txt
cp env.example .env        # then fill in real values
```

`SIGNING_KEY_HEX` is **required** and must be provided — the app does not generate one.
Generate a key with:

```bash
python -c "from nacl.signing import SigningKey; from nacl.encoding import HexEncoder; print(SigningKey.generate().encode(encoder=HexEncoder).decode())"
```

## Run

```bash
python app.py                 # binds HOST/PORT from the environment (default 0.0.0.0:8000)
# or, for local dev with reload:
uvicorn app:app --reload
```

## Run with Docker

```bash
# Build
docker build -t ondc-team-creds-api .

# Run (config from .env; PORT overridable)
docker run --env-file .env -e PORT=8000 -p 8000:8000 ondc-team-creds-api

# Or with docker compose
docker compose up --build
```

The container binds `0.0.0.0:$PORT`. `.env` is not baked into the image — pass
configuration at runtime via `--env-file` / `-e` (or `env_file` in compose).

## Configuration

All settings come from the environment (or `.env`). See `env.example` for the full list,
including `HOST`/`PORT`, `RATE_LIMIT_PER_SECOND` (default 20), `TABLE_NAME`, and
`CORS_ALLOW_ORIGINS`. For multi-worker deployments set `RATE_LIMIT_STORAGE_URI` to a
shared backend (e.g. Redis) so the rate limiter is enforced across processes.
