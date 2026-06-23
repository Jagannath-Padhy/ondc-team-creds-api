# ONDC TEAM Credential Verification API

ONDC-hosted, cryptographically signed verifiable credentials for the MSME **TEAM** scheme.

Buyer Network Providers (BNPs) hit a per-seller `verify_url` to confirm a seller's
MSME/TEAM eligibility. Each response is an Ed25519-signed JSON document so the BNP
can prove it was issued by ONDC and was not tampered with — and cross-check it against
the seller in the `on_search` response to stop a valid credential being reused for a
different seller.

## Architecture

| File | Responsibility |
|------|----------------|
| `config.py` | Environment loading + validation (fail-fast via pydantic-settings) |
| `security.py` | `CredentialSigner` — Ed25519 signing and JWKS public-key publication |
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
credential being claimed for a seller it does not belong to.

`credential_id` equals the TEAM ID (globally unique). The response is unchanged
apart from the `proof` block, which carries a `key_id` identifying which ONDC
public key verifies the signature.

### Public key for verification

ONDC's public key is **not** served by this API; Buyer Apps obtain it
out-of-band. The service logs the public key (hex + base64) at startup so the
operator can distribute it. `proof.key_id` tells a verifier which key to use
(supports key rotation).

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
including `HOST`/`PORT`, `RATE_LIMIT_PER_SECOND` (default 300), `TABLE_NAME`, and
`CORS_ALLOW_ORIGINS`. For multi-worker deployments set `RATE_LIMIT_STORAGE_URI` to a
shared backend (e.g. Redis) so the rate limiter is enforced across processes.
