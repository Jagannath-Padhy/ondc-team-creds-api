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
| `GET` | `/v1/team/{team_id}` | Primary `verify_url` — signed credential by TEAM ID |
| `GET` | `/v1/team/by-provider/{provider_id}` | Lookup by Provider ID |
| `GET` | `/.well-known/jwks.json` | ONDC public key (JWKS) for signature verification |
| `GET` | `/health` | Liveness probe |
| `GET` | `/` | Service info |
| `GET` | `/docs` | Swagger UI |

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
uvicorn app:app --host 0.0.0.0 --port 8000
```

## Configuration

All settings come from the environment (or `.env`). See `env.example` for the full list,
including `RATE_LIMIT_PER_SECOND` (default 300), `TABLE_NAME`, `BASE_URL`, and
`CORS_ALLOW_ORIGINS`. For multi-worker deployments set `RATE_LIMIT_STORAGE_URI` to a
shared backend (e.g. Redis) so the rate limiter is enforced across processes.
