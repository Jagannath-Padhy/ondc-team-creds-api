"""
ONDC TEAM Scheme — Verifiable Credential API.

Serves signed, machine-readable credential JSON for sellers verified under
the TEAM scheme. Buyer Apps hit a per-seller verify_url to confirm a
seller's MSME/TEAM eligibility and retrieve the details needed for
incentive claims.

Endpoints:
    GET /health
    GET /v1/{provider_id}/{team_id}     (the verify_url)

Run:  uvicorn app:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Path, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from config import get_settings
from credentials import CredentialService
from repository import CredentialRepository, RepositoryError
from schemas import Credential, Health
from security import CredentialSigner

settings = get_settings()

logging.basicConfig(
    level=settings.log_level.upper(),
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("team_creds")

# ── Singletons (sync, cheap to construct) ────────────────────────────
# The async Supabase client is built in the lifespan (it's a coroutine)
# and stored on app.state — see `get_repository`.
signer = CredentialSigner(settings.signing_key_hex, key_id=settings.signing_key_id)
credential_service = CredentialService(signer)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.rate_limit],
    storage_uri=settings.rate_limit_storage_uri,
)

CREDENTIAL_HEADERS = {
    "Cache-Control": "public, max-age=86400",
    "X-Credential-Schema": "ondc:team-credential:v1",
}


async def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"detail": {"error": "rate_limited", "message": "Too many requests"}},
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.repository = await CredentialRepository.create(
        settings.supabase_url, settings.supabase_service_key, settings.table_name
    )
    logger.info(
        "TEAM Creds API up | table=%r rate=%s key_id=%s",
        settings.table_name,
        settings.rate_limit,
        signer.key_id,
    )
    # Public key for Buyer Apps to verify signatures (distribute out-of-band).
    logger.info("ONDC public key (hex):    %s", signer.public_key_hex)
    logger.info("ONDC public key (base64): %s", signer.public_key_b64)
    yield
    await app.state.repository.aclose()
    logger.info("TEAM Creds API shutting down")


def get_repository(request: Request) -> CredentialRepository:
    """Dependency — the async repository created during lifespan startup."""
    return request.app.state.repository


app = FastAPI(
    title="ONDC TEAM Credential Verification API",
    version="2.0.0",
    description="Signed, ONDC-hosted verifiable credentials for the MSME TEAM scheme.",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["GET"],
    allow_headers=["*"],
)


_DATASTORE_UNAVAILABLE = HTTPException(
    status_code=503,
    detail={
        "error": "datastore_unavailable",
        "message": "Credential store is temporarily unavailable",
    },
)


def _credential_not_found(provider_id: str, team_id: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={
            "error": "credential_not_found",
            "message": (
                f"No verified TEAM credential for provider {provider_id} "
                f"and TEAM ID {team_id}"
            ),
        },
    )


# ── Routes ───────────────────────────────────────────────────────────


@app.get("/health", response_model=Health, tags=["meta"])
async def health() -> Health:
    return Health(status="ok", service="team-creds-api")


@app.get("/v1/{provider_id}/{team_id}", response_model=Credential, tags=["credentials"])
async def get_credential(
    response: Response,
    provider_id: str = Path(..., min_length=1, examples=["merchant-176467997904410987"]),
    team_id: str = Path(..., min_length=1, examples=["TEAM6419"]),
    repository: CredentialRepository = Depends(get_repository),
) -> dict:
    """
    The verify_url that Buyer Apps hit.

    Requires BOTH the provider id and the TEAM ID to match a stored
    credential. A valid TEAM ID paired with the wrong provider returns
    404 — this binding stops a credential being claimed for a seller it
    does not belong to.
    """
    try:
        row = await repository.get_by_provider_and_team(provider_id, team_id)
    except RepositoryError:
        raise _DATASTORE_UNAVAILABLE
    if row is None:
        raise _credential_not_found(provider_id, team_id)

    credential = credential_service.build(row)
    response.headers.update(CREDENTIAL_HEADERS)
    return credential


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.host, port=settings.port)
