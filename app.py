"""
ONDC TEAM Scheme — Verifiable Credential API.

Serves signed, machine-readable credential JSON for sellers verified under
the TEAM scheme. Buyer Apps hit these URLs (the `verify_url` from the
on_search creds schema) to confirm a seller's MSME/TEAM eligibility and
retrieve the details needed for incentive claims.

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
from schemas import Credential, Health, ServiceInfo
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
credential_service = CredentialService(signer, settings.base_url)

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
        "TEAM Creds API up | table=%r base_url=%s rate=%s kid=%s",
        settings.table_name,
        settings.base_url,
        settings.rate_limit,
        signer.key_id,
    )
    yield
    await app.state.repository.aclose()
    logger.info("TEAM Creds API shutting down")


def get_repository(request: Request) -> CredentialRepository:
    """Dependency — the async repository created during lifespan startup."""
    return request.app.state.repository


app = FastAPI(
    title="ONDC TEAM Credential Verification API",
    version="1.1.0",
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


def _credential_not_found(identifier: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={
            "error": "credential_not_found",
            "message": f"No verified TEAM credential found for {identifier}",
        },
    )


_DATASTORE_UNAVAILABLE = HTTPException(
    status_code=503,
    detail={
        "error": "datastore_unavailable",
        "message": "Credential store is temporarily unavailable",
    },
)


def _serve(row: dict, response: Response) -> dict:
    credential = credential_service.build(row)
    response.headers.update(CREDENTIAL_HEADERS)
    return credential


# ── Routes ───────────────────────────────────────────────────────────


@app.get("/", response_model=ServiceInfo, tags=["meta"])
async def root() -> ServiceInfo:
    return ServiceInfo(
        service="team-creds-api",
        version=app.version,
        docs="/docs",
        endpoints=[
            "/v1/team/{team_id}",
            "/v1/team/by-provider/{provider_id}",
            "/.well-known/jwks.json",
            "/health",
        ],
    )


@app.get("/health", response_model=Health, tags=["meta"])
async def health() -> Health:
    return Health(status="ok", service="team-creds-api")


@app.get("/.well-known/jwks.json", tags=["verification"])
async def public_key() -> dict:
    """ONDC's public key — Buyer Apps fetch this to verify signatures."""
    return signer.jwks()


@app.get("/v1/team/{team_id}", response_model=Credential, tags=["credentials"])
async def get_team_credential(
    response: Response,
    team_id: str = Path(..., min_length=1, examples=["TEAM6419"]),
    repository: CredentialRepository = Depends(get_repository),
) -> dict:
    """
    Primary endpoint — the verify_url that Buyer Apps hit.

    The Buyer App MUST cross-check that `entity.provider_id` in this
    response matches the provider_id from the on_search response to
    prevent a valid URL being reused for a different seller.
    """
    try:
        row = await repository.get_by_team_id(team_id)
    except RepositoryError:
        raise _DATASTORE_UNAVAILABLE
    if row is None:
        raise _credential_not_found(team_id)
    return _serve(row, response)


@app.get(
    "/v1/team/by-provider/{provider_id}",
    response_model=Credential,
    tags=["credentials"],
)
async def get_by_provider(
    response: Response,
    provider_id: str = Path(..., min_length=1, examples=["merchant-176467997904410987"]),
    repository: CredentialRepository = Depends(get_repository),
) -> dict:
    """Alternate lookup — when the Buyer App knows the provider but not the TEAM ID."""
    try:
        row = await repository.get_by_provider_id(provider_id)
    except RepositoryError:
        raise _DATASTORE_UNAVAILABLE
    if row is None:
        raise _credential_not_found(f"provider {provider_id}")
    return _serve(row, response)
