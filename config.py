"""
Application configuration.

All settings are loaded from environment variables (or a local .env file)
and validated at startup. If a required value is missing or malformed the
process fails fast with a clear error instead of starting in a broken state.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_HEX_DIGITS = set("0123456789abcdefABCDEF")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Supabase (required) ──────────────────────────────────────────
    supabase_url: str = Field(..., description="Supabase project URL")
    supabase_service_key: str = Field(..., description="Supabase service-role key")

    # ── Signing (required) ───────────────────────────────────────────
    # Provided via env only — the app never generates one at runtime.
    signing_key_hex: str = Field(..., description="Ed25519 private key (64 hex chars)")
    signing_key_id: str = Field("team-creds-v1", description="Key id published in JWKS")

    # ── Server ───────────────────────────────────────────────────────
    host: str = Field("0.0.0.0", description="Bind host")
    port: int = Field(8000, ge=1, le=65535, description="Bind port")

    # ── App config ───────────────────────────────────────────────────
    table_name: str = Field("MSME TEAM Scheme Tag", description="Supabase table holding credentials")

    # ── Rate limiting ────────────────────────────────────────────────
    rate_limit_per_second: int = Field(300, ge=1, description="Max requests/sec per client IP")
    rate_limit_storage_uri: str = Field(
        "memory://",
        description="limits storage backend; use redis://... in multi-worker prod",
    )

    # ── CORS / logging ───────────────────────────────────────────────
    cors_allow_origins: str = Field("*", description="Comma-separated origins, or * for any")
    log_level: str = Field("INFO", description="Python logging level")

    @field_validator("signing_key_hex")
    @classmethod
    def _validate_signing_key(cls, value: str) -> str:
        value = value.strip()
        if len(value) != 64 or any(c not in _HEX_DIGITS for c in value):
            raise ValueError(
                "SIGNING_KEY_HEX must be exactly 64 hex characters (a 32-byte Ed25519 seed)"
            )
        return value

    @property
    def rate_limit(self) -> str:
        """Rate limit in the string form the `limits` library expects."""
        return f"{self.rate_limit_per_second}/second"

    @property
    def cors_origins(self) -> list[str]:
        raw = self.cors_allow_origins.strip()
        if not raw or raw == "*":
            return ["*"]
        return [origin.strip() for origin in raw.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return the validated settings singleton, or fail with a clear message."""
    try:
        return Settings()
    except ValidationError as exc:
        raise RuntimeError(
            "Invalid or missing environment configuration.\n"
            "Copy env.example to .env and fill in the required values.\n\n"
            f"{exc}"
        ) from exc
