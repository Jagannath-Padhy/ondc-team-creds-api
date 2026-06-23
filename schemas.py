"""Pydantic response models — drive validation and the OpenAPI docs."""

from __future__ import annotations

from pydantic import BaseModel


class Entity(BaseModel):
    team_id: str
    provider_id: str


class Verification(BaseModel):
    udyam_verified: str
    udyam_id: str
    major_activity: str
    enterprise_type: str
    verified_by: str
    verified_at: str


class Issuer(BaseModel):
    name: str
    did: str


class Proof(BaseModel):
    type: str
    created: str
    verification_method: str
    signature: str


class Credential(BaseModel):
    credential_id: str
    credential_type: str
    entity: Entity
    verification: Verification
    issuer: Issuer
    proof: Proof


class Health(BaseModel):
    status: str
    service: str


class ServiceInfo(BaseModel):
    service: str
    version: str
    docs: str
    endpoints: list[str]
