from __future__ import annotations

import json
import time
from types import SimpleNamespace
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.server.auth.provider import AccessToken

from mcp_common import mcp_security
from mcp_common.mcp_security import OidcJwtTokenVerifier, build_mcp_server_security
from mcp_common.operations import OperationContext


ISSUER = "https://idp.example.test"
RESOURCE = "https://mcp.example.test/mcp"


def _key_material() -> tuple[Any, dict[str, Any]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(
        jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key())
    )
    public_jwk.update({"kid": "test-key", "use": "sig", "alg": "RS256"})
    return private_key, public_jwk


def _token(
    private_key: Any,
    *,
    issuer: str = ISSUER,
    audience: str = RESOURCE,
    scope: str | None = "mcp.files.read",
    roles: list[str] | None = None,
    expires_in: int = 300,
    not_before_in: int = -5,
) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "sub": "subject-123",
        "oid": "object-456",
        "preferred_username": "operator@example.test",
        "exp": now + expires_in,
        "nbf": now + not_before_in,
        "azp": "client-789",
    }
    if scope is not None:
        claims["scope"] = scope
    if roles is not None:
        claims["roles"] = roles
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )


def _verifier(
    public_jwk: dict[str, Any],
    *,
    scope: str = "mcp.files.read",
    audience: str = RESOURCE,
) -> OidcJwtTokenVerifier:
    verifier = OidcJwtTokenVerifier(
        issuer=ISSUER,
        audience=audience,
        resource=RESOURCE,
        required_scopes=(scope,),
    )
    verifier._jwks = [public_jwk]
    verifier._cache_expires = float("inf")
    return verifier


@pytest.mark.asyncio
async def test_oidc_verifier_accepts_exact_signed_resource_scope() -> None:
    private_key, public_jwk = _key_material()
    access = await _verifier(public_jwk).verify_token(_token(private_key))

    assert access is not None
    assert access.subject == "subject-123"
    assert access.client_id == "client-789"
    assert access.resource == RESOURCE
    assert "mcp.files.read" in access.scopes
    assert access.claims is not None
    assert access.claims["_flowoox_auth_mode"] == "oidc"
    assert access.claims["oid"] == "object-456"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("token_kwargs", "required_scope"),
    [
        ({"issuer": "https://wrong-issuer.example.test"}, "mcp.files.read"),
        ({"audience": "https://other-resource.example.test/mcp"}, "mcp.files.read"),
        ({"expires_in": -30}, "mcp.files.read"),
        ({"not_before_in": 300}, "mcp.files.read"),
        ({"scope": "mcp.infrastructure.observe"}, "mcp.files.read"),
    ],
)
async def test_oidc_verifier_rejects_invalid_claim_boundary(
    token_kwargs: dict[str, Any],
    required_scope: str,
) -> None:
    private_key, public_jwk = _key_material()
    verifier = _verifier(public_jwk, scope=required_scope)

    assert await verifier.verify_token(_token(private_key, **token_kwargs)) is None


@pytest.mark.asyncio
async def test_oidc_verifier_accepts_explicit_application_role_as_scope() -> None:
    private_key, public_jwk = _key_material()
    verifier = _verifier(public_jwk, scope="mcp.exchange.manage")
    token = _token(
        private_key,
        scope=None,
        roles=["mcp.exchange.manage"],
    )

    access = await verifier.verify_token(token)

    assert access is not None
    assert "mcp.exchange.manage" in access.scopes


@pytest.mark.asyncio
async def test_oidc_verifier_rejects_unsigned_token() -> None:
    private_key, public_jwk = _key_material()
    del private_key
    unsigned = jwt.encode(
        {
            "iss": ISSUER,
            "aud": RESOURCE,
            "sub": "subject-123",
            "exp": int(time.time()) + 300,
            "scope": "mcp.files.read",
        },
        key="",
        algorithm="none",
        headers={"kid": "test-key"},
    )

    assert await _verifier(public_jwk).verify_token(unsigned) is None


@pytest.mark.asyncio
async def test_oidc_discovery_rejects_cross_origin_jwks(monkeypatch: pytest.MonkeyPatch) -> None:
    verifier = OidcJwtTokenVerifier(
        issuer=ISSUER,
        audience=RESOURCE,
        resource=RESOURCE,
        required_scopes=("mcp.files.read",),
    )

    async def fake_fetch(url: str) -> dict[str, Any]:
        if "well-known" in url:
            return {
                "issuer": ISSUER,
                "jwks_uri": "https://attacker.example.test/keys",
            }
        raise AssertionError("cross-origin JWKS must not be fetched")

    monkeypatch.setattr(verifier, "_fetch_json", fake_fetch)

    with pytest.raises(ValueError, match="configured issuer origin"):
        await verifier._refresh_jwks()


def test_operation_context_ignores_caller_actor_under_oidc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    access = AccessToken(
        token="secret-token-not-for-audit",
        client_id="client-789",
        scopes=["mcp.exchange.manage"],
        resource=RESOURCE,
        subject="subject-123",
        claims={
            "_flowoox_auth_mode": "oidc",
            "iss": ISSUER,
            "oid": "object-456",
            "preferred_username": "operator@example.test",
        },
    )
    monkeypatch.setattr(mcp_security, "get_access_token", lambda: access)

    context = OperationContext(actor="forged-admin", source="exchange-m365-mcp")

    assert context.actor != "forged-admin"
    assert "operator@example.test" in context.actor
    assert "object-456" in context.actor
    assert "secret-token-not-for-audit" not in context.actor


def test_static_bootstrap_keeps_legacy_actor(monkeypatch: pytest.MonkeyPatch) -> None:
    access = AccessToken(
        token="bootstrap-secret",
        client_id="configured-mcp-bootstrap-client",
        scopes=["mcp"],
        resource=RESOURCE,
        claims={"_flowoox_auth_mode": "static"},
    )
    monkeypatch.setattr(mcp_security, "get_access_token", lambda: access)

    context = OperationContext(actor="single-trusted-client", source="test")

    assert context.actor == "single-trusted-client"


def _settings(**overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "mcp_trust_boundary": "external",
        "mcp_allowed_hosts": "",
        "mcp_allowed_origins": "",
        "mcp_public_url": RESOURCE,
        "mcp_issuer_url": ISSUER,
        "mcp_auth_token": "",
        "exchange_writes_enabled": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.mark.parametrize(
    ("service_host", "expected_scope"),
    [
        ("mcp-fileshare", "mcp.files.read"),
        ("mcp-veeam", "mcp.infrastructure.observe"),
        ("mcp-network", "mcp.network.debug"),
    ],
)
def test_service_access_tiers_are_deny_default(
    service_host: str,
    expected_scope: str,
) -> None:
    security = build_mcp_server_security(
        _settings(),
        service_hosts=(service_host,),
    )

    assert security.auth is not None
    assert security.auth.required_scopes == [expected_scope]
    assert isinstance(security.token_verifier, OidcJwtTokenVerifier)


def test_exchange_write_boundary_requires_manage_scope() -> None:
    security = build_mcp_server_security(
        _settings(exchange_writes_enabled=True),
        service_hosts=("mcp-exchange-m365",),
    )

    assert security.auth is not None
    assert security.auth.required_scopes == ["mcp.exchange.manage"]


def test_static_token_remains_bootstrap_mode_with_tier_scope() -> None:
    security = build_mcp_server_security(
        _settings(mcp_auth_token="bootstrap-secret"),
        service_hosts=("mcp-network",),
    )

    assert security.auth is not None
    assert security.auth.required_scopes == ["mcp.network.debug"]
    assert not isinstance(security.token_verifier, OidcJwtTokenVerifier)
