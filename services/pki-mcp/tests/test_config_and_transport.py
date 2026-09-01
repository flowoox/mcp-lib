from __future__ import annotations

import json

import pytest
from mcp_common.query_budget import QueryBudget, QueryBudgetLimits
from mcp_common.read_only_connector import (
    PageRequest,
    ReadOnlyConnector,
    ReadOnlyConnectorPolicy,
    ReadOnlyQuery,
)

from pki_mcp.config import Settings
from pki_mcp.scripts import SCRIPTS
from pki_mcp.transport import PKIReadOnlyTransport


def _targets(configuration_name: str = "McpPkiObserve") -> str:
    return json.dumps(
        {
            "issuing-ca": {
                "computer_name": "ca.example.invalid",
                "configuration_name": configuration_name,
                "ca_config": "ca.example.invalid\\Example Issuing CA",
            }
        }
    )


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "pki_backend_read_only": True,
        "pki_backend_view_ca_database_attested": True,
        "pki_targets_json": _targets(),
    }
    values.update(overrides)
    return Settings(**values)


def test_rejects_unrestricted_powershell_endpoint() -> None:
    settings = _settings(pki_targets_json=_targets("Microsoft.PowerShell"))
    with pytest.raises(ValueError, match="dedicated constrained JEA"):
        _ = settings.targets


def test_transport_requires_read_only_attestation() -> None:
    with pytest.raises(ValueError, match="PKI_BACKEND_READ_ONLY"):
        PKIReadOnlyTransport(_settings(pki_backend_read_only=False))


def test_transport_requires_view_database_attestation() -> None:
    with pytest.raises(ValueError, match="VIEW_CA_DATABASE"):
        PKIReadOnlyTransport(_settings(pki_backend_view_ca_database_attested=False))


class _NeverCalledTransport:
    read_only = True

    async def query(self, query, *, timeout_seconds, max_response_bytes):  # pragma: no cover
        raise AssertionError("non-allowlisted operation reached the backend")


@pytest.mark.asyncio
async def test_connector_rejects_non_allowlisted_write_operation() -> None:
    connector = ReadOnlyConnector(
        ReadOnlyConnectorPolicy(
            connector_name="pki-test",
            allowed_operations=frozenset({"pki.ca.observe"}),
        ),
        _NeverCalledTransport(),
    )
    budget = QueryBudget(QueryBudgetLimits())
    with pytest.raises(PermissionError, match="allowlist"):
        await connector.execute(
            ReadOnlyQuery(
                operation="pki.certificate.revoke",
                page=PageRequest(limit=1),
            ),
            budget,
        )


class _PayloadOnlyRunner:
    def run(self, script_id, target, payload, *, timeout_seconds, max_response_bytes):
        return (
            {
                "items": [
                    {
                        "requestId": 42,
                        "template": "1.3.6.1.4.1.311.21.8.example",
                        "notBefore": "2026-08-01T00:00:00Z",
                        "notAfter": "2026-09-15T00:00:00Z",
                        "daysRemaining": 14,
                    }
                ],
                "nextCursor": "truncated",
            },
            256,
        )


@pytest.mark.asyncio
async def test_expiring_projection_hides_backend_continuation() -> None:
    settings = _settings()
    transport = PKIReadOnlyTransport(settings, runner=_PayloadOnlyRunner())
    page = await transport.query(
        ReadOnlyQuery(
            operation="pki.certificate.list_expiring",
            parameters={"target_id": "issuing-ca", "expiry_days": 30},
            page=PageRequest(limit=10),
        ),
        timeout_seconds=5,
        max_response_bytes=4096,
    )
    assert page.truncated is True
    assert page.next_cursor is None
    assert set(page.items[0]) == {"requestId", "template", "notBefore", "notAfter", "daysRemaining"}


def test_target_alias_does_not_accept_caller_supplied_ca_config() -> None:
    settings = _settings()
    transport = PKIReadOnlyTransport(settings, runner=_PayloadOnlyRunner())
    with pytest.raises(ValueError, match="unsupported parameters"):
        transport._payload(
            ReadOnlyQuery(
                operation="pki.ca.observe",
                parameters={
                    "target_id": "issuing-ca",
                    "ca_config": "other.example.invalid\\Other CA",
                },
                page=PageRequest(limit=1),
            )
        )


def test_static_probes_exclude_mutating_admin_tools() -> None:
    rendered = "\n".join(SCRIPTS.values()).casefold()
    for forbidden in (
        "certutil",
        "start-service",
        "stop-service",
        "restart-service",
        "set-itemproperty",
        "remove-item",
        "new-selfsignedcertificate",
    ):
        assert forbidden not in rendered
