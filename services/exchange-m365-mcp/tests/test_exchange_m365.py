import json

import httpx
import pytest
from mcp_common.query_budget import QueryBudgetLimits
from mcp_common.read_only_connector import PageRequest, ReadOnlyConnectorPolicy, ReadOnlyQuery
from pydantic import ValidationError

from exchange_m365_mcp.config import Settings
from exchange_m365_mcp.contract import capabilities
from exchange_m365_mcp.exchange_transport import ExchangeOnlineReadOnlyTransport
from exchange_m365_mcp.graph_transport import MicrosoftGraphServiceHealthTransport


def settings(**overrides: object) -> Settings:
    values = {
        "exchange_backend_read_only": True,
        "exchange_view_only_rbac_attested": True,
        "exchange_organization": "tenant.onmicrosoft.com",
        "exchange_app_id": "11111111-1111-1111-1111-111111111111",
        "exchange_certificate_thumbprint": "A" * 40,
        "m365_graph_backend_read_only": True,
        "m365_graph_service_health_permission_attested": True,
        "m365_graph_tenant_id": "22222222-2222-2222-2222-222222222222",
        "m365_graph_client_id": "33333333-3333-3333-3333-333333333333",
        "m365_graph_client_secret": "secret",
    }
    values.update(overrides)
    return Settings(**values)


class StubExchangeTransport(ExchangeOnlineReadOnlyTransport):
    def __init__(self, config: Settings, payload: object) -> None:
        super().__init__(config)
        self.payload = payload
        self.last_script = ""

    async def _invoke(self, script: str, *, timeout_seconds: float, max_response_bytes: int):
        self.last_script = script
        return self.payload


def test_backends_fail_closed_without_attestations() -> None:
    with pytest.raises(ValueError, match="EXCHANGE_BACKEND_READ_ONLY"):
        ExchangeOnlineReadOnlyTransport(settings(exchange_backend_read_only=False))
    with pytest.raises(ValueError, match="VIEW_ONLY_RBAC"):
        ExchangeOnlineReadOnlyTransport(settings(exchange_view_only_rbac_attested=False))
    with pytest.raises(ValueError, match="M365_GRAPH_BACKEND_READ_ONLY"):
        MicrosoftGraphServiceHealthTransport(settings(m365_graph_backend_read_only=False))
    with pytest.raises(ValueError, match="SERVICE_HEALTH_PERMISSION"):
        MicrosoftGraphServiceHealthTransport(
            settings(m365_graph_service_health_permission_attested=False)
        )


def test_identifiers_are_strictly_validated() -> None:
    with pytest.raises(ValidationError):
        settings(exchange_organization="mail.example.com")
    with pytest.raises(ValidationError):
        settings(exchange_app_id="not-a-uuid")
    with pytest.raises(ValidationError):
        settings(exchange_certificate_thumbprint="not-a-thumbprint")


@pytest.mark.asyncio
async def test_domains_are_hashed_and_commands_are_allowlisted() -> None:
    transport = StubExchangeTransport(
        settings(),
        [{"DomainName": "example.com", "DomainType": "Authoritative", "Default": True}],
    )
    page = await transport.query(
        ReadOnlyQuery(operation="exchange.accepted_domains.list", page=PageRequest(limit=10)),
        timeout_seconds=10,
        max_response_bytes=65536,
    )
    assert page.items[0]["domain_ref"].startswith("domain:")
    assert page.items[0]["domain_name"] is None
    assert "Get-AcceptedDomain" in transport.last_script
    assert "-CommandName $commands" in transport.last_script
    assert all(word not in transport.last_script for word in ("Set-", "New-", "Remove-"))


@pytest.mark.asyncio
async def test_connector_topology_is_reduced_to_counts() -> None:
    transport = StubExchangeTransport(
        settings(),
        [{
            "Identity": "Inbound from partner",
            "Enabled": True,
            "ConnectorType": "Partner",
            "SenderIPAddresses": ["192.0.2.10", "192.0.2.11"],
            "SenderDomains": ["partner.example"],
        }],
    )
    page = await transport.query(
        ReadOnlyQuery(operation="exchange.inbound_connectors.list", page=PageRequest(limit=10)),
        timeout_seconds=10,
        max_response_bytes=65536,
    )
    item = page.items[0]
    assert item["sender_ip_count"] == 2
    assert item["sender_domain_count"] == 1
    serialized = json.dumps(item)
    assert "192.0.2.10" not in serialized
    assert "partner.example" not in serialized
    assert "Inbound from partner" not in serialized


@pytest.mark.asyncio
async def test_exchange_adapter_rejects_free_form_parameters_and_cursors() -> None:
    transport = StubExchangeTransport(settings(), [])
    with pytest.raises(ValueError, match="free-form"):
        await transport.query(
            ReadOnlyQuery(
                operation="exchange.organization.get",
                parameters={"cmdlet": "Get-Mailbox"},
                page=PageRequest(limit=1),
            ),
            timeout_seconds=10,
            max_response_bytes=65536,
        )
    with pytest.raises(ValueError, match="first-page-only"):
        await transport.query(
            ReadOnlyQuery(
                operation="exchange.accepted_domains.list",
                page=PageRequest(limit=1, cursor="next"),
            ),
            timeout_seconds=10,
            max_response_bytes=65536,
        )


def graph_handler(request: httpx.Request) -> httpx.Response:
    if request.url.host == "login.microsoftonline.com":
        assert request.method == "POST"
        return httpx.Response(200, json={"access_token": "token", "expires_in": 3600})
    assert request.url.host == "graph.microsoft.com"
    assert request.headers["Authorization"] == "Bearer token"
    if request.url.path.endswith("/healthOverviews"):
        assert request.url.params["$select"] == "service,status"
        return httpx.Response(
            200,
            json={"value": [{"service": "Exchange Online", "status": "ServiceOperational"}]},
        )
    if request.url.path.endswith("/issues"):
        assert request.url.params["$filter"] == "service eq 'Exchange Online'"
        assert "posts" not in request.url.params["$select"]
        assert "impactDescription" not in request.url.params["$select"]
        return httpx.Response(
            200,
            json={"value": [{
                "id": "EX12345",
                "service": "Exchange Online",
                "status": "ServiceDegradation",
                "classification": "Advisory",
                "origin": "Microsoft",
                "feature": "Mail flow",
                "featureGroup": "Transport",
                "startDateTime": "2026-09-02T07:00:00Z",
                "lastModifiedDateTime": "2026-09-02T08:00:00Z",
                "impactDescription": "sensitive long description",
                "posts": [{"description": {"content": "sensitive update body"}}],
            }]},
        )
    raise AssertionError(f"unexpected URL: {request.url}")


@pytest.mark.asyncio
async def test_graph_uses_fixed_minimized_queries_and_projections() -> None:
    transport = MicrosoftGraphServiceHealthTransport(
        settings(), transport=httpx.MockTransport(graph_handler)
    )
    health = await transport.query(
        ReadOnlyQuery(operation="m365.service_health.list", page=PageRequest(limit=10)),
        timeout_seconds=10,
        max_response_bytes=65536,
    )
    assert health.items == [{"service": "Exchange Online", "status": "ServiceOperational"}]
    issues = await transport.query(
        ReadOnlyQuery(operation="m365.exchange_issues.list", page=PageRequest(limit=10)),
        timeout_seconds=10,
        max_response_bytes=65536,
    )
    serialized = json.dumps(issues.items[0])
    assert issues.items[0]["issue_ref"].startswith("issue:")
    assert "EX12345" not in serialized
    assert "sensitive long description" not in serialized
    assert "sensitive update body" not in serialized


@pytest.mark.asyncio
async def test_graph_adapter_rejects_free_form_parameters() -> None:
    transport = MicrosoftGraphServiceHealthTransport(
        settings(), transport=httpx.MockTransport(graph_handler)
    )
    with pytest.raises(ValueError, match="free-form"):
        await transport.query(
            ReadOnlyQuery(
                operation="m365.exchange_issues.list",
                parameters={"filter": "service eq 'Anything'"},
                page=PageRequest(limit=10),
            ),
            timeout_seconds=10,
            max_response_bytes=65536,
        )


def test_capabilities_advertise_read_only_boundaries() -> None:
    exchange = ReadOnlyConnectorPolicy(
        connector_name="exchange.online.powershell.readonly",
        allowed_operations=frozenset({"exchange.organization.get"}),
    )
    graph = ReadOnlyConnectorPolicy(
        connector_name="microsoft.graph.service-health.readonly",
        allowed_operations=frozenset({"m365.service_health.list"}),
    )
    payload = capabilities(exchange, graph, QueryBudgetLimits(), return_domain_names=False)
    assert payload["mode"] == "read_only"
    assert payload["backends"]["exchangeOnline"]["previewAdminApiUsed"] is False
    assert payload["backends"]["microsoftGraph"]["applicationPermission"] == "ServiceHealth.Read.All"
    assert payload["safety"]["callerSelectedPowerShell"] is False
    assert payload["safety"]["domainNamesReturned"] is False
