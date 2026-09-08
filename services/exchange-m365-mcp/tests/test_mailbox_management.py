import pytest
from mcp_common.operations import ApprovalState
from pydantic import ValidationError

from exchange_m365_mcp.config import Settings
from exchange_m365_mcp.mailbox_debug import _validate_identity
from exchange_m365_mcp.mailbox_management import (
    ExchangeOnlineMailboxManagementTransport,
    SharedMailboxPlanRequest,
    _plan_payload,
    _validate_allowed_domain,
)


def write_settings(**overrides: object) -> Settings:
    values = {
        "exchange_backend_read_only": True,
        "exchange_view_only_rbac_attested": True,
        "exchange_organization": "tenant.onmicrosoft.com",
        "exchange_app_id": "11111111-1111-1111-1111-111111111111",
        "exchange_certificate_thumbprint": "A" * 40,
        "exchange_writes_enabled": True,
        "exchange_recipient_write_rbac_attested": True,
        "exchange_management_app_id": "44444444-4444-4444-4444-444444444444",
        "exchange_management_certificate_thumbprint": "B" * 40,
        "exchange_mailbox_allowed_domains": "example.com",
        "exchange_approval_secret": "x" * 32,
    }
    values.update(overrides)
    return Settings(**values)


def mailbox_request(**overrides: object) -> SharedMailboxPlanRequest:
    values = {
        "display_name": "IT Service",
        "alias": "it-service",
        "primary_smtp_address": "it-service@example.com",
        "idempotency_key": "exchange-mailbox-0001",
    }
    values.update(overrides)
    return SharedMailboxPlanRequest(**values)


def test_write_boundary_fails_closed_without_attestation_or_approval_secret() -> None:
    config = write_settings(exchange_recipient_write_rbac_attested=False)
    with pytest.raises(ValueError, match="RBAC_ATTESTED"):
        config.validate_write_boundary()

    config = write_settings(exchange_approval_secret="short")
    with pytest.raises(ValueError, match="32 bytes"):
        config.validate_write_boundary()


def test_write_boundary_requires_distinct_read_and_management_identity() -> None:
    config = write_settings(
        exchange_management_app_id="11111111-1111-1111-1111-111111111111"
    )
    with pytest.raises(ValueError, match="distinct app IDs"):
        config.validate_write_boundary()

    config = write_settings(exchange_management_certificate_thumbprint="A" * 40)
    with pytest.raises(ValueError, match="distinct app IDs"):
        config.validate_write_boundary()


def test_mailbox_domain_allowlist_is_exact_and_has_no_wildcards() -> None:
    config = write_settings(exchange_mailbox_allowed_domains="example.com,corp.example.com")
    _validate_allowed_domain(config, "service@example.com")
    _validate_allowed_domain(config, "service@corp.example.com")

    with pytest.raises(PermissionError, match="not included"):
        _validate_allowed_domain(config, "service@sub.example.com")

    with pytest.raises(ValidationError):
        write_settings(exchange_mailbox_allowed_domains="*.example.com")


def test_shared_mailbox_request_rejects_wildcards_and_bad_aliases() -> None:
    with pytest.raises(ValidationError):
        mailbox_request(primary_smtp_address="*@example.com")
    with pytest.raises(ValidationError):
        mailbox_request(alias="it service")


def test_debug_identity_requires_one_exact_smtp_address() -> None:
    assert _validate_identity("IT-Service@Example.com") == "it-service@example.com"
    with pytest.raises(ValueError, match="exact SMTP"):
        _validate_identity("*@example.com")
    with pytest.raises(ValueError, match="exact SMTP"):
        _validate_identity("it-service")


def test_plan_requires_approval_and_binds_exact_desired_state() -> None:
    request = mailbox_request()
    payload = _plan_payload(
        request=request,
        current=None,
        actor="it-admin@example.com",
        reason="Create the approved IT service shared mailbox",
        correlation_id="",
    )
    assert payload["plan"]["approval"]["state"] == ApprovalState.REQUIRED.value
    assert payload["plan"]["risk"] == "high"
    assert payload["approvalBinding"] == {
        "operation": "exchange.mailbox.shared.create.change",
        "target": "mailbox:it-service@example.com",
        "idempotencyKey": "exchange-mailbox-0001",
        "intent": {
            "mailboxType": "shared",
            "displayName": "IT Service",
            "alias": "it-service",
            "primarySmtpAddress": "it-service@example.com",
        },
    }


def test_plan_rejects_conflicting_existing_recipient() -> None:
    request = mailbox_request()
    with pytest.raises(ValueError, match="different state"):
        _plan_payload(
            request=request,
            current={
                "DisplayName": "Other",
                "Alias": "other",
                "PrimarySmtpAddress": "it-service@example.com",
                "RecipientTypeDetails": "UserMailbox",
            },
            actor="it-admin@example.com",
            reason="Preflight",
            correlation_id="",
        )


class StubManagementTransport(ExchangeOnlineMailboxManagementTransport):
    def __init__(self, config: Settings) -> None:
        super().__init__(config)
        self.commands: tuple[str, ...] = ()
        self.body = ""
        self.environment: dict[str, str] = {}

    async def _invoke(self, *, commands, body, environment):
        self.commands = commands
        self.body = body
        self.environment = dict(environment)
        return {
            "changed": True,
            "mailbox": {
                "DisplayName": "IT Service",
                "Alias": "it-service",
                "PrimarySmtpAddress": "it-service@example.com",
                "RecipientTypeDetails": "SharedMailbox",
                "ExternalDirectoryObjectId": "opaque-object-id",
            },
        }


@pytest.mark.asyncio
async def test_management_adapter_uses_static_cmdlets_and_environment_parameters() -> None:
    transport = StubManagementTransport(write_settings())
    request = mailbox_request()
    result = await transport.create_shared_mailbox(request)

    assert transport.commands == ("Get-Mailbox", "New-Mailbox")
    assert "$env:MCP_EXCHANGE_TARGET_ADDRESS" in transport.body
    assert "it-service@example.com" not in transport.body
    assert transport.environment["MCP_EXCHANGE_TARGET_ADDRESS"] == "it-service@example.com"
    assert result["changed"] is True
