from __future__ import annotations

import asyncio
from typing import Any

from mcp.server.fastmcp import FastMCP

from .changes import authorize_change, change_response, verify_response
from .config import Settings
from .credential_bootstrap import (
    CredentialBootstrapChangeRequest,
    CredentialBootstrapPlanRequest,
    CredentialReceiptStore,
    FileSecretResolver,
    analyze_credential_preflight,
    build_credential_bootstrap_plan,
    credential_bootstrap_verification,
    credential_target,
    receipt_matches_plan,
)
from .provisioning_scripts import ProvisioningScriptId
from .runner import PowerShellRunner


def register_credential_tools(
    mcp: FastMCP,
    *,
    runner: PowerShellRunner,
    settings: Settings,
) -> None:
    """Register initial-password tools without exposing password material to MCP."""

    async def probe(
        script_id: ProvisioningScriptId, payload: dict[str, Any]
    ) -> dict[str, Any]:
        return await asyncio.to_thread(runner.run, script_id, payload)

    def receipt_store(*, required: bool) -> CredentialReceiptStore | None:
        path = settings.ad_credential_receipt_store.strip()
        if not path:
            if required:
                raise PermissionError(
                    "credential bootstrap requires AD_CREDENTIAL_RECEIPT_STORE"
                )
            return None
        return CredentialReceiptStore(path)

    def require_bootstrap() -> tuple[FileSecretResolver, CredentialReceiptStore]:
        if not settings.ad_writes_enabled:
            raise PermissionError("AD mutation tools are disabled by AD_WRITES_ENABLED=false")
        if not settings.ad_credential_bootstrap_enabled:
            raise PermissionError(
                "AD credential bootstrap is disabled by AD_CREDENTIAL_BOOTSTRAP_ENABLED=false"
            )
        return (
            FileSecretResolver(settings.ad_credential_secret_directory),
            CredentialReceiptStore(settings.ad_credential_receipt_store),
        )

    @mcp.tool()
    async def plan_user_credential_bootstrap(
        identity: str,
        secret_ref: str,
        idempotency_key: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Plan initial password establishment using only an opaque runtime secret reference."""

        request = CredentialBootstrapPlanRequest(
            identity=identity,
            secret_ref=secret_ref,
            idempotency_key=idempotency_key,
        )
        preflight = await probe(
            ProvisioningScriptId.PREFLIGHT_CREDENTIAL_BOOTSTRAP,
            {"identity": request.identity},
        )
        observed = analyze_credential_preflight(preflight)
        store = receipt_store(required=False)
        receipt = store.get(request.idempotency_key) if store is not None else None
        matching_receipt = receipt_matches_plan(
            receipt,
            object_guid=observed["objectGuid"],
            secret_ref=request.secret_ref,
        )
        return build_credential_bootstrap_plan(
            request=request,
            preflight=preflight,
            correlation_id=correlation_id,
            matching_verified_receipt=matching_receipt,
        )

    @mcp.tool()
    async def change_user_credential_bootstrap(
        identity: str,
        secret_ref: str,
        expected_object_guid: str,
        idempotency_key: str,
        approval_grant: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Set one initial AD password from a runtime-only secret reference after approval."""

        resolver, store = require_bootstrap()
        request = CredentialBootstrapChangeRequest(
            identity=identity,
            secret_ref=secret_ref,
            expected_object_guid=expected_object_guid,
            idempotency_key=idempotency_key,
            approval_grant=approval_grant,
        )
        target = credential_target(request.expected_object_guid)
        approval = authorize_change(
            grant=request.approval_grant,
            secret=settings.ad_approval_secret,
            operation="ad.user.credential-bootstrap.change",
            target=target,
            idempotency_key=request.idempotency_key,
            intent=request.approval_intent(request.expected_object_guid),
        )
        preflight = await probe(
            ProvisioningScriptId.PREFLIGHT_CREDENTIAL_BOOTSTRAP,
            {"identity": request.identity},
        )
        observed = analyze_credential_preflight(
            preflight,
            expected_object_guid=request.expected_object_guid,
        )
        existing_receipt = store.get(request.idempotency_key)
        if receipt_matches_plan(
            existing_receipt,
            object_guid=request.expected_object_guid,
            secret_ref=request.secret_ref,
        ):
            verification = credential_bootstrap_verification(
                preflight=preflight,
                expected_object_guid=request.expected_object_guid,
            )
            if not verification.passed:
                raise RuntimeError(
                    "verified credential receipt conflicts with current AD credential state"
                )
            return change_response(
                operation="ad.user.credential-bootstrap.change",
                target=target,
                correlation_id=correlation_id,
                idempotency_key=request.idempotency_key,
                changed=False,
                output={
                    "objectGuid": request.expected_object_guid,
                    "credentialEstablished": True,
                    "idempotentReceipt": True,
                },
                approval=approval,
                verification=verification,
            )

        if existing_receipt is None and observed["credentialEstablished"]:
            raise ValueError(
                "AD user already has credential state without a matching bootstrap receipt; refusing an implicit password reset"
            )

        secret = await asyncio.to_thread(resolver.resolve, request.secret_ref)
        fingerprint = CredentialReceiptStore.secret_fingerprint(
            secret,
            key=settings.ad_approval_secret,
        )
        receipt = store.prepare(
            idempotency_key=request.idempotency_key,
            object_guid=request.expected_object_guid,
            secret_ref=request.secret_ref,
            secret_fingerprint=fingerprint,
            pre_password_last_set=observed["passwordLastSet"],
        )

        if receipt.get("status") == "pending" and observed["credentialEstablished"]:
            verification = credential_bootstrap_verification(
                preflight=preflight,
                expected_object_guid=request.expected_object_guid,
            )
            if not verification.passed:
                raise RuntimeError("pending credential receipt could not be recovered safely")
            password_last_set = str(verification.details.get("passwordLastSet") or "")
            if not password_last_set:
                raise RuntimeError("credential recovery did not produce passwordLastSet evidence")
            store.mark_verified(
                idempotency_key=request.idempotency_key,
                object_guid=request.expected_object_guid,
                observed_password_last_set=password_last_set,
            )
            return change_response(
                operation="ad.user.credential-bootstrap.change",
                target=target,
                correlation_id=correlation_id,
                idempotency_key=request.idempotency_key,
                changed=False,
                output={
                    "objectGuid": request.expected_object_guid,
                    "credentialEstablished": True,
                    "recoveredPendingReceipt": True,
                },
                approval=approval,
                verification=verification,
            )

        output = await asyncio.to_thread(
            runner.run_with_secret,
            ProvisioningScriptId.SET_INITIAL_PASSWORD,
            {
                "identity": request.identity,
                "expectedObjectGuid": request.expected_object_guid,
            },
            secret=secret,
        )
        readback = await probe(
            ProvisioningScriptId.PREFLIGHT_CREDENTIAL_BOOTSTRAP,
            {"identity": request.identity},
        )
        verification = credential_bootstrap_verification(
            preflight=readback,
            expected_object_guid=request.expected_object_guid,
        )
        if verification.passed:
            password_last_set = str(verification.details.get("passwordLastSet") or "")
            if not password_last_set:
                raise RuntimeError("credential verification did not produce passwordLastSet evidence")
            store.mark_verified(
                idempotency_key=request.idempotency_key,
                object_guid=request.expected_object_guid,
                observed_password_last_set=password_last_set,
            )
        return change_response(
            operation="ad.user.credential-bootstrap.change",
            target=target,
            correlation_id=correlation_id,
            idempotency_key=request.idempotency_key,
            changed=bool(output.get("changed")),
            output={
                "objectGuid": output.get("objectGuid"),
                "enabled": output.get("enabled"),
                "credentialEstablished": output.get("credentialEstablished"),
                "passwordLastSet": output.get("passwordLastSet"),
            },
            approval=approval,
            verification=verification,
        )

    @mcp.tool()
    async def verify_user_credential_bootstrap(
        identity: str,
        expected_object_guid: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        """Verify credential state without resolving or returning password material."""

        request = CredentialBootstrapChangeRequest.model_construct(
            identity=identity,
            secret_ref="unused",
            expected_object_guid=expected_object_guid,
            idempotency_key="unused000",
            approval_grant="unused-approval-grant",
        )
        preflight = await probe(
            ProvisioningScriptId.PREFLIGHT_CREDENTIAL_BOOTSTRAP,
            {"identity": clean_identity_for_verify(request.identity)},
        )
        verification = credential_bootstrap_verification(
            preflight=preflight,
            expected_object_guid=request.expected_object_guid,
        )
        return verify_response(
            operation="ad.user.credential-bootstrap.verify",
            target=credential_target(request.expected_object_guid),
            correlation_id=correlation_id,
            check=verification.check,
            passed=verification.passed,
            details=verification.details,
        )


def clean_identity_for_verify(identity: str) -> str:
    """Validate verify-only identity without constructing mutation-only fields."""

    from .changes import clean_identity

    return clean_identity(identity)
