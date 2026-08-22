from __future__ import annotations

import hashlib
from typing import Any

from mcp_common.operations import (
    Approval,
    ApprovalState,
    AuditEvent,
    ChangePlan,
    ChangeStep,
    OperationContext,
    OperationPhase,
    OperationResult,
    OperationStatus,
    RiskLevel,
    Verification,
)

from .approval import create_challenge, verify_approval
from .ledger import OperationLedger
from .runner import PowerShellRunner
from .write_models import AddGroupMemberInput, CreateDisabledUserInput
from .write_scripts import WriteScriptId

_CREATE_USER_OPERATION = "ad.user.create-disabled"
_ADD_MEMBER_OPERATION = "ad.group.member.add"


class AdWriteService:
    """Plan, approve, execute and verify the narrow AD mutation allowlist."""

    def __init__(
        self,
        runner: PowerShellRunner,
        *,
        approval_secret: str,
        plan_ttl_seconds: int,
        ledger: OperationLedger,
    ):
        if len(approval_secret) < 32:
            raise ValueError("approval_secret must be at least 32 characters")
        self.runner = runner
        self.approval_secret = approval_secret
        self.plan_ttl_seconds = plan_ttl_seconds
        self.ledger = ledger

    def _server(self) -> str:
        context = self.runner.run(WriteScriptId.WRITE_CONTEXT)
        server = str(context.get("server") or "").strip()
        if not server:
            raise RuntimeError("AD write context did not return a PDC emulator")
        return server

    @staticmethod
    def _fingerprint(challenge: str) -> str:
        return hashlib.sha256(challenge.encode("utf-8")).hexdigest()

    @staticmethod
    def _result_payload(
        *,
        operation: str,
        status: OperationStatus,
        context: OperationContext,
        output: dict[str, Any],
        target: str,
        changed: bool,
        approved_by: str,
        verification: list[Verification] | None = None,
        rollback_performed: bool = False,
    ) -> dict[str, Any]:
        result = OperationResult(
            operation=operation,
            phase=OperationPhase.CHANGE,
            status=status,
            context=context,
            changed=changed,
            output=output,
            verification=verification or [],
            rollback_performed=rollback_performed,
        )
        audit = AuditEvent(
            operation=operation,
            phase=OperationPhase.CHANGE,
            risk=RiskLevel.HIGH,
            context=context,
            target=target,
            status=status,
            changed=changed,
            metadata={"approval_scheme": "hmac-sha256", "approved_by": approved_by},
        )
        payload = result.model_dump(mode="json")
        payload["audit"] = audit.model_dump(mode="json")
        return payload

    def plan_create_disabled_user(
        self,
        request: CreateDisabledUserInput,
        context: OperationContext,
    ) -> dict[str, Any]:
        if context.idempotency_key is None:
            raise ValueError("plan_create_disabled_user requires an idempotency key")
        server = self._server()
        user_state = self.runner.run(
            WriteScriptId.USER_PRESTATE,
            {"identity": request.sam_account_name, "server": server},
        )
        if bool(user_state.get("exists")):
            raise ValueError("target AD user already exists; create plan refused")
        path_state = self.runner.run(
            WriteScriptId.PATH_PRESTATE,
            {"path": request.path, "server": server},
        )
        object_class = str(path_state.get("objectClass") or "").casefold()
        if object_class not in {"organizationalunit", "container"}:
            raise ValueError("target path is not an AD organizational unit/container")

        pre_state = {
            "server": server,
            "user_exists": False,
            "path_object_guid": path_state.get("objectGuid"),
            "path_distinguished_name": path_state.get("distinguishedName"),
        }
        encoded, challenge = create_challenge(
            operation=_CREATE_USER_OPERATION,
            correlation_id=context.correlation_id,
            idempotency_key=context.idempotency_key,
            parameters=request.model_dump(mode="json"),
            pre_state=pre_state,
            ttl_seconds=self.plan_ttl_seconds,
        )
        plan = ChangePlan(
            operation=_CREATE_USER_OPERATION,
            risk=RiskLevel.HIGH,
            context=context,
            steps=[
                ChangeStep(
                    action="create disabled AD user",
                    target=f"user:{request.sam_account_name}",
                    reversible=True,
                    rollback_action=(
                        "Remove only the newly-created object by returned object GUID if "
                        "post-change verification fails."
                    ),
                )
            ],
            pre_state=pre_state,
            approval=Approval(
                state=ApprovalState.REQUIRED,
                reason="External HMAC approval is required before execution.",
            ),
        )
        payload = plan.model_dump(mode="json")
        payload.update(
            {
                "approval_challenge": encoded,
                "approval_scheme": "hmac-sha256",
                "expires_at": challenge.expires_at.isoformat(),
            }
        )
        return payload

    def create_disabled_user(
        self,
        *,
        approval_challenge: str,
        approved_by: str,
        approval_signature: str,
    ) -> dict[str, Any]:
        approved_by = approved_by.strip()
        challenge = verify_approval(
            secret=self.approval_secret,
            challenge=approval_challenge,
            approved_by=approved_by,
            signature=approval_signature,
            expected_operation=_CREATE_USER_OPERATION,
        )
        context = OperationContext(
            correlation_id=challenge.correlation_id,
            actor=f"approved:{approved_by}",
            source="ad-mcp:approval-hmac",
            idempotency_key=challenge.idempotency_key,
        )
        fingerprint = self._fingerprint(approval_challenge)
        replay = self.ledger.get(challenge.idempotency_key, fingerprint)
        if replay is not None:
            return {**replay, "idempotent_replay": True}

        request = CreateDisabledUserInput.model_validate(challenge.parameters)
        server = str(challenge.pre_state.get("server") or "")
        user_state = self.runner.run(
            WriteScriptId.USER_PRESTATE,
            {"identity": request.sam_account_name, "server": server},
        )
        path_state = self.runner.run(
            WriteScriptId.PATH_PRESTATE,
            {"path": request.path, "server": server},
        )
        if bool(user_state.get("exists")) or path_state.get("objectGuid") != challenge.pre_state.get(
            "path_object_guid"
        ):
            result = self._result_payload(
                operation=_CREATE_USER_OPERATION,
                status=OperationStatus.REJECTED,
                context=context,
                output={"reason": "AD pre-state changed after approval plan"},
                target=f"user:{request.sam_account_name}",
                changed=False,
                approved_by=approved_by,
            )
            return self.ledger.record(challenge.idempotency_key, fingerprint, result)

        mutation_payload = {**request.model_dump(mode="json"), "server": server}
        created = self.runner.run(WriteScriptId.CREATE_DISABLED_USER, mutation_payload)
        created_guid = str(created.get("objectGuid") or "").strip()
        if not created_guid:
            raise RuntimeError("AD create operation did not return the created object GUID")

        verify_state = self.runner.run(
            WriteScriptId.USER_PRESTATE,
            {"identity": created_guid, "server": server},
        )
        checks = [
            Verification(
                check="created object exists by immutable GUID",
                passed=bool(verify_state.get("exists")),
                details={"objectGuid": created_guid},
            ),
            Verification(
                check="created user remains disabled",
                passed=verify_state.get("enabled") is False,
                details={"enabled": verify_state.get("enabled")},
            ),
            Verification(
                check="UPN matches approved plan",
                passed=verify_state.get("userPrincipalName") == request.user_principal_name,
                details={"userPrincipalName": verify_state.get("userPrincipalName")},
            ),
        ]
        if not all(check.passed for check in checks):
            self.runner.run(
                WriteScriptId.REMOVE_CREATED_USER,
                {"object_guid": created_guid, "server": server},
            )
            result = self._result_payload(
                operation=_CREATE_USER_OPERATION,
                status=OperationStatus.FAILED,
                context=context,
                output={
                    "reason": "post-change verification failed; newly-created user rolled back",
                    "objectGuid": created_guid,
                },
                target=f"user:{request.sam_account_name}",
                changed=True,
                approved_by=approved_by,
                verification=checks,
                rollback_performed=True,
            )
            return self.ledger.record(challenge.idempotency_key, fingerprint, result)

        result = self._result_payload(
            operation=_CREATE_USER_OPERATION,
            status=OperationStatus.SUCCEEDED,
            context=context,
            output=created,
            target=f"user:{request.sam_account_name}",
            changed=True,
            approved_by=approved_by,
            verification=checks,
        )
        return self.ledger.record(challenge.idempotency_key, fingerprint, result)

    def plan_add_group_member(
        self,
        request: AddGroupMemberInput,
        context: OperationContext,
    ) -> dict[str, Any]:
        if context.idempotency_key is None:
            raise ValueError("plan_add_group_member requires an idempotency key")
        server = self._server()
        state = self.runner.run(
            WriteScriptId.MEMBERSHIP_PRESTATE,
            {
                "user_identity": request.user_identity,
                "group_identity": request.group_identity,
                "server": server,
            },
        )
        if bool(state.get("isMember")):
            return OperationResult(
                operation=_ADD_MEMBER_OPERATION,
                phase=OperationPhase.PLAN,
                status=OperationStatus.SUCCEEDED,
                context=context,
                output={"already_satisfied": True, "pre_state": state},
            ).model_dump(mode="json")

        pre_state = {
            "server": server,
            "user_guid": state.get("userGuid"),
            "group_guid": state.get("groupGuid"),
            "is_member": False,
        }
        encoded, challenge = create_challenge(
            operation=_ADD_MEMBER_OPERATION,
            correlation_id=context.correlation_id,
            idempotency_key=context.idempotency_key,
            parameters=request.model_dump(mode="json"),
            pre_state=pre_state,
            ttl_seconds=self.plan_ttl_seconds,
        )
        plan = ChangePlan(
            operation=_ADD_MEMBER_OPERATION,
            risk=RiskLevel.HIGH,
            context=context,
            steps=[
                ChangeStep(
                    action="add direct AD group membership",
                    target=f"group:{request.group_identity}/user:{request.user_identity}",
                    reversible=True,
                    rollback_action=(
                        "Remove only this direct membership if post-change verification fails "
                        "and the approved pre-state was not already a member."
                    ),
                )
            ],
            pre_state=pre_state,
            approval=Approval(
                state=ApprovalState.REQUIRED,
                reason="External HMAC approval is required before execution.",
            ),
        )
        payload = plan.model_dump(mode="json")
        payload.update(
            {
                "approval_challenge": encoded,
                "approval_scheme": "hmac-sha256",
                "expires_at": challenge.expires_at.isoformat(),
            }
        )
        return payload

    def add_group_member(
        self,
        *,
        approval_challenge: str,
        approved_by: str,
        approval_signature: str,
    ) -> dict[str, Any]:
        approved_by = approved_by.strip()
        challenge = verify_approval(
            secret=self.approval_secret,
            challenge=approval_challenge,
            approved_by=approved_by,
            signature=approval_signature,
            expected_operation=_ADD_MEMBER_OPERATION,
        )
        context = OperationContext(
            correlation_id=challenge.correlation_id,
            actor=f"approved:{approved_by}",
            source="ad-mcp:approval-hmac",
            idempotency_key=challenge.idempotency_key,
        )
        fingerprint = self._fingerprint(approval_challenge)
        replay = self.ledger.get(challenge.idempotency_key, fingerprint)
        if replay is not None:
            return {**replay, "idempotent_replay": True}

        request = AddGroupMemberInput.model_validate(challenge.parameters)
        server = str(challenge.pre_state.get("server") or "")
        state = self.runner.run(
            WriteScriptId.MEMBERSHIP_PRESTATE,
            {
                "user_identity": request.user_identity,
                "group_identity": request.group_identity,
                "server": server,
            },
        )
        if (
            bool(state.get("isMember"))
            or state.get("userGuid") != challenge.pre_state.get("user_guid")
            or state.get("groupGuid") != challenge.pre_state.get("group_guid")
        ):
            result = self._result_payload(
                operation=_ADD_MEMBER_OPERATION,
                status=OperationStatus.REJECTED,
                context=context,
                output={"reason": "AD membership pre-state changed after approval plan"},
                target=f"group:{request.group_identity}/user:{request.user_identity}",
                changed=False,
                approved_by=approved_by,
            )
            return self.ledger.record(challenge.idempotency_key, fingerprint, result)

        mutation = {
            "user_guid": state["userGuid"],
            "group_guid": state["groupGuid"],
            "server": server,
        }
        self.runner.run(WriteScriptId.ADD_GROUP_MEMBER, mutation)
        verified = self.runner.run(
            WriteScriptId.MEMBERSHIP_PRESTATE,
            {
                "user_identity": state["userGuid"],
                "group_identity": state["groupGuid"],
                "server": server,
            },
        )
        check = Verification(
            check="approved direct group membership is present",
            passed=bool(verified.get("isMember")),
            details={"userGuid": state["userGuid"], "groupGuid": state["groupGuid"]},
        )
        if not check.passed:
            self.runner.run(WriteScriptId.REMOVE_GROUP_MEMBER, mutation)
            result = self._result_payload(
                operation=_ADD_MEMBER_OPERATION,
                status=OperationStatus.FAILED,
                context=context,
                output={"reason": "post-change verification failed; membership rolled back"},
                target=f"group:{request.group_identity}/user:{request.user_identity}",
                changed=True,
                approved_by=approved_by,
                verification=[check],
                rollback_performed=True,
            )
            return self.ledger.record(challenge.idempotency_key, fingerprint, result)

        result = self._result_payload(
            operation=_ADD_MEMBER_OPERATION,
            status=OperationStatus.SUCCEEDED,
            context=context,
            output={
                "userGuid": state["userGuid"],
                "groupGuid": state["groupGuid"],
                "isMember": True,
            },
            target=f"group:{request.group_identity}/user:{request.user_identity}",
            changed=True,
            approved_by=approved_by,
            verification=[check],
        )
        return self.ledger.record(challenge.idempotency_key, fingerprint, result)
