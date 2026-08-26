from __future__ import annotations

import json
from pathlib import PureWindowsPath
from typing import Any
from uuid import UUID

from mcp.server.fastmcp import FastMCP
from mcp_common.mcp_security import build_mcp_server_security
from mcp_common.operations import (
    AuditEvent,
    OperationContext,
    OperationPhase,
    OperationResult,
    OperationStatus,
    RiskLevel,
)
from mcp_common.query_budget import QueryBudget, QueryBudgetLimits

from .backend import FileShareBackend, PowerShellFileShareBackend
from .config import Settings
from .contract import capabilities
from .models import AccessExplanation, AclObservation, DirectoryEntry, PathInfo, ShareAce, ShareRoot


def _budget_limits(settings: Settings) -> QueryBudgetLimits:
    return QueryBudgetLimits(
        max_requests=settings.fileshare_budget_max_requests,
        max_items=settings.fileshare_budget_max_items,
        max_response_bytes=settings.fileshare_budget_max_response_bytes,
        max_fan_out=settings.fileshare_budget_max_fan_out,
        total_timeout_seconds=settings.fileshare_budget_timeout_seconds,
    )


def _operation_context(actor: str, correlation_id: str) -> OperationContext:
    value = correlation_id.strip()
    if not value:
        return OperationContext(actor=actor, source="fileshare-mcp")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ValueError("correlation_id must be a UUID") from exc
    return OperationContext(correlation_id=parsed, actor=actor, source="fileshare-mcp")


def _reason(value: str) -> str:
    value = value.strip()
    if not 1 <= len(value) <= 1_000:
        raise ValueError("reason must contain 1-1000 characters")
    return value


def _root(settings: Settings, alias: str) -> ShareRoot:
    normalized = alias.strip().lower()
    for root in settings.roots:
        if root.alias == normalized:
            return root
    raise ValueError("unknown root alias")


def _full_path(root: ShareRoot, relative_path: str) -> str:
    value = relative_path.strip().replace("/", "\\")
    relative = PureWindowsPath(value or ".")
    if relative.is_absolute() or relative.drive or ".." in relative.parts:
        raise ValueError("relative_path must stay within the configured root")
    if any("\x00" in part or ":" in part for part in relative.parts):
        raise ValueError("relative_path contains an invalid segment")
    return str(PureWindowsPath(root.path).joinpath(relative))


def _response(
    operation: str,
    *,
    actor: str,
    reason: str,
    correlation_id: str,
    output: dict[str, Any],
    budget: QueryBudget,
    target: str,
) -> dict[str, Any]:
    context = _operation_context(actor, correlation_id)
    result_output = dict(output)
    result_output["queryBudget"] = budget.snapshot().model_dump(mode="json")
    result = OperationResult(
        operation=operation,
        phase=OperationPhase.OBSERVE,
        status=OperationStatus.SUCCEEDED,
        context=context,
        output=result_output,
    )
    audit = AuditEvent(
        operation=operation,
        phase=OperationPhase.OBSERVE,
        risk=RiskLevel.READ_ONLY,
        context=context,
        target=target,
        status=OperationStatus.SUCCEEDED,
        metadata={"reason": _reason(reason)},
    )
    payload = result.model_dump(mode="json")
    payload["audit"] = audit.model_dump(mode="json")
    return payload


async def _backend_call(
    backend: FileShareBackend,
    budget: QueryBudget,
    settings: Settings,
    operation: str,
    **kwargs: Any,
) -> Any:
    budget.reserve_request()
    result = await backend.execute(
        operation,
        timeout_seconds=budget.remaining_timeout(settings.fileshare_request_timeout_seconds),
        **kwargs,
    )
    encoded = json.dumps(result, separators=(",", ":"), default=str).encode()
    items = len(result) if isinstance(result, list) else 1
    budget.record_response(items=items, response_bytes=len(encoded))
    return result


def explain_access(acl: AclObservation, principal_sid: str, group_sids: list[str]) -> AccessExplanation:
    considered = {principal_sid.strip().upper(), *(sid.strip().upper() for sid in group_sids)}
    considered.discard("")
    ntfs = [ace for ace in acl.ntfs if ace.sid and ace.sid.upper() in considered]
    share = [ace for ace in acl.share if ace.sid and ace.sid.upper() in considered]
    deny = any(ace.access_type.lower() == "deny" for ace in [*ntfs, *share])
    allow = any(ace.access_type.lower() == "allow" for ace in [*ntfs, *share])
    if deny:
        conclusion = "matching_deny_present"
    elif allow:
        conclusion = "matching_allow_present_but_effective_access_unverified"
    else:
        conclusion = "undetermined_no_matching_sid_ace"
    return AccessExplanation(
        principal_sid=principal_sid,
        considered_sids=sorted(considered),
        matching_ntfs_aces=ntfs,
        matching_share_aces=share,
        conclusion=conclusion,
        notes=[
            "Result is advisory; Windows token expansion, ACE ordering, special privileges and application-level checks are not simulated.",
            "When a share ACL is configured, both SMB share and NTFS layers are surfaced; the most restrictive effective layer still governs.",
        ],
    )


def create_server(settings: Settings | None = None, backend: FileShareBackend | None = None) -> FastMCP:
    settings = settings or Settings()
    budget_limits = _budget_limits(settings)
    backend = backend or PowerShellFileShareBackend(settings)
    security = build_mcp_server_security(settings, service_hosts=("mcp-fileshare",))
    mcp = FastMCP(
        "Flowoox FileShare Diagnostics MCP",
        instructions=(
            "Bounded read-only Windows file-share diagnostics. Every filesystem target is resolved from a configured root alias; arbitrary paths, recursive walks, file content reads and write commands are not exposed. Reparse points are blocked by default."
        ),
        host=settings.mcp_host,
        port=settings.mcp_port,
        stateless_http=True,
        json_response=True,
        transport_security=security.transport_security,
        auth=security.auth,
        token_verifier=security.token_verifier,
    )

    @mcp.tool()
    async def get_capabilities() -> dict[str, Any]:
        return capabilities(
            budget_limits,
            allow_reparse_points=settings.fileshare_allow_reparse_points,
        )

    @mcp.tool()
    async def fileshare_list_roots(
        actor: str,
        reason: str,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        budget = QueryBudget(budget_limits)
        roots = [
            {
                "alias": root.alias,
                "shareName": root.share_name,
                "description": root.description,
            }
            for root in settings.roots
        ]
        return _response(
            "fileshare.roots.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={"roots": roots},
            budget=budget,
            target="configured-roots",
        )

    @mcp.tool()
    async def fileshare_observe_path(
        actor: str,
        reason: str,
        root_alias: str,
        relative_path: str = "",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        root = _root(settings, root_alias)
        path = _full_path(root, relative_path)
        budget = QueryBudget(budget_limits)
        raw = await _backend_call(backend, budget, settings, "path_info", path=path)
        info = PathInfo.model_validate(raw)
        return _response(
            "fileshare.path.observe",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={"path": info.model_dump(mode="json")},
            budget=budget,
            target=f"{root.alias}:{relative_path or '.'}",
        )

    @mcp.tool()
    async def fileshare_list_directory(
        actor: str,
        reason: str,
        root_alias: str,
        relative_path: str = "",
        limit: int = 100,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        if not 1 <= limit <= settings.fileshare_max_page_size:
            raise ValueError("limit exceeds configured page size")
        root = _root(settings, root_alias)
        path = _full_path(root, relative_path)
        budget = QueryBudget(budget_limits)
        raw = await _backend_call(
            backend,
            budget,
            settings,
            "directory_list",
            path=path,
            limit=limit,
        )
        entries = [DirectoryEntry.model_validate(item) for item in raw]
        return _response(
            "fileshare.directory.list",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={
                "entries": [entry.model_dump(mode="json") for entry in entries],
                "returned": len(entries),
            },
            budget=budget,
            target=f"{root.alias}:{relative_path or '.'}",
        )

    @mcp.tool()
    async def fileshare_observe_acl(
        actor: str,
        reason: str,
        root_alias: str,
        relative_path: str = "",
        correlation_id: str = "",
    ) -> dict[str, Any]:
        root = _root(settings, root_alias)
        path = _full_path(root, relative_path)
        budget = QueryBudget(budget_limits)
        raw = await _backend_call(backend, budget, settings, "ntfs_acl", path=path)
        acl = AclObservation.model_validate(raw)
        if root.share_name:
            share_raw = await _backend_call(
                backend,
                budget,
                settings,
                "share_acl",
                share_name=root.share_name,
            )
            acl.share = [ShareAce.model_validate(item) for item in share_raw]
        return _response(
            "fileshare.acl.observe",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={"acl": acl.model_dump(mode="json")},
            budget=budget,
            target=f"{root.alias}:{relative_path or '.'}",
        )

    @mcp.tool()
    async def fileshare_explain_access(
        actor: str,
        reason: str,
        root_alias: str,
        principal_sid: str,
        relative_path: str = "",
        group_sids: list[str] | None = None,
        correlation_id: str = "",
    ) -> dict[str, Any]:
        root = _root(settings, root_alias)
        path = _full_path(root, relative_path)
        budget = QueryBudget(budget_limits)
        raw = await _backend_call(backend, budget, settings, "ntfs_acl", path=path)
        acl = AclObservation.model_validate(raw)
        if root.share_name:
            share_raw = await _backend_call(
                backend,
                budget,
                settings,
                "share_acl",
                share_name=root.share_name,
            )
            acl.share = [ShareAce.model_validate(item) for item in share_raw]
        explanation = explain_access(acl, principal_sid, group_sids or [])
        return _response(
            "fileshare.access.explain",
            actor=actor,
            reason=reason,
            correlation_id=correlation_id,
            output={"access": explanation.model_dump(mode="json")},
            budget=budget,
            target=f"{root.alias}:{relative_path or '.'}",
        )

    return mcp


def main() -> None:
    create_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()
