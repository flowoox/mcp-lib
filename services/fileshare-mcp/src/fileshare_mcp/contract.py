from __future__ import annotations

from typing import Any

from mcp_common.operations import OperationPhase, RiskLevel, ToolPolicy
from mcp_common.query_budget import QueryBudgetLimits

CONTRACT = "flowoox.fileshare-diagnostics"
CONTRACT_VERSION = "1.1.0"

CONTENT_TOOL_NAMES = frozenset(
    {"fileshare.file.hash", "fileshare.text.preview", "fileshare.text.search"}
)

TOOL_POLICIES = (
    ToolPolicy(name="fileshare.roots.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fileshare.path.observe", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fileshare.directory.list", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fileshare.acl.observe", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fileshare.access.explain", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fileshare.file.hash", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fileshare.text.preview", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
    ToolPolicy(name="fileshare.text.search", phase=OperationPhase.OBSERVE, risk=RiskLevel.READ_ONLY),
)


def capabilities(
    budget_limits: QueryBudgetLimits,
    *,
    allow_reparse_points: bool,
    content_read_enabled: bool,
    safe_text_extensions: tuple[str, ...],
    max_text_read_bytes: int,
    max_text_characters: int,
    max_text_lines: int,
    max_text_matches: int,
    max_hash_bytes: int,
) -> dict[str, Any]:
    return {
        "contract": CONTRACT,
        "version": CONTRACT_VERSION,
        "runtime": {
            "backend": "windows-powershell-readonly",
            "backend_read_only_attestation_required": True,
            "query_budget": budget_limits.model_dump(mode="json"),
            "writes_enabled": False,
            "arbitrary_command": False,
            "arbitrary_path": False,
            "configured_root_alias_required": True,
            "recursive_directory_walk": False,
            "reparse_points_allowed": allow_reparse_points,
            "effective_access_authoritative": False,
            "content_analysis": {
                "enabled": content_read_enabled,
                "root_opt_in_required": True,
                "unrestricted_file_read": False,
                "safe_text_extensions": list(safe_text_extensions),
                "utf8_only": True,
                "nul_bytes_rejected": True,
                "substring_search_only": True,
                "regex_search": False,
                "max_text_read_bytes": max_text_read_bytes,
                "max_text_characters": max_text_characters,
                "max_text_lines": max_text_lines,
                "max_text_matches": max_text_matches,
                "max_hash_bytes": max_hash_bytes,
            },
        },
        "capabilities": [
            {
                "id": policy.name,
                "phase": policy.phase.value,
                "risk": policy.risk.value,
                "requires_approval": policy.requires_approval,
            }
            for policy in TOOL_POLICIES
            if content_read_enabled or policy.name not in CONTENT_TOOL_NAMES
        ],
    }
