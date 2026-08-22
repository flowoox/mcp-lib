from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .client import LdapDirectoryClient
from .models import AuditReport, Finding, Severity

UAC_ACCOUNT_DISABLED = 0x0002
UAC_PASSWORD_NEVER_EXPIRES = 0x10000
DOMAIN_PASSWORD_COMPLEX = 0x0001


def datetime_to_ad_filetime(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("value must be timezone-aware")
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((value.astimezone(timezone.utc) - epoch).total_seconds() * 10_000_000)


def _attribute(attributes: dict[str, Any], name: str) -> Any:
    folded = name.casefold()
    for key, value in attributes.items():
        if key.casefold() == folded:
            if isinstance(value, list) and len(value) == 1:
                return value[0]
            return value
    return None


def _integer(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def evaluate_domain_policy(
    attributes: dict[str, Any], *, minimum_password_length: int
) -> list[Finding]:
    findings: list[Finding] = []
    min_length = _integer(_attribute(attributes, "minPwdLength"))
    properties = _integer(_attribute(attributes, "pwdProperties"))
    lockout_threshold = _integer(_attribute(attributes, "lockoutThreshold"))
    history_length = _integer(_attribute(attributes, "pwdHistoryLength"))

    if min_length is None:
        findings.append(
            Finding(
                check_id="AD-PASSWORD-POLICY-UNREADABLE",
                severity=Severity.HIGH,
                title="Password policy could not be evaluated",
                description="The domain minimum password length was not returned by LDAP.",
                evidence={"attribute": "minPwdLength"},
                remediation="Verify read permissions and re-run the audit against the domain root.",
            )
        )
    elif min_length < minimum_password_length:
        findings.append(
            Finding(
                check_id="AD-PASSWORD-MIN-LENGTH",
                severity=Severity.HIGH,
                title="Domain minimum password length is below the configured baseline",
                description=(
                    f"The effective domain value is {min_length}; the service baseline is "
                    f"{minimum_password_length}."
                ),
                evidence={"observed": min_length, "required": minimum_password_length},
                remediation=(
                    "Raise the domain or fine-grained password policy after validating legacy "
                    "application and service-account compatibility."
                ),
            )
        )

    if properties is None or properties & DOMAIN_PASSWORD_COMPLEX == 0:
        findings.append(
            Finding(
                check_id="AD-PASSWORD-COMPLEXITY",
                severity=Severity.HIGH,
                title="Password complexity is not confirmed",
                description="The DOMAIN_PASSWORD_COMPLEX policy bit is not enabled or unreadable.",
                evidence={"pwdProperties": properties},
                remediation="Enable password complexity in the effective domain password policy.",
            )
        )

    if lockout_threshold is None:
        findings.append(
            Finding(
                check_id="AD-LOCKOUT-POLICY-UNREADABLE",
                severity=Severity.MEDIUM,
                title="Account lockout threshold could not be evaluated",
                description="The domain lockoutThreshold attribute was not returned.",
                evidence={"attribute": "lockoutThreshold"},
                remediation="Verify read permissions and inspect the effective password policy.",
            )
        )
    elif lockout_threshold == 0:
        findings.append(
            Finding(
                check_id="AD-LOCKOUT-DISABLED",
                severity=Severity.MEDIUM,
                title="Account lockout is disabled",
                description="The effective domain lockout threshold is zero.",
                evidence={"lockoutThreshold": 0},
                remediation=(
                    "Define an account-lockout policy together with monitoring and a helpdesk "
                    "recovery process; avoid settings that make denial-of-service trivial."
                ),
            )
        )

    if history_length is not None and history_length < 12:
        findings.append(
            Finding(
                check_id="AD-PASSWORD-HISTORY",
                severity=Severity.LOW,
                title="Password history is below the service baseline",
                description=f"The domain remembers {history_length} previous passwords.",
                evidence={"observed": history_length, "baseline": 12},
                remediation="Increase password history after checking service-account workflows.",
            )
        )
    return findings


def evaluate_privileged_members(groups: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for group_dn, result in groups.items():
        disabled: list[str] = []
        never_expires: list[str] = []
        for entry in result.objects:
            uac = _integer(_attribute(entry.attributes, "userAccountControl")) or 0
            identity = str(
                _attribute(entry.attributes, "userPrincipalName")
                or _attribute(entry.attributes, "sAMAccountName")
                or entry.distinguished_name
            )
            if uac & UAC_ACCOUNT_DISABLED:
                disabled.append(identity)
            if uac & UAC_PASSWORD_NEVER_EXPIRES:
                never_expires.append(identity)

        if disabled:
            findings.append(
                Finding(
                    check_id="AD-PRIVILEGED-DISABLED",
                    severity=Severity.MEDIUM,
                    title="Disabled accounts retain direct privileged-group membership",
                    description=f"Disabled direct members were found in {group_dn}.",
                    evidence={"group_dn": group_dn, "accounts": sorted(disabled)},
                    remediation=(
                        "Remove obsolete privileged memberships after validating emergency and "
                        "break-glass account procedures."
                    ),
                )
            )
        if never_expires:
            findings.append(
                Finding(
                    check_id="AD-PRIVILEGED-NONEXPIRING",
                    severity=Severity.HIGH,
                    title="Privileged accounts have non-expiring passwords",
                    description=f"Direct members with PasswordNeverExpires were found in {group_dn}.",
                    evidence={"group_dn": group_dn, "accounts": sorted(never_expires)},
                    remediation=(
                        "Migrate human privileged identities to managed, time-bound access and "
                        "rotate service identities through a supported secret-management process."
                    ),
                )
            )
    return findings


def run_security_audit(
    client: LdapDirectoryClient,
    *,
    now: datetime | None = None,
) -> AuditReport:
    settings = client.settings
    observed_at = now or datetime.now(timezone.utc)
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ValueError("now must be timezone-aware")

    findings: list[Finding] = []
    policy_result = client.get_domain_policy()
    policy_attributes: dict[str, Any] = {}
    if policy_result.objects:
        policy_attributes = policy_result.objects[0].attributes
        findings.extend(
            evaluate_domain_policy(
                policy_attributes,
                minimum_password_length=settings.ad_min_password_length,
            )
        )
    else:
        findings.append(
            Finding(
                check_id="AD-DOMAIN-POLICY-MISSING",
                severity=Severity.HIGH,
                title="Domain policy object was not returned",
                description="The configured base DN did not return a domainDNS object.",
                evidence={"configured_scope": settings.ad_base_dn},
                remediation="Validate AD_BASE_DN and the service account's read permissions.",
            )
        )

    stale_cutoff = observed_at - timedelta(days=settings.ad_stale_days)
    stale = client.list_stale_enabled_users(
        stale_before_filetime=datetime_to_ad_filetime(stale_cutoff)
    )
    if stale.count:
        findings.append(
            Finding(
                check_id="AD-STALE-ENABLED-USERS",
                severity=Severity.MEDIUM,
                title="Stale enabled user accounts were found",
                description=(
                    f"{stale.count} enabled accounts have no logon timestamp or have not logged "
                    f"on within {settings.ad_stale_days} days."
                ),
                evidence={
                    "count": stale.count,
                    "truncated": stale.truncated,
                    "cutoff": stale_cutoff.isoformat(),
                    "accounts": [
                        str(
                            _attribute(item.attributes, "userPrincipalName")
                            or _attribute(item.attributes, "sAMAccountName")
                            or item.distinguished_name
                        )
                        for item in stale.objects
                    ],
                },
                remediation=(
                    "Validate ownership and disable or remove unused identities through the normal "
                    "offboarding and exception process."
                ),
            )
        )

    privileged_groups = client.list_privileged_members()
    if privileged_groups:
        findings.extend(evaluate_privileged_members(privileged_groups))
    else:
        findings.append(
            Finding(
                check_id="AD-PRIVILEGED-SCOPE-NOT-CONFIGURED",
                severity=Severity.INFO,
                title="Privileged-group audit scope is not configured",
                description="No AD_PRIVILEGED_GROUP_DNS values were supplied at runtime.",
                evidence={},
                remediation=(
                    "Configure explicit privileged group DNs for the deployment; keep private DNs "
                    "outside the public repository."
                ),
            )
        )

    return AuditReport(
        scope=settings.ad_base_dn,
        findings=findings,
        observations={
            "domain_policy": policy_attributes,
            "stale_user_count": stale.count,
            "stale_results_truncated": stale.truncated,
            "privileged_groups_checked": len(privileged_groups),
            "limitations": [
                "Direct group membership only; nested privilege expansion is not yet evaluated.",
                "LDAP signing, channel binding, NTLM policy, replication health, and GPO state "
                "require dedicated Windows/AD diagnostic adapters and are not inferred here.",
            ],
        },
    )
