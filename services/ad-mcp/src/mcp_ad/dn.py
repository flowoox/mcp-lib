from __future__ import annotations

from ldap3.core.exceptions import LDAPInvalidDnError
from ldap3.utils.dn import parse_dn


class InvalidDistinguishedName(ValueError):
    pass


class SearchBaseNotAllowed(PermissionError):
    pass


def _rdns(value: str) -> tuple[tuple[str, str, str], ...]:
    """Return a parsed, comparison-safe DN without raw suffix matching."""

    try:
        parsed = parse_dn(value.strip(), escape=True, strip=True)
    except (LDAPInvalidDnError, TypeError, ValueError) as exc:
        raise InvalidDistinguishedName("Invalid distinguished name") from exc
    if not parsed:
        raise InvalidDistinguishedName("Distinguished name must not be empty")
    return tuple(
        (attribute.casefold(), component.casefold(), separator)
        for attribute, component, separator in parsed
    )


def is_within_base(candidate: str, base: str) -> bool:
    candidate_parts = _rdns(candidate)
    base_parts = _rdns(base)
    if len(candidate_parts) < len(base_parts):
        return False
    return candidate_parts[-len(base_parts) :] == base_parts


def require_allowed_base(candidate: str, allowed_bases: tuple[str, ...]) -> str:
    normalized = candidate.strip()
    if not allowed_bases:
        raise SearchBaseNotAllowed("No LDAP search bases are configured")
    if not any(is_within_base(normalized, base) for base in allowed_bases):
        raise SearchBaseNotAllowed("Requested LDAP search base is outside the configured allowlist")
    return normalized
