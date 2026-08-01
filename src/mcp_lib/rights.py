from __future__ import annotations

from dataclasses import dataclass

ALLOWED_RIGHTS_BASES = {
    "owned-copy",
    "licensed",
    "public-domain",
    "artist-permission",
    "other-documented-permission",
}

REFERENCE_REQUIRED = {
    "licensed",
    "artist-permission",
    "other-documented-permission",
}


class RightsError(ValueError):
    """Raised when a side effect lacks a valid authorization assertion."""


@dataclass(frozen=True, slots=True)
class ValidatedRights:
    basis: str
    reference: str


def validate_rights(
    *,
    confirmed: bool,
    basis: str,
    reference: str = "",
) -> ValidatedRights:
    normalized_basis = basis.strip().lower()
    normalized_reference = reference.strip()

    if not confirmed:
        raise RightsError(
            "Download/import blocked: confirm that this material is owned, licensed, "
            "public-domain, or otherwise authorized."
        )
    if normalized_basis not in ALLOWED_RIGHTS_BASES:
        allowed = ", ".join(sorted(ALLOWED_RIGHTS_BASES))
        raise RightsError(f"Unknown rights basis. Allowed values: {allowed}")
    if normalized_basis in REFERENCE_REQUIRED and not normalized_reference:
        raise RightsError(
            f"Rights basis '{normalized_basis}' requires a license, permission, or catalog reference."
        )

    return ValidatedRights(normalized_basis, normalized_reference)


def validate_automation_rights(
    *,
    authorized_library: bool,
    basis: str,
    reference: str,
) -> ValidatedRights:
    if not authorized_library:
        raise RightsError(
            "Automatic acquisition is disabled until AUTHORIZED_LIBRARY=true is explicitly set."
        )
    return validate_rights(
        confirmed=True,
        basis=basis,
        reference=reference,
    )
