from __future__ import annotations

from dataclasses import asdict, dataclass

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
    pass


@dataclass(frozen=True, slots=True)
class RightsAssertion:
    basis: str
    reference: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def validate_rights(
    *,
    confirmed: bool,
    basis: str,
    reference: str = "",
) -> RightsAssertion:
    normalized = basis.strip().casefold()
    reference = reference.strip()
    if not confirmed:
        raise RightsError("Explicit authorization for this library operation is required")
    if normalized not in ALLOWED_RIGHTS_BASES:
        raise RightsError(
            "rights_basis must be one of: " + ", ".join(sorted(ALLOWED_RIGHTS_BASES))
        )
    if normalized in REFERENCE_REQUIRED and not reference:
        raise RightsError(f"A rights reference is required for {normalized}")
    return RightsAssertion(normalized, reference)
