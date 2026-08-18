from __future__ import annotations

import re
from dataclasses import dataclass

from mcp_common.http import get_case_insensitive

# Only licences that permit redistribution of a verbatim copy get through.
# Every Creative Commons licence does — NC and ND restrict commercial use and
# derivative works, not sharing the file itself — so all six are accepted and
# the restriction travels with the candidate for the operator to see.
CC_LICENSE_RE = re.compile(
    r"creativecommons\.org/licenses/(?P<code>[a-z-]+)/(?P<version>[0-9.]+)",
    re.IGNORECASE,
)
CC_PUBLIC_DOMAIN_RE = re.compile(
    r"creativecommons\.org/(?:publicdomain/(?P<kind>zero|mark)|licenses/publicdomain)",
    re.IGNORECASE,
)
# Wording used by the Archive's own public-domain items, which carry no URL.
PUBLIC_DOMAIN_TEXT_RE = re.compile(
    r"\b(public\s*domain|no\s+known\s+copyright|copyright\s+expired)\b",
    re.IGNORECASE,
)

# The rights vocabulary the shared gate accepts. Mapping to it here keeps the
# connector from inventing a basis the orchestrator cannot validate.
BASIS_PUBLIC_DOMAIN = "public-domain"
BASIS_LICENSED = "licensed"


@dataclass(frozen=True, slots=True)
class LicenseVerdict:
    """What the item says about redistribution, and how sure we are."""

    redistributable: bool
    basis: str
    url: str
    label: str
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "redistributable": self.redistributable,
            "rights_basis": self.basis,
            "license_url": self.url,
            "license_label": self.label,
            "reason": self.reason,
        }


def _cc_label(code: str, version: str) -> str:
    return f"CC {code.upper()} {version}".strip()


def classify_license_url(value: str) -> LicenseVerdict | None:
    """Read one licence URL. Returns None when it says nothing usable."""
    url = (value or "").strip()
    if not url:
        return None
    public_domain = CC_PUBLIC_DOMAIN_RE.search(url)
    if public_domain:
        kind = (public_domain.group("kind") or "").lower()
        label = "CC0" if kind == "zero" else "Public Domain Mark"
        return LicenseVerdict(
            redistributable=True,
            basis=BASIS_PUBLIC_DOMAIN,
            url=url,
            label=label,
            reason=f"Item ist als {label} ausgewiesen.",
        )
    creative_commons = CC_LICENSE_RE.search(url)
    if creative_commons:
        label = _cc_label(
            creative_commons.group("code"), creative_commons.group("version")
        )
        return LicenseVerdict(
            redistributable=True,
            basis=BASIS_LICENSED,
            url=url,
            label=label,
            # The reference the rights gate demands for "licensed" is this URL.
            reason=f"Item steht unter {label}; unveraenderte Weitergabe ist erlaubt.",
        )
    return None


def classify_item(metadata: dict[str, object]) -> LicenseVerdict:
    """Decide whether one Archive item may be copied into a private library.

    The item level is checked first, then the free-text ``rights`` field. An
    item that says nothing is rejected: measured against the live API, a large
    part of the audio catalogue carries no ``licenseurl`` at all (every
    ``freemusicarchive`` and ``etree`` item in the sample), and guessing from
    the collection it sits in would turn "unknown" into "allowed".
    """
    for key in ("licenseurl", "license", "rights"):
        raw = get_case_insensitive(metadata, key)
        for value in raw if isinstance(raw, list) else [raw]:
            verdict = classify_license_url(str(value or ""))
            if verdict is not None:
                return verdict

    rights = get_case_insensitive(metadata, "rights", "usage", default="")
    text = " ".join(rights) if isinstance(rights, list) else str(rights or "")
    if text and PUBLIC_DOMAIN_TEXT_RE.search(text):
        return LicenseVerdict(
            redistributable=True,
            basis=BASIS_PUBLIC_DOMAIN,
            url="",
            label="Public Domain",
            reason=f"Rechtefeld des Items nennt Gemeinfreiheit: {text[:120]}",
        )
    return LicenseVerdict(
        redistributable=False,
        basis="",
        url="",
        label="",
        reason=(
            "Das Item nennt keine maschinenlesbare Lizenz (kein licenseurl, kein "
            "Rechtevermerk). Ohne belegte Lizenz wird es nicht angeboten."
        ),
    )
