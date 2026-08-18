import pytest
from mcp_common.rights import ALLOWED_RIGHTS_BASES, validate_rights

from archive_mcp.licenses import classify_item, classify_license_url


@pytest.mark.parametrize(
    ("url", "basis", "label"),
    [
        # Exactly the values measured on live items.
        ("https://creativecommons.org/licenses/by/4.0/", "licensed", "CC BY 4.0"),
        ("http://creativecommons.org/licenses/by-nc-nd/3.0/", "licensed", "CC BY-NC-ND 3.0"),
        ("http://creativecommons.org/licenses/by-nd-nc/1.0/", "licensed", "CC BY-ND-NC 1.0"),
        ("https://creativecommons.org/publicdomain/zero/1.0/", "public-domain", "CC0"),
        ("https://creativecommons.org/publicdomain/mark/1.0/", "public-domain", "Public Domain Mark"),
    ],
)
def test_known_open_licenses_are_accepted(url: str, basis: str, label: str) -> None:
    verdict = classify_license_url(url)
    assert verdict is not None
    assert verdict.redistributable is True
    assert verdict.basis == basis
    assert verdict.label == label


def test_every_basis_this_connector_emits_is_one_the_shared_gate_accepts() -> None:
    """The rights vocabulary lives in mcp_common; inventing one here would
    make queue_album_folder fail only at runtime, on the operator's album."""
    for url in (
        "https://creativecommons.org/licenses/by-sa/4.0/",
        "https://creativecommons.org/publicdomain/zero/1.0/",
    ):
        verdict = classify_license_url(url)
        assert verdict is not None
        assert verdict.basis in ALLOWED_RIGHTS_BASES
        # A "licensed" basis needs a reference; the licence URL is it.
        validate_rights(confirmed=True, basis=verdict.basis, reference=verdict.url)


def test_nc_and_nd_still_permit_redistribution() -> None:
    """NC and ND restrict commercial use and derivatives, not copying.

    Rejecting them would drop most of the netlabel catalogue for a reason
    that does not apply to putting a verbatim copy in a private library.
    """
    verdict = classify_license_url("http://creativecommons.org/licenses/by-nc-nd/3.0/")
    assert verdict is not None and verdict.redistributable is True


def test_item_without_any_license_field_is_refused() -> None:
    """Measured: every ``freemusicarchive`` and ``etree`` item in the sample
    carries no ``licenseurl`` at all. Inferring permission from the collection
    would turn "unknown" into "allowed"."""
    verdict = classify_item({"title": "Undercover Vampire Policeman", "collection": "freemusicarchive"})
    assert verdict.redistributable is False
    assert verdict.basis == ""
    assert "keine maschinenlesbare Lizenz" in verdict.reason


def test_proprietary_license_url_is_refused() -> None:
    assert classify_license_url("https://example.com/all-rights-reserved") is None
    verdict = classify_item({"licenseurl": "https://example.com/all-rights-reserved"})
    assert verdict.redistributable is False


def test_license_url_may_arrive_as_a_list() -> None:
    """Archive metadata fields are single-valued or repeated at will."""
    verdict = classify_item(
        {"licenseurl": ["https://creativecommons.org/licenses/by/4.0/"]}
    )
    assert verdict.redistributable is True
    assert verdict.label == "CC BY 4.0"


def test_public_domain_wording_without_a_url_is_accepted() -> None:
    verdict = classify_item({"rights": "Public Domain - no known copyright restrictions"})
    assert verdict.redistributable is True
    assert verdict.basis == "public-domain"
