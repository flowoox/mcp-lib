import pytest

from mcp_lib.rights import RightsError, validate_automation_rights, validate_rights


def test_requires_confirmation() -> None:
    with pytest.raises(RightsError):
        validate_rights(confirmed=False, basis="owned-copy")


def test_permission_requires_reference() -> None:
    with pytest.raises(RightsError):
        validate_rights(confirmed=True, basis="artist-permission", reference="")


def test_owned_copy_is_accepted() -> None:
    result = validate_rights(confirmed=True, basis="owned-copy", reference="CD shelf #12")
    assert result.basis == "owned-copy"


def test_automation_requires_authorized_library_switch() -> None:
    with pytest.raises(RightsError):
        validate_automation_rights(
            authorized_library=False,
            basis="licensed",
            reference="license-123",
        )
