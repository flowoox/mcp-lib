import pytest
from pydantic import ValidationError

from ad_mcp.write_models import AddGroupMemberInput, CreateDisabledUserInput


def _valid_user() -> dict[str, str]:
    return {
        "sam_account_name": "alice",
        "user_principal_name": "alice@example.invalid",
        "display_name": "Alice Example",
        "given_name": "Alice",
        "surname": "Example",
        "path": "OU=Users,DC=example,DC=invalid",
    }


def test_create_disabled_user_accepts_bounded_identity_fields() -> None:
    request = CreateDisabledUserInput(**_valid_user())
    assert request.sam_account_name == "alice"


@pytest.mark.parametrize("sam", ["alice user", "alice;rm", "a" * 21, "alice\\admin"])
def test_sam_account_name_rejects_unsafe_shapes(sam: str) -> None:
    values = _valid_user()
    values["sam_account_name"] = sam
    with pytest.raises(ValidationError):
        CreateDisabledUserInput(**values)


def test_user_path_must_be_directory_container_dn() -> None:
    values = _valid_user()
    values["path"] = "DC=example,DC=invalid"
    with pytest.raises(ValidationError, match="OU/container"):
        CreateDisabledUserInput(**values)


def test_write_inputs_reject_control_characters() -> None:
    values = _valid_user()
    values["display_name"] = "Alice\nNew-ADUser"
    with pytest.raises(ValidationError):
        CreateDisabledUserInput(**values)
    with pytest.raises(ValidationError):
        AddGroupMemberInput(user_identity="alice\n", group_identity="Employees")
