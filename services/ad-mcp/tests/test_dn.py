import pytest

from mcp_ad.dn import (
    InvalidDistinguishedName,
    SearchBaseNotAllowed,
    is_within_base,
    require_allowed_base,
)


def test_nested_dn_is_within_configured_base() -> None:
    assert is_within_base(
        "CN=Alice,OU=People,DC=Example,DC=Internal",
        "OU=People,DC=example,DC=internal",
    )


def test_similarly_named_suffix_is_not_allowed() -> None:
    assert not is_within_base(
        "CN=Alice,OU=People,DC=notexample,DC=internal",
        "DC=example,DC=internal",
    )


def test_escaped_separator_is_parsed_before_comparison() -> None:
    assert is_within_base(
        r"CN=Doe\, Jane,OU=People,DC=example,DC=internal",
        "OU=People,DC=example,DC=internal",
    )


def test_invalid_dn_is_normalized_to_safe_error() -> None:
    with pytest.raises(InvalidDistinguishedName):
        is_within_base("not-a-dn", "DC=example,DC=internal")


def test_out_of_scope_base_fails_closed() -> None:
    with pytest.raises(SearchBaseNotAllowed):
        require_allowed_base(
            "CN=Administrators,CN=Builtin,DC=other,DC=internal",
            ("DC=example,DC=internal",),
        )
