from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from pydantic import SecretStr

from mcp_ad.client import LdapDirectoryClient, _to_object
from mcp_ad.dn import SearchBaseNotAllowed
from mcp_ad.models import QueryResult
from mcp_ad.settings import Settings


def make_client(**overrides: object) -> LdapDirectoryClient:
    values: dict[str, object] = {
        "ad_host": "dc.example.internal",
        "ad_bind_dn": "reader@example.internal",
        "ad_bind_password": SecretStr("not-a-real-secret"),
        "ad_base_dn": "DC=example,DC=internal",
        "ad_max_results": 200,
    }
    values.update(overrides)
    return LdapDirectoryClient(Settings(**values))


def test_user_identifier_is_escaped_and_filter_is_constructed_by_service() -> None:
    client = make_client()
    captured: dict[str, Any] = {}

    def fake_search(**kwargs: Any) -> QueryResult:
        captured.update(kwargs)
        return QueryResult(count=0, objects=[])

    client._search = fake_search  # type: ignore[method-assign]
    injected = "*)(objectClass=*)"
    client.find_user(injected)

    search_filter = captured["search_filter"]
    assert injected not in search_filter
    assert "\\2a" in search_filter
    assert "\\28" in search_filter
    assert "\\29" in search_filter
    assert captured["limit"] == 10


def test_group_dn_outside_allowlist_is_rejected_before_query() -> None:
    client = make_client()
    with pytest.raises(SearchBaseNotAllowed):
        client.get_group_members("CN=Admins,DC=other,DC=internal")


class FakeEntry:
    def __init__(self, number: int = 1):
        self.entry_dn = f"CN=User {number},OU=People,DC=example,DC=internal"
        self.entry_attributes_as_dict = {
            "objectClass": ["top", "person", "user"],
            "sAMAccountName": f"user-{number}",
        }


class FakeConnection:
    def __init__(self, count: int):
        self.entries = [FakeEntry(number) for number in range(count)]
        self.result = {"description": "success"}
        self.arguments: dict[str, Any] = {}

    def search(self, **kwargs: Any) -> bool:
        self.arguments = kwargs
        return True


def test_runtime_result_limit_is_enforced_even_for_larger_internal_request() -> None:
    client = make_client(ad_max_results=25)
    connection = FakeConnection(count=30)

    @contextmanager
    def fake_connection() -> Iterator[FakeConnection]:
        yield connection

    client.connection = fake_connection  # type: ignore[method-assign]
    result = client._search(
        search_base="DC=example,DC=internal",
        search_filter="(objectClass=user)",
        attributes=("sAMAccountName",),
        limit=100,
    )

    assert connection.arguments["size_limit"] == 26
    assert result.count == 25
    assert result.truncated is True


class SensitiveEntry:
    entry_dn = "CN=svc,OU=People,DC=example,DC=internal"
    entry_attributes_as_dict = {
        "objectClass": ["top", "person", "user"],
        "sAMAccountName": "svc",
        "unicodePwd": b"must-never-leave",
        "objectGUID": b"binary-guid",
    }


def test_directory_object_omits_secret_attributes_and_binary_payloads() -> None:
    result = _to_object(SensitiveEntry())
    assert "unicodePwd" not in result.attributes
    assert result.object_classes == ["top", "person", "user"]
    assert result.attributes["objectGUID"] == {
        "binary_value_omitted": True,
        "length": len(b"binary-guid"),
    }
