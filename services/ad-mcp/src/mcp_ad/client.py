from __future__ import annotations

import ssl
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from datetime import date, datetime, timezone
from typing import Any

from ldap3 import (
    AUTO_BIND_NO_TLS,
    AUTO_BIND_TLS_BEFORE_BIND,
    BASE,
    SUBTREE,
    Connection,
    Server,
    Tls,
)
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from .dn import require_allowed_base
from .models import DirectoryObject, QueryResult
from .settings import Settings

USER_ATTRIBUTES = (
    "displayName",
    "givenName",
    "sn",
    "sAMAccountName",
    "userPrincipalName",
    "mail",
    "department",
    "title",
    "company",
    "manager",
    "memberOf",
    "userAccountControl",
    "pwdLastSet",
    "lastLogonTimestamp",
    "whenCreated",
    "whenChanged",
    "adminCount",
)
GROUP_MEMBER_ATTRIBUTES = (
    "displayName",
    "sAMAccountName",
    "userPrincipalName",
    "mail",
    "objectClass",
    "userAccountControl",
    "adminCount",
)
DOMAIN_CONTROLLER_ATTRIBUTES = (
    "dNSHostName",
    "operatingSystem",
    "operatingSystemVersion",
    "servicePrincipalName",
    "userAccountControl",
    "whenCreated",
    "whenChanged",
)
DOMAIN_POLICY_ATTRIBUTES = (
    "distinguishedName",
    "minPwdLength",
    "minPwdAge",
    "maxPwdAge",
    "pwdHistoryLength",
    "pwdProperties",
    "lockoutThreshold",
    "lockoutDuration",
    "lockOutObservationWindow",
    "msDS-Behavior-Version",
)
SENSITIVE_ATTRIBUTES = {
    "unicodepwd",
    "userpassword",
    "dbcspwd",
    "ntpwdhistory",
    "lmpwdhistory",
    "supplementalcredentials",
    "msds-managedpassword",
    "msds-managedpasswordid",
    "msds-groupmsamembership",
}


class DirectoryConnectionError(RuntimeError):
    """A safe error that never includes bind credentials or host details."""


class DirectoryQueryError(RuntimeError):
    pass


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime, date)):
        if isinstance(value, datetime) and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    if isinstance(value, bytes):
        return {"binary_value_omitted": True, "length": len(value)}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return str(value)


def _to_object(entry: Any) -> DirectoryObject:
    values = {
        key: _json_value(value)
        for key, value in entry.entry_attributes_as_dict.items()
        if key.casefold() not in SENSITIVE_ATTRIBUTES
    }
    object_classes: list[str] = []
    for key in list(values):
        if key.casefold() == "objectclass":
            raw_classes = values.pop(key)
            if not isinstance(raw_classes, list):
                raw_classes = [raw_classes]
            object_classes = [str(item) for item in raw_classes]
            break
    return DirectoryObject(
        distinguished_name=str(entry.entry_dn),
        object_classes=object_classes,
        attributes=values,
    )


class LdapDirectoryClient:
    """Narrow AD reader without raw filters, arbitrary attributes or writes."""

    def __init__(self, settings: Settings):
        self.settings = settings

    def _server(self) -> Server:
        validate = ssl.CERT_REQUIRED if self.settings.ad_validate_certificate else ssl.CERT_NONE
        tls = Tls(
            validate=validate,
            ca_certs_file=str(self.settings.ad_ca_file) if self.settings.ad_ca_file else None,
            valid_names=[self.settings.ad_server_name] if self.settings.ad_server_name else None,
        )
        return Server(
            self.settings.ad_host,
            port=self.settings.ad_port,
            use_ssl=self.settings.ad_use_ssl,
            tls=tls,
            connect_timeout=self.settings.ad_connect_timeout_seconds,
        )

    @contextmanager
    def connection(self) -> Iterator[Connection]:
        auto_bind = AUTO_BIND_TLS_BEFORE_BIND if self.settings.ad_start_tls else AUTO_BIND_NO_TLS
        try:
            connection = Connection(
                self._server(),
                user=self.settings.ad_bind_dn,
                password=self.settings.bind_password,
                auto_bind=auto_bind,
                receive_timeout=self.settings.ad_receive_timeout_seconds,
                raise_exceptions=True,
            )
        except LDAPException as exc:
            raise DirectoryConnectionError("Unable to bind to the configured directory") from exc
        try:
            yield connection
        finally:
            with suppress(LDAPException):
                connection.unbind()

    def _search(
        self,
        *,
        search_base: str,
        search_filter: str,
        attributes: Sequence[str],
        search_scope: Any = SUBTREE,
        limit: int | None = None,
    ) -> QueryResult:
        allowed_base = require_allowed_base(search_base, self.settings.allowed_base_dns)
        if limit is not None and limit < 1:
            raise ValueError("limit must be positive")
        requested_limit = min(limit or self.settings.ad_max_results, self.settings.ad_max_results)
        server_limit = min(requested_limit + 1, 1000)
        search_arguments: dict[str, Any] = {
            "search_base": allowed_base,
            "search_filter": search_filter,
            "search_scope": search_scope,
            "attributes": list(attributes),
            "size_limit": server_limit,
        }
        if search_scope == SUBTREE:
            search_arguments["paged_size"] = server_limit

        try:
            with self.connection() as connection:
                ok = connection.search(**search_arguments)
                result = connection.result or {}
                description = str(result.get("description", ""))
                if not ok and description not in {"success", "sizeLimitExceeded"}:
                    raise DirectoryQueryError(f"LDAP query failed: {description or 'unknown error'}")
                entries = list(connection.entries)
        except DirectoryConnectionError:
            raise
        except LDAPException as exc:
            raise DirectoryQueryError("LDAP query failed") from exc

        truncated = len(entries) > requested_limit or description == "sizeLimitExceeded"
        objects = [_to_object(entry) for entry in entries[:requested_limit]]
        return QueryResult(count=len(objects), truncated=truncated, objects=objects)

    def get_domain_policy(self) -> QueryResult:
        return self._search(
            search_base=self.settings.ad_base_dn,
            search_filter="(objectClass=domainDNS)",
            search_scope=BASE,
            attributes=DOMAIN_POLICY_ATTRIBUTES,
            limit=1,
        )

    def find_user(self, identifier: str) -> QueryResult:
        value = identifier.strip()
        if not value or len(value) > 256:
            raise ValueError("identifier must contain 1-256 characters")
        escaped = escape_filter_chars(value)
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            f"(|(sAMAccountName={escaped})(userPrincipalName={escaped})(mail={escaped})))"
        )
        return self._search(
            search_base=self.settings.ad_base_dn,
            search_filter=search_filter,
            attributes=USER_ATTRIBUTES,
            limit=10,
        )

    def get_group_members(self, group_dn: str, *, limit: int | None = None) -> QueryResult:
        allowed_group = require_allowed_base(group_dn, self.settings.allowed_base_dns)
        escaped_group = escape_filter_chars(allowed_group)
        return self._search(
            search_base=self.settings.ad_base_dn,
            search_filter=f"(memberOf={escaped_group})",
            attributes=GROUP_MEMBER_ATTRIBUTES,
            limit=limit,
        )

    def list_domain_controllers(self) -> QueryResult:
        return self._search(
            search_base=self.settings.ad_base_dn,
            search_filter=(
                "(&(objectCategory=computer)"
                "(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            ),
            attributes=DOMAIN_CONTROLLER_ATTRIBUTES,
        )

    def list_stale_enabled_users(self, *, stale_before_filetime: int) -> QueryResult:
        if stale_before_filetime <= 0:
            raise ValueError("stale_before_filetime must be positive")
        return self._search(
            search_base=self.settings.ad_base_dn,
            search_filter=(
                "(&(objectCategory=person)(objectClass=user)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                f"(|(!(lastLogonTimestamp=*))(lastLogonTimestamp<={stale_before_filetime})))"
            ),
            attributes=USER_ATTRIBUTES,
        )

    def list_privileged_members(self) -> dict[str, QueryResult]:
        return {
            group_dn: self.get_group_members(group_dn)
            for group_dn in self.settings.privileged_group_dns
        }
