from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_SAM_RE = re.compile(r"^[A-Za-z0-9._-]{1,20}$")


def _clean_text(value: str, field: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError(f"{field} must not be blank")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"{field} must not contain control characters")
    return value


class CreateDisabledUserInput(BaseModel):
    """Safe subset used to create a disabled AD user without handling a password."""

    model_config = ConfigDict(extra="forbid")

    sam_account_name: str = Field(min_length=1, max_length=20)
    user_principal_name: str = Field(min_length=3, max_length=256)
    display_name: str = Field(min_length=1, max_length=256)
    given_name: str = Field(min_length=1, max_length=128)
    surname: str = Field(min_length=1, max_length=128)
    path: str = Field(min_length=3, max_length=1024)
    mail: str | None = Field(default=None, max_length=320)

    @field_validator("sam_account_name")
    @classmethod
    def validate_sam(cls, value: str) -> str:
        value = value.strip()
        if not _SAM_RE.fullmatch(value):
            raise ValueError("sam_account_name contains unsupported characters")
        return value

    @field_validator("user_principal_name")
    @classmethod
    def validate_upn(cls, value: str) -> str:
        value = _clean_text(value, "user_principal_name")
        if value.count("@") != 1 or " " in value:
            raise ValueError("user_principal_name must contain one '@' and no spaces")
        return value

    @field_validator("display_name", "given_name", "surname")
    @classmethod
    def validate_names(cls, value: str) -> str:
        return _clean_text(value, "name")

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        value = _clean_text(value, "path")
        prefix = value.split("=", 1)[0].casefold()
        if prefix not in {"ou", "cn"} or "," not in value:
            raise ValueError("path must be an OU/container distinguished name")
        return value

    @field_validator("mail")
    @classmethod
    def validate_mail(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = _clean_text(value, "mail")
        if value.count("@") != 1 or " " in value:
            raise ValueError("mail must contain one '@' and no spaces")
        return value


class AddGroupMemberInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_identity: str = Field(min_length=1, max_length=512)
    group_identity: str = Field(min_length=1, max_length=512)

    @field_validator("user_identity", "group_identity")
    @classmethod
    def validate_identity(cls, value: str) -> str:
        return _clean_text(value, "identity")
