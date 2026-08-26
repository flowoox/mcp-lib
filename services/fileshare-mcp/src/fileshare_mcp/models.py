from __future__ import annotations

import re
from pathlib import PureWindowsPath

from pydantic import Field, field_validator, model_validator

from mcp_common.operations import StrictModel

_ALIAS_RE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")


class ShareRoot(StrictModel):
    alias: str = Field(min_length=2, max_length=32)
    path: str = Field(min_length=3, max_length=1024)
    share_name: str | None = Field(default=None, min_length=1, max_length=80)
    description: str = Field(default="", max_length=240)

    @field_validator("alias")
    @classmethod
    def validate_alias(cls, value: str) -> str:
        value = value.strip().lower()
        if not _ALIAS_RE.fullmatch(value):
            raise ValueError("alias must match ^[a-z][a-z0-9_-]{1,31}$")
        return value

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        value = value.strip().rstrip("\\/")
        path = PureWindowsPath(value)
        if not path.is_absolute():
            raise ValueError("share root path must be an absolute Windows path or UNC path")
        if ".." in path.parts:
            raise ValueError("share root path must not contain '..'")
        return str(path)


class FileAce(StrictModel):
    identity: str
    sid: str | None = None
    rights: str
    access_type: str
    inherited: bool
    inheritance_flags: str = ""
    propagation_flags: str = ""


class ShareAce(StrictModel):
    account_name: str
    sid: str | None = None
    access_type: str
    access_right: str


class PathInfo(StrictModel):
    full_path: str
    name: str
    exists: bool = True
    kind: str
    length: int | None = Field(default=None, ge=0)
    last_write_time_utc: str | None = None
    attributes: list[str] = Field(default_factory=list)
    reparse_point: bool = False
    owner: str | None = None


class DirectoryEntry(StrictModel):
    name: str
    kind: str
    length: int | None = Field(default=None, ge=0)
    last_write_time_utc: str | None = None
    attributes: list[str] = Field(default_factory=list)
    reparse_point: bool = False


class AclObservation(StrictModel):
    full_path: str
    owner: str | None = None
    inheritance_protected: bool
    ntfs: list[FileAce] = Field(default_factory=list)
    share: list[ShareAce] = Field(default_factory=list)


class AccessExplanation(StrictModel):
    principal_sid: str
    considered_sids: list[str]
    matching_ntfs_aces: list[FileAce]
    matching_share_aces: list[ShareAce]
    conclusion: str
    authoritative: bool = False
    notes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_non_authoritative(self) -> AccessExplanation:
        if self.authoritative:
            raise ValueError("fileshare access explanations are advisory, never authoritative")
        return self
