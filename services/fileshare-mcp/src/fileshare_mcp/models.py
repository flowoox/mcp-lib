from __future__ import annotations

import re
from pathlib import PureWindowsPath
from typing import Literal

from mcp_common.operations import StrictModel
from pydantic import Field, field_validator, model_validator

_ALIAS_RE = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")


class ShareRoot(StrictModel):
    alias: str = Field(min_length=2, max_length=32)
    path: str = Field(min_length=3, max_length=1024)
    share_name: str | None = Field(default=None, min_length=1, max_length=80)
    description: str = Field(default="", max_length=240)
    content_read: bool = False

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


class FileHashObservation(StrictModel):
    algorithm: Literal["sha256"] = "sha256"
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    length: int = Field(ge=0)
    bytes_read: int = Field(ge=0)


class TextPreviewObservation(StrictModel):
    encoding: Literal["utf-8"] = "utf-8"
    bytes_read: int = Field(ge=0)
    decoded_characters: int = Field(ge=0)
    lines_returned: int = Field(ge=0)
    truncated: bool
    preview: str


class TextSearchMatch(StrictModel):
    line_number: int = Field(ge=1)
    snippet: str = Field(max_length=512)


class TextSearchObservation(StrictModel):
    encoding: Literal["utf-8"] = "utf-8"
    bytes_read: int = Field(ge=0)
    decoded_characters: int = Field(ge=0)
    lines_scanned: int = Field(ge=0)
    truncated: bool
    matches: list[TextSearchMatch] = Field(default_factory=list)
