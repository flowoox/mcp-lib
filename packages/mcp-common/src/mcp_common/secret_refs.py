from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from secrets import token_urlsafe
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

_REFERENCE_PREFIX = "mcpsecret:v1:"
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{2,127}$")
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_TTL = timedelta(hours=1)
_CLOCK_SKEW = timedelta(minutes=2)
_MAX_FILE_BYTES = 16 * 1024


class SecretReferenceEnvelope(BaseModel):
    """One-time secret envelope stored outside the model-facing MCP request."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    purpose: str = Field(pattern=_NAME_RE.pattern)
    target: str = Field(min_length=1, max_length=500)
    idempotency_key: str = Field(min_length=8, max_length=128)
    reference_sha256: str = Field(pattern=_DIGEST_RE.pattern)
    issued_at: datetime
    expires_at: datetime
    secret: SecretStr = Field(min_length=1, max_length=4096)

    @field_validator("target")
    @classmethod
    def clean_target(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(character) < 32 for character in value):
            raise ValueError("target must be non-blank and contain no control characters")
        return value

    @field_validator("idempotency_key")
    @classmethod
    def validate_idempotency_key(cls, value: str) -> str:
        value = value.strip()
        if not _IDEMPOTENCY_RE.fullmatch(value):
            raise ValueError("invalid idempotency_key")
        return value

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("secret envelope timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_window(self) -> SecretReferenceEnvelope:
        if self.expires_at <= self.issued_at:
            raise ValueError("secret envelope must expire after it is issued")
        if self.expires_at - self.issued_at > _MAX_TTL:
            raise ValueError("secret envelope TTL must not exceed one hour")
        return self


def parse_secret_reference(reference: str) -> str:
    value = reference.strip()
    if not value.startswith(_REFERENCE_PREFIX):
        raise ValueError("invalid opaque secret reference")
    token = value[len(_REFERENCE_PREFIX) :]
    if not _TOKEN_RE.fullmatch(token):
        raise ValueError("invalid opaque secret reference")
    return token


def secret_reference_sha256(reference: str) -> str:
    token = parse_secret_reference(reference)
    canonical = f"{_REFERENCE_PREFIX}{token}".encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def new_secret_reference() -> str:
    while True:
        token = token_urlsafe(32)
        if _TOKEN_RE.fullmatch(token):
            return f"{_REFERENCE_PREFIX}{token}"


def _secret_root(path: str | Path, *, create: bool) -> Path:
    root = Path(path).expanduser()
    if not root.is_absolute():
        raise ValueError("secret reference directory must be absolute")
    if create:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        original_info = root.lstat()
    except OSError as exc:
        raise ValueError("secret reference directory is unavailable") from exc
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if root.is_symlink() or getattr(original_info, "st_file_attributes", 0) & reparse_flag:
        raise PermissionError("secret reference directory must not be a link or reparse point")
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ValueError("secret reference directory is unavailable") from exc
    if not resolved.is_dir():
        raise ValueError("secret reference directory must be a directory")
    info = resolved.stat()
    if os.name != "nt" and info.st_mode & 0o077:
        raise PermissionError("secret reference directory must not be group/world accessible")
    return resolved


def _validate_secret_file(path: Path, root: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError("secret reference is unavailable or already consumed") from exc
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise PermissionError("secret reference must resolve to a regular non-link file")
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if getattr(info, "st_file_attributes", 0) & reparse_flag:
        raise PermissionError("secret reference must not be a reparse point")
    if info.st_size < 2 or info.st_size > _MAX_FILE_BYTES:
        raise ValueError("secret reference file has an invalid size")
    if os.name != "nt" and info.st_mode & 0o077:
        raise PermissionError("secret reference file must not be group/world accessible")
    try:
        parent = path.resolve(strict=True).parent
    except OSError as exc:
        raise ValueError("secret reference file cannot be resolved") from exc
    if parent != root:
        raise PermissionError("secret reference escaped the configured directory")


def stage_secret_reference(
    directory: str | Path,
    *,
    purpose: str,
    target: str,
    idempotency_key: str,
    secret: str,
    ttl_seconds: int = 900,
    now: datetime | None = None,
) -> str:
    """Stage a one-time secret file for a trusted broker and return only its opaque handle."""

    if ttl_seconds < 1 or ttl_seconds > int(_MAX_TTL.total_seconds()):
        raise ValueError("ttl_seconds must be between 1 and 3600")
    root = _secret_root(directory, create=True)
    issued_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    reference = new_secret_reference()
    token = parse_secret_reference(reference)
    envelope = SecretReferenceEnvelope(
        purpose=purpose,
        target=target,
        idempotency_key=idempotency_key,
        reference_sha256=secret_reference_sha256(reference),
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=ttl_seconds),
        secret=secret,
    )
    payload = envelope.model_dump(mode="json")
    payload["secret"] = envelope.secret.get_secret_value()
    data = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    if len(data) > _MAX_FILE_BYTES:
        raise ValueError("secret envelope is too large")

    final_path = root / f"{token}.json"
    temp_path = root / f".stage-{token}-{uuid4().hex}.tmp"
    descriptor = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o600)
        os.rename(temp_path, final_path)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
    return reference


def consume_secret_reference(
    directory: str | Path,
    reference: str,
    *,
    purpose: str,
    target: str,
    idempotency_key: str,
    now: datetime | None = None,
) -> SecretStr:
    """Atomically consume and validate one target-bound secret reference.

    The source file is renamed before it is read and is deleted after this call,
    including on validation failure. This deliberately favors fail-closed,
    one-time use over automatic retries with the same secret material.
    """

    root = _secret_root(directory, create=False)
    token = parse_secret_reference(reference)
    source = root / f"{token}.json"
    claimed = root / f".claimed-{token}-{uuid4().hex}.json"
    try:
        os.rename(source, claimed)
    except OSError as exc:
        raise ValueError("secret reference is unavailable or already consumed") from exc

    try:
        _validate_secret_file(claimed, root)
        try:
            raw = json.loads(claimed.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("secret reference file is invalid") from exc
        envelope = SecretReferenceEnvelope.model_validate(raw)
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if envelope.issued_at - _CLOCK_SKEW > current:
            raise ValueError("secret reference is not yet valid")
        if envelope.expires_at < current:
            raise ValueError("secret reference has expired")
        expected = {
            "purpose": purpose,
            "target": target,
            "idempotency_key": idempotency_key,
            "reference_sha256": secret_reference_sha256(reference),
        }
        actual = {
            "purpose": envelope.purpose,
            "target": envelope.target,
            "idempotency_key": envelope.idempotency_key,
            "reference_sha256": envelope.reference_sha256,
        }
        if actual != expected:
            raise ValueError("secret reference does not match the requested operation")
        return SecretStr(envelope.secret.get_secret_value())
    finally:
        try:
            claimed.unlink()
        except FileNotFoundError:
            pass
