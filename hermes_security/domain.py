"""Security-domain types for authorized multi-discipline assessments.

These types deliberately contain no execution logic. They describe engagements,
scope, registered artefacts, device sessions, typed tool requests, approvals, and
policy outcomes that must exist before an agent can ask an isolated worker to
perform an action.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import unquote

from pydantic import BaseModel


_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def canonical_host(host: str) -> str:
    """Return a canonical ASCII hostname or compressed IP literal."""
    value = host.strip().rstrip(".")
    if not value or any(char.isspace() for char in value):
        raise ValueError("host must be a non-empty hostname or IP address")

    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        pass

    if "*" in value:
        raise ValueError("wildcards are not permitted in scope hosts")

    try:
        canonical = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("host is not valid IDNA") from exc

    if not canonical or ".." in canonical:
        raise ValueError("host is not valid")
    return canonical


def canonical_path(path: str) -> str:
    """Normalize a URL path for scope comparisons.

    Percent-encoding is decoded once before normalization so encoded traversal
    cannot bypass a path-prefix rule.
    """
    try:
        decoded = unquote(path or "/", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("path contains invalid percent-encoding") from exc

    if "\x00" in decoded or "\\" in decoded:
        raise ValueError("path contains forbidden characters")

    normalized = posixpath.normpath("/" + decoded.lstrip("/"))
    return "/" if normalized == "." else normalized


class SecurityDomain(StrEnum):
    WEB = "web"
    MOBILE = "mobile"
    REVERSE_ENGINEERING = "reverse_engineering"


class TargetKind(StrEnum):
    URL = "url"
    ARTIFACT = "artifact"
    DEVICE_SESSION = "device_session"
    NONE = "none"


class ArtifactKind(StrEnum):
    ANDROID_APK = "android_apk"
    ANDROID_AAB = "android_aab"
    IOS_IPA = "ios_ipa"
    NATIVE_BINARY = "native_binary"
    MANAGED_ASSEMBLY = "managed_assembly"
    FIRMWARE_IMAGE = "firmware_image"


class EngagementStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    CLOSED = "closed"


class ToolRisk(StrEnum):
    PASSIVE = "passive"
    ACTIVE_SAFE = "active_safe"
    VALIDATION = "validation"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class DecisionCode(StrEnum):
    ALLOW = "allow"
    ENGAGEMENT_MISMATCH = "engagement_mismatch"
    ENGAGEMENT_INACTIVE = "engagement_inactive"
    DOMAIN_NOT_AUTHORIZED = "domain_not_authorized"
    FORBIDDEN_TOOL = "forbidden_tool"
    TOOL_NOT_REGISTERED = "tool_not_registered"
    INVALID_ARGUMENTS = "invalid_arguments"
    TARGET_KIND_MISMATCH = "target_kind_mismatch"
    TARGET_REQUIRED = "target_required"
    TARGET_INVALID = "target_invalid"
    TARGET_OUT_OF_SCOPE = "target_out_of_scope"
    ARTIFACT_REQUIRED = "artifact_required"
    ARTIFACT_NOT_AUTHORIZED = "artifact_not_authorized"
    ARTIFACT_KIND_NOT_ALLOWED = "artifact_kind_not_allowed"
    DEVICE_SESSION_REQUIRED = "device_session_required"
    DEVICE_SESSION_NOT_AUTHORIZED = "device_session_not_authorized"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_INVALID = "approval_invalid"


@dataclass(frozen=True, slots=True)
class ScopeRule:
    """Explicit HTTP(S) scope rule for a web target."""

    scheme: str
    host: str
    port: int | None = None
    path_prefix: str = "/"
    include_subdomains: bool = False

    def __post_init__(self) -> None:
        scheme = self.scheme.strip().lower()
        if scheme not in {"http", "https"}:
            raise ValueError("scope scheme must be http or https")
        if self.port is not None and not 1 <= self.port <= 65535:
            raise ValueError("scope port must be between 1 and 65535")

        object.__setattr__(self, "scheme", scheme)
        object.__setattr__(self, "host", canonical_host(self.host))
        object.__setattr__(self, "path_prefix", canonical_path(self.path_prefix))

    @property
    def effective_port(self) -> int:
        return self.port if self.port is not None else (443 if self.scheme == "https" else 80)


@dataclass(frozen=True, slots=True)
class ArtifactScope:
    """Immutable artefact registered by the operator for authorised analysis."""

    artifact_id: str
    kind: ArtifactKind
    sha256: str
    display_name: str

    def __post_init__(self) -> None:
        if not self.artifact_id.strip():
            raise ValueError("artifact_id is required")
        if not self.display_name.strip():
            raise ValueError("artifact display_name is required")
        if not _SHA256_RE.fullmatch(self.sha256):
            raise ValueError("artifact sha256 must contain exactly 64 hexadecimal characters")
        object.__setattr__(self, "sha256", self.sha256.lower())


@dataclass(frozen=True, slots=True)
class Engagement:
    engagement_id: str
    name: str
    status: EngagementStatus
    scope: tuple[ScopeRule, ...] = ()
    domains: tuple[SecurityDomain, ...] = (SecurityDomain.WEB,)
    artifacts: tuple[ArtifactScope, ...] = ()
    device_session_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.engagement_id.strip():
            raise ValueError("engagement_id is required")
        if not self.name.strip():
            raise ValueError("engagement name is required")
        if not self.domains:
            raise ValueError("engagement must authorize at least one security domain")
        if len(set(self.domains)) != len(self.domains):
            raise ValueError("engagement domains must be unique")
        if len({artifact.artifact_id for artifact in self.artifacts}) != len(self.artifacts):
            raise ValueError("artifact IDs must be unique within an engagement")
        if len(set(self.device_session_ids)) != len(self.device_session_ids):
            raise ValueError("device session IDs must be unique within an engagement")
        if self.status is EngagementStatus.ACTIVE and not (
            self.scope or self.artifacts or self.device_session_ids
        ):
            raise ValueError("active engagements require at least one authorised target")


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    risk: ToolRisk
    arguments_model: type[BaseModel]
    domain: SecurityDomain | None = SecurityDomain.WEB
    target_kind: TargetKind = TargetKind.URL
    network_access: bool = True
    artifact_kinds: frozenset[ArtifactKind] = frozenset()

    def __post_init__(self) -> None:
        if not _TOOL_NAME_RE.fullmatch(self.name):
            raise ValueError("tool names must use lower_snake_case")
        if not issubclass(self.arguments_model, BaseModel):
            raise TypeError("arguments_model must be a pydantic BaseModel type")
        if self.artifact_kinds and self.target_kind is not TargetKind.ARTIFACT:
            raise ValueError("artifact_kinds may only be set for artifact-targeted tools")


@dataclass(frozen=True, slots=True)
class ToolRequest:
    request_id: str
    engagement_id: str
    tool_name: str
    target_url: str | None = None
    artifact_id: str | None = None
    device_session_id: str | None = None
    arguments: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.request_id.strip():
            raise ValueError("request_id is required")
        if not self.engagement_id.strip():
            raise ValueError("engagement_id is required")
        object.__setattr__(self, "arguments", MappingProxyType(dict(self.arguments)))


@dataclass(frozen=True, slots=True)
class Approval:
    approval_id: str
    engagement_id: str
    request_id: str
    tool_name: str
    status: ApprovalStatus


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    code: DecisionCode
    reason: str
    requires_approval: bool = False
