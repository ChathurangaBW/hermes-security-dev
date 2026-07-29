"""Authorized web-application pentest control-plane primitives.

This module deliberately contains no worker or network execution. It defines
engagement scope, typed tool requests, approval requirements, and policy
decisions that must be satisfied before future isolated workers can run.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal, Mapping
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError


_TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")

FORBIDDEN_TOOL_NAMES = frozenset(
    {
        "bash",
        "exec",
        "execute_command",
        "powershell",
        "run_command",
        "run_shell",
        "shell",
        "ssh_exec",
        "terminal",
    }
)


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
    """Normalize a URL path for scope comparisons."""
    try:
        decoded = unquote(path or "/", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("path contains invalid percent-encoding") from exc

    if "\x00" in decoded or "\\" in decoded:
        raise ValueError("path contains forbidden characters")

    normalized = posixpath.normpath("/" + decoded.lstrip("/"))
    return "/" if normalized == "." else normalized


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
    FORBIDDEN_TOOL = "forbidden_tool"
    TOOL_NOT_REGISTERED = "tool_not_registered"
    INVALID_ARGUMENTS = "invalid_arguments"
    TARGET_REQUIRED = "target_required"
    TARGET_INVALID = "target_invalid"
    TARGET_OUT_OF_SCOPE = "target_out_of_scope"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_INVALID = "approval_invalid"


@dataclass(frozen=True, slots=True)
class ScopeRule:
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
class Engagement:
    engagement_id: str
    name: str
    status: EngagementStatus
    scope: tuple[ScopeRule, ...]

    def __post_init__(self) -> None:
        if not self.engagement_id.strip():
            raise ValueError("engagement_id is required")
        if not self.name.strip():
            raise ValueError("engagement name is required")
        if self.status is EngagementStatus.ACTIVE and not self.scope:
            raise ValueError("active engagements require at least one scope rule")


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    risk: ToolRisk
    arguments_model: type[BaseModel]
    requires_target: bool = True
    network_access: bool = True

    def __post_init__(self) -> None:
        if not _TOOL_NAME_RE.fullmatch(self.name):
            raise ValueError("tool names must use lower_snake_case")
        if not issubclass(self.arguments_model, BaseModel):
            raise TypeError("arguments_model must be a pydantic BaseModel type")


@dataclass(frozen=True, slots=True)
class ToolRequest:
    request_id: str
    engagement_id: str
    tool_name: str
    target_url: str | None = None
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


@dataclass(frozen=True, slots=True)
class ScopeMatch:
    matched: bool
    reason: str
    rule: ScopeRule | None = None


def match_scope(target_url: str, rules: tuple[ScopeRule, ...]) -> ScopeMatch:
    """Match an HTTP(S) URL against explicit engagement scope rules."""
    try:
        parsed = urlsplit(target_url)
    except ValueError as exc:
        return ScopeMatch(False, f"target URL is invalid: {exc}")

    if parsed.scheme.lower() not in {"http", "https"}:
        return ScopeMatch(False, "target URL must use http or https")
    if parsed.username is not None or parsed.password is not None:
        return ScopeMatch(False, "userinfo is not permitted in target URLs")
    if parsed.hostname is None:
        return ScopeMatch(False, "target URL must contain a hostname")

    try:
        host = canonical_host(parsed.hostname)
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        path = canonical_path(parsed.path)
    except ValueError as exc:
        return ScopeMatch(False, f"target URL is invalid: {exc}")

    for rule in rules:
        host_matches = host == rule.host or (
            rule.include_subdomains and host.endswith("." + rule.host)
        )
        if not host_matches:
            continue
        if parsed.scheme.lower() != rule.scheme or port != rule.effective_port:
            continue

        prefix = rule.path_prefix
        path_matches = prefix == "/" or path == prefix or path.startswith(prefix + "/")
        if path_matches:
            return ScopeMatch(True, "target is within engagement scope", rule)

    return ScopeMatch(False, "target is outside engagement scope")


class StrictArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CrawlTargetArguments(StrictArguments):
    max_pages: int = Field(default=100, ge=1, le=1_000)
    max_depth: int = Field(default=3, ge=0, le=10)
    same_origin_only: Literal[True] = True


class HttpProbeArguments(StrictArguments):
    method: Literal["GET", "HEAD", "OPTIONS"] = "GET"
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=30.0)
    follow_redirects: bool = False


class AnalyzeHeadersArguments(StrictArguments):
    include_informational: bool = False


class CheckTlsConfigArguments(StrictArguments):
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=30.0)


class PassiveScanArguments(StrictArguments):
    profile: Literal["baseline", "owasp_passive"] = "baseline"
    max_requests: int = Field(default=200, ge=1, le=500)


class AuthenticatedSafeCheckArguments(StrictArguments):
    check_name: Literal[
        "access_control_readonly",
        "csrf_presence",
        "session_cookie_flags",
    ]
    credential_reference_id: str = Field(min_length=1, max_length=128)
    max_requests: int = Field(default=20, ge=1, le=50)


class VerifyFindingArguments(StrictArguments):
    finding_id: str = Field(min_length=1, max_length=128)
    verification_mode: Literal["replay_evidence", "safe_recheck"]
    max_requests: int = Field(default=10, ge=1, le=20)


class ExportReportArguments(StrictArguments):
    format: Literal["json", "html", "markdown"] = "markdown"
    validated_only: Literal[True] = True


DEFAULT_TOOL_DEFINITIONS = (
    ToolDefinition("crawl_target", ToolRisk.PASSIVE, CrawlTargetArguments),
    ToolDefinition("http_probe", ToolRisk.PASSIVE, HttpProbeArguments),
    ToolDefinition("analyze_headers", ToolRisk.PASSIVE, AnalyzeHeadersArguments),
    ToolDefinition("check_tls_config", ToolRisk.PASSIVE, CheckTlsConfigArguments),
    ToolDefinition("run_passive_scan", ToolRisk.PASSIVE, PassiveScanArguments),
    ToolDefinition(
        "run_authenticated_safe_check",
        ToolRisk.ACTIVE_SAFE,
        AuthenticatedSafeCheckArguments,
    ),
    ToolDefinition(
        "verify_candidate_finding",
        ToolRisk.VALIDATION,
        VerifyFindingArguments,
    ),
    ToolDefinition(
        "export_report",
        ToolRisk.PASSIVE,
        ExportReportArguments,
        requires_target=False,
        network_access=False,
    ),
)


class PolicyEngine:
    """Authorize model-proposed tool requests without executing them."""

    def __init__(self, definitions: Iterable[ToolDefinition] = ()) -> None:
        self._definitions: dict[str, ToolDefinition] = {}
        for definition in definitions:
            self.register(definition)

    def register(self, definition: ToolDefinition) -> None:
        if definition.name in FORBIDDEN_TOOL_NAMES:
            raise ValueError(f"tool {definition.name!r} is prohibited")
        if definition.name in self._definitions:
            raise ValueError(f"tool {definition.name!r} is already registered")
        self._definitions[definition.name] = definition

    @property
    def definitions(self) -> tuple[ToolDefinition, ...]:
        return tuple(self._definitions.values())

    def evaluate(
        self,
        *,
        engagement: Engagement,
        request: ToolRequest,
        approval: Approval | None = None,
    ) -> PolicyDecision:
        if request.engagement_id != engagement.engagement_id:
            return PolicyDecision(
                False,
                DecisionCode.ENGAGEMENT_MISMATCH,
                "tool request does not belong to the supplied engagement",
            )

        if engagement.status is not EngagementStatus.ACTIVE:
            return PolicyDecision(
                False,
                DecisionCode.ENGAGEMENT_INACTIVE,
                f"engagement is {engagement.status.value}, not active",
            )

        if request.tool_name in FORBIDDEN_TOOL_NAMES:
            return PolicyDecision(
                False,
                DecisionCode.FORBIDDEN_TOOL,
                "generic command execution is prohibited",
            )

        definition = self._definitions.get(request.tool_name)
        if definition is None:
            return PolicyDecision(
                False,
                DecisionCode.TOOL_NOT_REGISTERED,
                "tool is not present in the security tool catalogue",
            )

        try:
            definition.arguments_model.model_validate(dict(request.arguments))
        except ValidationError as exc:
            first_error = exc.errors(include_url=False)[0]
            location = ".".join(str(part) for part in first_error["loc"]) or "arguments"
            return PolicyDecision(
                False,
                DecisionCode.INVALID_ARGUMENTS,
                f"invalid tool arguments at {location}: {first_error['msg']}",
            )

        if definition.requires_target:
            if not request.target_url:
                return PolicyDecision(
                    False,
                    DecisionCode.TARGET_REQUIRED,
                    "tool requires an explicit target URL",
                )
            scope_match = match_scope(request.target_url, engagement.scope)
            if not scope_match.matched:
                code = (
                    DecisionCode.TARGET_INVALID
                    if scope_match.reason.startswith("target URL")
                    else DecisionCode.TARGET_OUT_OF_SCOPE
                )
                return PolicyDecision(False, code, scope_match.reason)
        elif request.target_url is not None:
            return PolicyDecision(
                False,
                DecisionCode.INVALID_ARGUMENTS,
                "non-targeted tool requests must not include target_url",
            )

        if definition.risk is ToolRisk.VALIDATION:
            if approval is None or approval.status is ApprovalStatus.PENDING:
                return PolicyDecision(
                    False,
                    DecisionCode.APPROVAL_REQUIRED,
                    "validation action requires explicit human approval",
                    requires_approval=True,
                )
            if (
                approval.status is not ApprovalStatus.APPROVED
                or approval.engagement_id != engagement.engagement_id
                or approval.request_id != request.request_id
                or approval.tool_name != request.tool_name
            ):
                return PolicyDecision(
                    False,
                    DecisionCode.APPROVAL_INVALID,
                    "approval does not authorize this exact tool request",
                    requires_approval=True,
                )

        return PolicyDecision(True, DecisionCode.ALLOW, "policy authorized the tool request")


class TypedToolBroker:
    """Policy-check requests before a future isolated worker receives them.

    The broker intentionally has no ``execute`` method. Worker dispatch will be
    added only after audit, evidence, and isolation contracts exist.
    """

    def __init__(self, policy: PolicyEngine | None = None) -> None:
        self.policy = policy or PolicyEngine(DEFAULT_TOOL_DEFINITIONS)

    def authorize(
        self,
        *,
        engagement: Engagement,
        request: ToolRequest,
        approval: Approval | None = None,
    ) -> PolicyDecision:
        return self.policy.evaluate(
            engagement=engagement,
            request=request,
            approval=approval,
        )
