"""Authorized multi-discipline security assessment control-plane primitives.

This module deliberately contains no worker, network, device, or process
execution. It defines the engagement, target, typed-tool, approval, and policy
contracts that must be satisfied before future isolated workers can run.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
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
_WORKER_PROFILE_RE = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

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
    """Normalize a URL path for scope comparisons.

    Percent-encoding is decoded before normalization so encoded traversal cannot
    bypass a path-prefix rule.
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


class MobilePlatform(StrEnum):
    ANDROID = "android"
    IOS = "ios"


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
class DeviceSessionScope:
    """Operator-registered test device or emulator session."""

    session_id: str
    platform: MobilePlatform

    def __post_init__(self) -> None:
        if not self.session_id.strip():
            raise ValueError("device session_id is required")


@dataclass(frozen=True, slots=True)
class Engagement:
    engagement_id: str
    name: str
    status: EngagementStatus
    scope: tuple[ScopeRule, ...] = ()
    domains: tuple[SecurityDomain, ...] = (SecurityDomain.WEB,)
    artifacts: tuple[ArtifactScope, ...] = ()
    device_sessions: tuple[DeviceSessionScope, ...] = ()

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
        if len({session.session_id for session in self.device_sessions}) != len(
            self.device_sessions
        ):
            raise ValueError("device session IDs must be unique within an engagement")
        if self.status is EngagementStatus.ACTIVE and not (
            self.scope or self.artifacts or self.device_sessions
        ):
            raise ValueError("active engagements require at least one authorised target")


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    risk: ToolRisk
    arguments_model: type[BaseModel]
    domain: SecurityDomain | None = SecurityDomain.WEB
    target_kind: TargetKind = TargetKind.URL
    worker_profile: str = "web-passive"
    network_access: bool = True
    artifact_kinds: frozenset[ArtifactKind] = frozenset()

    def __post_init__(self) -> None:
        if not _TOOL_NAME_RE.fullmatch(self.name):
            raise ValueError("tool names must use lower_snake_case")
        if not issubclass(self.arguments_model, BaseModel):
            raise TypeError("arguments_model must be a pydantic BaseModel type")
        if not _WORKER_PROFILE_RE.fullmatch(self.worker_profile):
            raise ValueError("worker_profile must use a constrained slug")
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

        argument_snapshot = dict(self.arguments)
        try:
            json.dumps(argument_snapshot, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError("tool arguments must be JSON serializable") from exc
        object.__setattr__(self, "arguments", MappingProxyType(argument_snapshot))

    @property
    def fingerprint(self) -> str:
        """Bind an approval to the exact immutable request content."""
        payload = {
            "artifact_id": self.artifact_id,
            "arguments": dict(self.arguments),
            "device_session_id": self.device_session_id,
            "engagement_id": self.engagement_id,
            "request_id": self.request_id,
            "target_url": self.target_url,
            "tool_name": self.tool_name,
        }
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class Approval:
    approval_id: str
    engagement_id: str
    request_id: str
    tool_name: str
    request_fingerprint: str
    status: ApprovalStatus

    def __post_init__(self) -> None:
        if not self.approval_id.strip():
            raise ValueError("approval_id is required")
        if not _SHA256_RE.fullmatch(self.request_fingerprint):
            raise ValueError("request_fingerprint must be a SHA-256 hex digest")
        object.__setattr__(self, "request_fingerprint", self.request_fingerprint.lower())


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


# Web assessment tools


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


# Mobile assessment tools


class MobileStaticArguments(StrictArguments):
    platform: Literal["auto", "android", "ios"] = "auto"


class MobileEndpointArguments(MobileStaticArguments):
    include_native_libraries: bool = True
    max_results: int = Field(default=500, ge=1, le=5_000)


class ObserveMobileRuntimeArguments(StrictArguments):
    platform: Literal["android", "ios"]
    app_identifier: str = Field(min_length=1, max_length=255)
    duration_seconds: int = Field(default=30, ge=5, le=120)
    network_mode: Literal["disabled", "engagement_proxy"] = "disabled"
    capture_screenshots: bool = False


# Reverse-engineering tools


class FingerprintBinaryArguments(StrictArguments):
    calculate_entropy: bool = True
    detect_packers: bool = True


class ExtractBinaryStringsArguments(StrictArguments):
    minimum_length: int = Field(default=5, ge=3, le=64)
    max_results: int = Field(default=2_000, ge=1, le=20_000)
    encodings: tuple[Literal["ascii", "utf16le", "utf16be"], ...] = (
        "ascii",
        "utf16le",
    )


class InspectBinaryImportsArguments(StrictArguments):
    include_delay_loaded: bool = True
    demangle_symbols: bool = True


class AnalyzeControlFlowArguments(StrictArguments):
    function_identifier: str | None = Field(default=None, max_length=512)
    max_functions: int = Field(default=500, ge=1, le=5_000)


class DecompileFunctionArguments(StrictArguments):
    function_identifier: str = Field(min_length=1, max_length=512)
    max_output_characters: int = Field(default=40_000, ge=1_000, le=200_000)


class ObserveBinaryRuntimeArguments(StrictArguments):
    duration_seconds: int = Field(default=30, ge=5, le=120)
    network_mode: Literal["disabled"] = "disabled"
    collect_syscalls: Literal[True] = True
    collect_child_process_metadata: bool = True


class ExportReportArguments(StrictArguments):
    format: Literal["json", "html", "markdown"] = "markdown"
    validated_only: Literal[True] = True


_MOBILE_PACKAGES = frozenset(
    {
        ArtifactKind.ANDROID_APK,
        ArtifactKind.ANDROID_AAB,
        ArtifactKind.IOS_IPA,
    }
)

_REVERSE_ARTIFACTS = frozenset(
    {
        ArtifactKind.NATIVE_BINARY,
        ArtifactKind.MANAGED_ASSEMBLY,
        ArtifactKind.FIRMWARE_IMAGE,
        ArtifactKind.ANDROID_APK,
        ArtifactKind.IOS_IPA,
    }
)

DEFAULT_TOOL_DEFINITIONS = (
    ToolDefinition(
        "crawl_target",
        ToolRisk.PASSIVE,
        CrawlTargetArguments,
        domain=SecurityDomain.WEB,
        target_kind=TargetKind.URL,
        worker_profile="web-passive",
    ),
    ToolDefinition(
        "http_probe",
        ToolRisk.PASSIVE,
        HttpProbeArguments,
        domain=SecurityDomain.WEB,
        target_kind=TargetKind.URL,
        worker_profile="web-passive",
    ),
    ToolDefinition(
        "analyze_headers",
        ToolRisk.PASSIVE,
        AnalyzeHeadersArguments,
        domain=SecurityDomain.WEB,
        target_kind=TargetKind.URL,
        worker_profile="web-passive",
    ),
    ToolDefinition(
        "check_tls_config",
        ToolRisk.PASSIVE,
        CheckTlsConfigArguments,
        domain=SecurityDomain.WEB,
        target_kind=TargetKind.URL,
        worker_profile="web-passive",
    ),
    ToolDefinition(
        "run_passive_scan",
        ToolRisk.PASSIVE,
        PassiveScanArguments,
        domain=SecurityDomain.WEB,
        target_kind=TargetKind.URL,
        worker_profile="web-passive",
    ),
    ToolDefinition(
        "run_authenticated_safe_check",
        ToolRisk.ACTIVE_SAFE,
        AuthenticatedSafeCheckArguments,
        domain=SecurityDomain.WEB,
        target_kind=TargetKind.URL,
        worker_profile="web-active-safe",
    ),
    ToolDefinition(
        "verify_candidate_finding",
        ToolRisk.VALIDATION,
        VerifyFindingArguments,
        domain=SecurityDomain.WEB,
        target_kind=TargetKind.URL,
        worker_profile="web-validation",
    ),
    ToolDefinition(
        "inspect_mobile_manifest",
        ToolRisk.PASSIVE,
        MobileStaticArguments,
        domain=SecurityDomain.MOBILE,
        target_kind=TargetKind.ARTIFACT,
        worker_profile="mobile-static",
        network_access=False,
        artifact_kinds=_MOBILE_PACKAGES,
    ),
    ToolDefinition(
        "enumerate_mobile_permissions",
        ToolRisk.PASSIVE,
        MobileStaticArguments,
        domain=SecurityDomain.MOBILE,
        target_kind=TargetKind.ARTIFACT,
        worker_profile="mobile-static",
        network_access=False,
        artifact_kinds=_MOBILE_PACKAGES,
    ),
    ToolDefinition(
        "analyze_mobile_network_security",
        ToolRisk.PASSIVE,
        MobileStaticArguments,
        domain=SecurityDomain.MOBILE,
        target_kind=TargetKind.ARTIFACT,
        worker_profile="mobile-static",
        network_access=False,
        artifact_kinds=_MOBILE_PACKAGES,
    ),
    ToolDefinition(
        "extract_mobile_endpoints",
        ToolRisk.PASSIVE,
        MobileEndpointArguments,
        domain=SecurityDomain.MOBILE,
        target_kind=TargetKind.ARTIFACT,
        worker_profile="mobile-static",
        network_access=False,
        artifact_kinds=_MOBILE_PACKAGES,
    ),
    ToolDefinition(
        "observe_mobile_runtime",
        ToolRisk.VALIDATION,
        ObserveMobileRuntimeArguments,
        domain=SecurityDomain.MOBILE,
        target_kind=TargetKind.DEVICE_SESSION,
        worker_profile="mobile-runtime",
    ),
    ToolDefinition(
        "fingerprint_binary",
        ToolRisk.PASSIVE,
        FingerprintBinaryArguments,
        domain=SecurityDomain.REVERSE_ENGINEERING,
        target_kind=TargetKind.ARTIFACT,
        worker_profile="reverse-static",
        network_access=False,
        artifact_kinds=_REVERSE_ARTIFACTS,
    ),
    ToolDefinition(
        "extract_binary_strings",
        ToolRisk.PASSIVE,
        ExtractBinaryStringsArguments,
        domain=SecurityDomain.REVERSE_ENGINEERING,
        target_kind=TargetKind.ARTIFACT,
        worker_profile="reverse-static",
        network_access=False,
        artifact_kinds=_REVERSE_ARTIFACTS,
    ),
    ToolDefinition(
        "inspect_binary_imports",
        ToolRisk.PASSIVE,
        InspectBinaryImportsArguments,
        domain=SecurityDomain.REVERSE_ENGINEERING,
        target_kind=TargetKind.ARTIFACT,
        worker_profile="reverse-static",
        network_access=False,
        artifact_kinds=_REVERSE_ARTIFACTS,
    ),
    ToolDefinition(
        "analyze_control_flow",
        ToolRisk.PASSIVE,
        AnalyzeControlFlowArguments,
        domain=SecurityDomain.REVERSE_ENGINEERING,
        target_kind=TargetKind.ARTIFACT,
        worker_profile="reverse-static",
        network_access=False,
        artifact_kinds=_REVERSE_ARTIFACTS,
    ),
    ToolDefinition(
        "decompile_function",
        ToolRisk.PASSIVE,
        DecompileFunctionArguments,
        domain=SecurityDomain.REVERSE_ENGINEERING,
        target_kind=TargetKind.ARTIFACT,
        worker_profile="reverse-static",
        network_access=False,
        artifact_kinds=_REVERSE_ARTIFACTS,
    ),
    ToolDefinition(
        "observe_binary_runtime",
        ToolRisk.VALIDATION,
        ObserveBinaryRuntimeArguments,
        domain=SecurityDomain.REVERSE_ENGINEERING,
        target_kind=TargetKind.ARTIFACT,
        worker_profile="reverse-runtime",
        network_access=False,
        artifact_kinds=_REVERSE_ARTIFACTS,
    ),
    ToolDefinition(
        "export_report",
        ToolRisk.PASSIVE,
        ExportReportArguments,
        domain=None,
        target_kind=TargetKind.NONE,
        worker_profile="reporting",
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

        if definition.domain is not None and definition.domain not in engagement.domains:
            return PolicyDecision(
                False,
                DecisionCode.DOMAIN_NOT_AUTHORIZED,
                f"engagement does not authorize the {definition.domain.value} domain",
            )

        try:
            validated_arguments = definition.arguments_model.model_validate(
                dict(request.arguments)
            )
        except ValidationError as exc:
            first_error = exc.errors(include_url=False)[0]
            location = ".".join(str(part) for part in first_error["loc"]) or "arguments"
            return PolicyDecision(
                False,
                DecisionCode.INVALID_ARGUMENTS,
                f"invalid tool arguments at {location}: {first_error['msg']}",
            )

        target_decision = self._authorize_target(
            engagement=engagement,
            request=request,
            definition=definition,
            validated_arguments=validated_arguments,
        )
        if target_decision is not None:
            return target_decision

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
                or approval.request_fingerprint != request.fingerprint
            ):
                return PolicyDecision(
                    False,
                    DecisionCode.APPROVAL_INVALID,
                    "approval does not authorize this exact immutable tool request",
                    requires_approval=True,
                )

        return PolicyDecision(True, DecisionCode.ALLOW, "policy authorized the tool request")

    @staticmethod
    def _authorize_target(
        *,
        engagement: Engagement,
        request: ToolRequest,
        definition: ToolDefinition,
        validated_arguments: BaseModel,
    ) -> PolicyDecision | None:
        supplied_targets = sum(
            value is not None
            for value in (request.target_url, request.artifact_id, request.device_session_id)
        )

        if definition.target_kind is TargetKind.NONE:
            if supplied_targets:
                return PolicyDecision(
                    False,
                    DecisionCode.TARGET_KIND_MISMATCH,
                    "non-targeted tool requests must not include a target reference",
                )
            return None

        if supplied_targets > 1:
            return PolicyDecision(
                False,
                DecisionCode.TARGET_KIND_MISMATCH,
                "tool requests must contain exactly one target reference",
            )

        if definition.target_kind is TargetKind.URL:
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
            return None

        if definition.target_kind is TargetKind.ARTIFACT:
            if not request.artifact_id:
                return PolicyDecision(
                    False,
                    DecisionCode.ARTIFACT_REQUIRED,
                    "tool requires an explicitly registered artefact",
                )
            artifact = next(
                (
                    candidate
                    for candidate in engagement.artifacts
                    if candidate.artifact_id == request.artifact_id
                ),
                None,
            )
            if artifact is None:
                return PolicyDecision(
                    False,
                    DecisionCode.ARTIFACT_NOT_AUTHORIZED,
                    "artefact is not registered in this engagement",
                )
            if definition.artifact_kinds and artifact.kind not in definition.artifact_kinds:
                return PolicyDecision(
                    False,
                    DecisionCode.ARTIFACT_KIND_NOT_ALLOWED,
                    f"tool does not accept artefacts of type {artifact.kind.value}",
                )

            requested_platform = getattr(validated_arguments, "platform", None)
            artifact_platform = _mobile_platform_for_artifact(artifact.kind)
            if (
                requested_platform not in {None, "auto"}
                and artifact_platform is not None
                and requested_platform != artifact_platform.value
            ):
                return PolicyDecision(
                    False,
                    DecisionCode.INVALID_ARGUMENTS,
                    "requested mobile platform does not match the registered artefact",
                )
            return None

        if definition.target_kind is TargetKind.DEVICE_SESSION:
            if not request.device_session_id:
                return PolicyDecision(
                    False,
                    DecisionCode.DEVICE_SESSION_REQUIRED,
                    "tool requires an explicitly registered device session",
                )
            session = next(
                (
                    candidate
                    for candidate in engagement.device_sessions
                    if candidate.session_id == request.device_session_id
                ),
                None,
            )
            if session is None:
                return PolicyDecision(
                    False,
                    DecisionCode.DEVICE_SESSION_NOT_AUTHORIZED,
                    "device session is not registered in this engagement",
                )
            requested_platform = getattr(validated_arguments, "platform", None)
            if requested_platform is not None and requested_platform != session.platform.value:
                return PolicyDecision(
                    False,
                    DecisionCode.INVALID_ARGUMENTS,
                    "requested mobile platform does not match the device session",
                )
            return None

        return PolicyDecision(
            False,
            DecisionCode.TARGET_KIND_MISMATCH,
            "unsupported target kind",
        )


def _mobile_platform_for_artifact(kind: ArtifactKind) -> MobilePlatform | None:
    if kind in {ArtifactKind.ANDROID_APK, ArtifactKind.ANDROID_AAB}:
        return MobilePlatform.ANDROID
    if kind is ArtifactKind.IOS_IPA:
        return MobilePlatform.IOS
    return None


class TypedToolBroker:
    """Policy-check requests before a future isolated worker receives them.

    This implementation intentionally has no execute method. Worker dispatch is
    introduced only after durable audit, evidence, and isolation contracts exist.
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


__all__ = [
    "Approval",
    "ApprovalStatus",
    "ArtifactKind",
    "ArtifactScope",
    "DEFAULT_TOOL_DEFINITIONS",
    "DecisionCode",
    "DeviceSessionScope",
    "Engagement",
    "EngagementStatus",
    "FORBIDDEN_TOOL_NAMES",
    "MobilePlatform",
    "PolicyDecision",
    "PolicyEngine",
    "ScopeMatch",
    "ScopeRule",
    "SecurityDomain",
    "TargetKind",
    "ToolDefinition",
    "ToolRequest",
    "ToolRisk",
    "TypedToolBroker",
    "canonical_host",
    "canonical_path",
    "match_scope",
]
