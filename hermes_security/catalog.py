"""Initial constrained multi-discipline security tool catalogue.

No implementation in this module performs network, device, or process execution.
It only defines validated arguments, target requirements, accepted artefact kinds,
and risk classifications consumed by the policy engine.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .domain import (
    ArtifactKind,
    SecurityDomain,
    TargetKind,
    ToolDefinition,
    ToolRisk,
)


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
    encodings: tuple[Literal["ascii", "utf16le", "utf16be"], ...] = ("ascii", "utf16le")


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
        name="crawl_target",
        risk=ToolRisk.PASSIVE,
        arguments_model=CrawlTargetArguments,
        domain=SecurityDomain.WEB,
        target_kind=TargetKind.URL,
    ),
    ToolDefinition(
        name="http_probe",
        risk=ToolRisk.PASSIVE,
        arguments_model=HttpProbeArguments,
        domain=SecurityDomain.WEB,
        target_kind=TargetKind.URL,
    ),
    ToolDefinition(
        name="analyze_headers",
        risk=ToolRisk.PASSIVE,
        arguments_model=AnalyzeHeadersArguments,
        domain=SecurityDomain.WEB,
        target_kind=TargetKind.URL,
    ),
    ToolDefinition(
        name="check_tls_config",
        risk=ToolRisk.PASSIVE,
        arguments_model=CheckTlsConfigArguments,
        domain=SecurityDomain.WEB,
        target_kind=TargetKind.URL,
    ),
    ToolDefinition(
        name="run_passive_scan",
        risk=ToolRisk.PASSIVE,
        arguments_model=PassiveScanArguments,
        domain=SecurityDomain.WEB,
        target_kind=TargetKind.URL,
    ),
    ToolDefinition(
        name="run_authenticated_safe_check",
        risk=ToolRisk.ACTIVE_SAFE,
        arguments_model=AuthenticatedSafeCheckArguments,
        domain=SecurityDomain.WEB,
        target_kind=TargetKind.URL,
    ),
    ToolDefinition(
        name="verify_candidate_finding",
        risk=ToolRisk.VALIDATION,
        arguments_model=VerifyFindingArguments,
        domain=SecurityDomain.WEB,
        target_kind=TargetKind.URL,
    ),
    ToolDefinition(
        name="inspect_mobile_manifest",
        risk=ToolRisk.PASSIVE,
        arguments_model=MobileStaticArguments,
        domain=SecurityDomain.MOBILE,
        target_kind=TargetKind.ARTIFACT,
        network_access=False,
        artifact_kinds=_MOBILE_PACKAGES,
    ),
    ToolDefinition(
        name="enumerate_mobile_permissions",
        risk=ToolRisk.PASSIVE,
        arguments_model=MobileStaticArguments,
        domain=SecurityDomain.MOBILE,
        target_kind=TargetKind.ARTIFACT,
        network_access=False,
        artifact_kinds=_MOBILE_PACKAGES,
    ),
    ToolDefinition(
        name="analyze_mobile_network_security",
        risk=ToolRisk.PASSIVE,
        arguments_model=MobileStaticArguments,
        domain=SecurityDomain.MOBILE,
        target_kind=TargetKind.ARTIFACT,
        network_access=False,
        artifact_kinds=_MOBILE_PACKAGES,
    ),
    ToolDefinition(
        name="extract_mobile_endpoints",
        risk=ToolRisk.PASSIVE,
        arguments_model=MobileEndpointArguments,
        domain=SecurityDomain.MOBILE,
        target_kind=TargetKind.ARTIFACT,
        network_access=False,
        artifact_kinds=_MOBILE_PACKAGES,
    ),
    ToolDefinition(
        name="observe_mobile_runtime",
        risk=ToolRisk.VALIDATION,
        arguments_model=ObserveMobileRuntimeArguments,
        domain=SecurityDomain.MOBILE,
        target_kind=TargetKind.DEVICE_SESSION,
    ),
    ToolDefinition(
        name="fingerprint_binary",
        risk=ToolRisk.PASSIVE,
        arguments_model=FingerprintBinaryArguments,
        domain=SecurityDomain.REVERSE_ENGINEERING,
        target_kind=TargetKind.ARTIFACT,
        network_access=False,
        artifact_kinds=_REVERSE_ARTIFACTS,
    ),
    ToolDefinition(
        name="extract_binary_strings",
        risk=ToolRisk.PASSIVE,
        arguments_model=ExtractBinaryStringsArguments,
        domain=SecurityDomain.REVERSE_ENGINEERING,
        target_kind=TargetKind.ARTIFACT,
        network_access=False,
        artifact_kinds=_REVERSE_ARTIFACTS,
    ),
    ToolDefinition(
        name="inspect_binary_imports",
        risk=ToolRisk.PASSIVE,
        arguments_model=InspectBinaryImportsArguments,
        domain=SecurityDomain.REVERSE_ENGINEERING,
        target_kind=TargetKind.ARTIFACT,
        network_access=False,
        artifact_kinds=_REVERSE_ARTIFACTS,
    ),
    ToolDefinition(
        name="analyze_control_flow",
        risk=ToolRisk.PASSIVE,
        arguments_model=AnalyzeControlFlowArguments,
        domain=SecurityDomain.REVERSE_ENGINEERING,
        target_kind=TargetKind.ARTIFACT,
        network_access=False,
        artifact_kinds=_REVERSE_ARTIFACTS,
    ),
    ToolDefinition(
        name="decompile_function",
        risk=ToolRisk.PASSIVE,
        arguments_model=DecompileFunctionArguments,
        domain=SecurityDomain.REVERSE_ENGINEERING,
        target_kind=TargetKind.ARTIFACT,
        network_access=False,
        artifact_kinds=_REVERSE_ARTIFACTS,
    ),
    ToolDefinition(
        name="observe_binary_runtime",
        risk=ToolRisk.VALIDATION,
        arguments_model=ObserveBinaryRuntimeArguments,
        domain=SecurityDomain.REVERSE_ENGINEERING,
        target_kind=TargetKind.ARTIFACT,
        network_access=False,
        artifact_kinds=_REVERSE_ARTIFACTS,
    ),
    ToolDefinition(
        name="export_report",
        risk=ToolRisk.PASSIVE,
        arguments_model=ExportReportArguments,
        domain=None,
        target_kind=TargetKind.NONE,
        network_access=False,
    ),
)
