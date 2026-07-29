"""Initial constrained tool catalogue.

No implementation in this module performs network or process execution. It only
defines the validated arguments and risk classification accepted by the policy
engine.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .domain import ToolDefinition, ToolRisk


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
    ToolDefinition(
        name="crawl_target",
        risk=ToolRisk.PASSIVE,
        arguments_model=CrawlTargetArguments,
    ),
    ToolDefinition(
        name="http_probe",
        risk=ToolRisk.PASSIVE,
        arguments_model=HttpProbeArguments,
    ),
    ToolDefinition(
        name="analyze_headers",
        risk=ToolRisk.PASSIVE,
        arguments_model=AnalyzeHeadersArguments,
    ),
    ToolDefinition(
        name="check_tls_config",
        risk=ToolRisk.PASSIVE,
        arguments_model=CheckTlsConfigArguments,
    ),
    ToolDefinition(
        name="run_passive_scan",
        risk=ToolRisk.PASSIVE,
        arguments_model=PassiveScanArguments,
    ),
    ToolDefinition(
        name="run_authenticated_safe_check",
        risk=ToolRisk.ACTIVE_SAFE,
        arguments_model=AuthenticatedSafeCheckArguments,
    ),
    ToolDefinition(
        name="verify_candidate_finding",
        risk=ToolRisk.VALIDATION,
        arguments_model=VerifyFindingArguments,
    ),
    ToolDefinition(
        name="export_report",
        risk=ToolRisk.PASSIVE,
        arguments_model=ExportReportArguments,
        requires_target=False,
        network_access=False,
    ),
)
