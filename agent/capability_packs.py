"""Versioned capability-pack contracts for security assessment domains.

Capability packs declare which typed tools, target kinds, worker profiles,
evidence schemas, finding templates, and report sections belong to a domain.
Registration is fail-closed: unknown tools, mismatched domains, unsupported
target kinds, and unregistered worker profiles are rejected before enablement.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .security import (
    DEFAULT_TOOL_DEFINITIONS,
    Engagement,
    SecurityDomain,
    TargetKind,
    ToolDefinition,
)
from .security_jobs import DEFAULT_WORKER_PROFILES, WorkerProfile

_PACK_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
_SCHEMA_ID_RE = re.compile(r"^[a-z][a-z0-9_.:-]{2,127}$")
_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True, slots=True)
class AssessmentStep:
    step_id: str
    tool_name: str
    reason: str
    depends_on: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AssessmentPlan:
    pack_name: str
    pack_version: str
    steps: tuple[AssessmentStep, ...]


@dataclass(frozen=True, slots=True)
class VerificationResult:
    verified: bool
    reason: str
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ReportSection:
    section_id: str
    title: str
    content: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "content", MappingProxyType(dict(self.content)))


@dataclass(frozen=True, slots=True)
class CapabilityPackManifest:
    name: str
    version: str
    domains: frozenset[SecurityDomain]
    supported_target_kinds: frozenset[TargetKind]
    required_worker_profiles: frozenset[str]
    tool_names: tuple[str, ...]
    evidence_schema_ids: tuple[str, ...]
    finding_template_ids: tuple[str, ...]
    report_section_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not _PACK_NAME_RE.fullmatch(self.name):
            raise ValueError("capability pack name must use a constrained slug")
        if not _SEMVER_RE.fullmatch(self.version):
            raise ValueError("capability pack version must use semantic versioning")
        if not self.domains:
            raise ValueError("capability pack must declare at least one domain")
        if not self.supported_target_kinds:
            raise ValueError("capability pack must declare at least one target kind")
        if not self.required_worker_profiles:
            raise ValueError("capability pack must require at least one worker profile")
        if not self.tool_names:
            raise ValueError("capability pack must declare at least one typed tool")
        if len(set(self.tool_names)) != len(self.tool_names):
            raise ValueError("capability pack tool names must be unique")

        identifiers: Sequence[str] = (
            *self.evidence_schema_ids,
            *self.finding_template_ids,
            *self.report_section_ids,
        )
        if any(not _SCHEMA_ID_RE.fullmatch(identifier) for identifier in identifiers):
            raise ValueError("schema, template, and report IDs must use constrained slugs")


class CapabilityPack(ABC):
    """Interface implemented by independently versioned domain packs."""

    @property
    @abstractmethod
    def manifest(self) -> CapabilityPackManifest:
        """Return the immutable pack manifest."""

    @abstractmethod
    def validate_scope(
        self,
        engagement: Engagement,
        target_kind: TargetKind,
        target_reference: str | None,
    ) -> ScopeDecision:
        """Validate a target against the engagement's authoritative scope."""

    @abstractmethod
    def propose_plan(self, context: Mapping[str, Any]) -> AssessmentPlan:
        """Produce a typed-tool plan without executing tools."""

    @abstractmethod
    def verify_finding(
        self,
        finding: Mapping[str, Any],
        evidence: Sequence[Mapping[str, Any]],
    ) -> VerificationResult:
        """Independently verify a finding from evidence."""

    @abstractmethod
    def render_report_section(self, engagement: Engagement) -> ReportSection:
        """Render a report section from persisted validated data."""


class CapabilityPackRegistry:
    """Validate, version, register, and independently enable capability packs."""

    def __init__(
        self,
        definitions: tuple[ToolDefinition, ...] = DEFAULT_TOOL_DEFINITIONS,
        worker_profiles: Mapping[str, WorkerProfile] = DEFAULT_WORKER_PROFILES,
    ) -> None:
        self._definitions = {definition.name: definition for definition in definitions}
        if len(self._definitions) != len(definitions):
            raise ValueError("tool definitions must have unique names")
        self._worker_profiles = MappingProxyType(dict(worker_profiles))
        self._manifests: dict[tuple[str, str], CapabilityPackManifest] = {}
        self._enabled: set[tuple[str, str]] = set()

    def register_manifest(self, manifest: CapabilityPackManifest) -> None:
        key = (manifest.name, manifest.version)
        if key in self._manifests:
            raise ValueError(f"capability pack {manifest.name}@{manifest.version} is registered")

        for profile_name in manifest.required_worker_profiles:
            if profile_name not in self._worker_profiles:
                raise ValueError(
                    f"capability pack references unknown worker profile {profile_name!r}"
                )

        for tool_name in manifest.tool_names:
            try:
                definition = self._definitions[tool_name]
            except KeyError as exc:
                raise ValueError(
                    f"capability pack references unknown tool {tool_name!r}"
                ) from exc
            if definition.domain is not None and definition.domain not in manifest.domains:
                raise ValueError(
                    f"tool {tool_name!r} belongs to domain {definition.domain.value}, "
                    f"outside pack {manifest.name!r}"
                )
            if definition.target_kind not in manifest.supported_target_kinds:
                raise ValueError(
                    f"tool {tool_name!r} requires unsupported target kind "
                    f"{definition.target_kind.value}"
                )
            if definition.worker_profile not in manifest.required_worker_profiles:
                raise ValueError(
                    f"tool {tool_name!r} requires undeclared worker profile "
                    f"{definition.worker_profile!r}"
                )

        self._manifests[key] = manifest

    def enable(self, name: str, version: str) -> None:
        key = (name, version)
        if key not in self._manifests:
            raise KeyError(f"capability pack {name}@{version} is not registered")
        self._enabled.add(key)

    def disable(self, name: str, version: str) -> None:
        self._enabled.discard((name, version))

    def resolve(self, name: str, version: str) -> CapabilityPackManifest:
        try:
            return self._manifests[(name, version)]
        except KeyError as exc:
            raise KeyError(f"capability pack {name}@{version} is not registered") from exc

    def is_enabled(self, name: str, version: str) -> bool:
        return (name, version) in self._enabled

    @property
    def registered(self) -> tuple[CapabilityPackManifest, ...]:
        return tuple(self._manifests.values())

    @property
    def enabled(self) -> tuple[CapabilityPackManifest, ...]:
        return tuple(self._manifests[key] for key in sorted(self._enabled))


WEB_CAPABILITY_PACK = CapabilityPackManifest(
    name="web-security",
    version="0.1.0",
    domains=frozenset({SecurityDomain.WEB}),
    supported_target_kinds=frozenset({TargetKind.URL}),
    required_worker_profiles=frozenset(
        {"web-passive", "web-active-safe", "web-validation"}
    ),
    tool_names=(
        "crawl_target",
        "http_probe",
        "analyze_headers",
        "check_tls_config",
        "run_passive_scan",
        "run_authenticated_safe_check",
        "verify_candidate_finding",
    ),
    evidence_schema_ids=("evidence.http_exchange.v1", "evidence.web_observation.v1"),
    finding_template_ids=("finding.web.v1",),
    report_section_ids=("report.web.v1",),
)

MOBILE_CAPABILITY_PACK = CapabilityPackManifest(
    name="mobile-security",
    version="0.1.0",
    domains=frozenset({SecurityDomain.MOBILE}),
    supported_target_kinds=frozenset({TargetKind.ARTIFACT, TargetKind.DEVICE_SESSION}),
    required_worker_profiles=frozenset({"mobile-static", "mobile-runtime"}),
    tool_names=(
        "inspect_mobile_manifest",
        "enumerate_mobile_permissions",
        "analyze_mobile_network_security",
        "extract_mobile_endpoints",
        "observe_mobile_runtime",
    ),
    evidence_schema_ids=("evidence.mobile_static.v1", "evidence.mobile_runtime.v1"),
    finding_template_ids=("finding.mobile.v1",),
    report_section_ids=("report.mobile.v1",),
)

REVERSE_ENGINEERING_CAPABILITY_PACK = CapabilityPackManifest(
    name="reverse-engineering",
    version="0.1.0",
    domains=frozenset({SecurityDomain.REVERSE_ENGINEERING}),
    supported_target_kinds=frozenset({TargetKind.ARTIFACT}),
    required_worker_profiles=frozenset({"reverse-static", "reverse-runtime"}),
    tool_names=(
        "fingerprint_binary",
        "extract_binary_strings",
        "inspect_binary_imports",
        "analyze_control_flow",
        "decompile_function",
        "observe_binary_runtime",
    ),
    evidence_schema_ids=("evidence.binary_static.v1", "evidence.binary_runtime.v1"),
    finding_template_ids=("finding.reverse_engineering.v1",),
    report_section_ids=("report.reverse_engineering.v1",),
)

DEFAULT_CAPABILITY_PACKS = (
    WEB_CAPABILITY_PACK,
    MOBILE_CAPABILITY_PACK,
    REVERSE_ENGINEERING_CAPABILITY_PACK,
)


def build_default_capability_registry() -> CapabilityPackRegistry:
    registry = CapabilityPackRegistry()
    for manifest in DEFAULT_CAPABILITY_PACKS:
        registry.register_manifest(manifest)
    return registry


__all__ = [
    "AssessmentPlan",
    "AssessmentStep",
    "CapabilityPack",
    "CapabilityPackManifest",
    "CapabilityPackRegistry",
    "DEFAULT_CAPABILITY_PACKS",
    "MOBILE_CAPABILITY_PACK",
    "REVERSE_ENGINEERING_CAPABILITY_PACK",
    "ReportSection",
    "ScopeDecision",
    "VerificationResult",
    "WEB_CAPABILITY_PACK",
    "build_default_capability_registry",
]
