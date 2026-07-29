"""Fail-closed contracts for isolated security execution workers.

This module does not start containers, emulators, virtual machines, processes, or
network connections. It converts an already-authorized typed tool request into
an immutable job envelope that a future worker control plane can validate and
claim.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping

from pydantic import ValidationError

from .security import (
    Approval,
    ApprovalStatus,
    Engagement,
    PolicyDecision,
    SecurityDomain,
    TargetKind,
    ToolDefinition,
    ToolRequest,
    ToolRisk,
)


_PROFILE_RE = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")
_LABEL_RE = re.compile(r"^[a-z][a-z0-9_.:-]{1,95}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class IsolationClass(StrEnum):
    """Worker isolation boundary. Host execution is intentionally absent."""

    CONTAINER = "container"
    EMULATOR = "emulator"
    MICROVM = "microvm"


class NetworkPolicy(StrEnum):
    """Network access granted by the worker supervisor."""

    DENY_ALL = "deny_all"
    ENGAGEMENT_ALLOWLIST = "engagement_allowlist"
    ENGAGEMENT_PROXY = "engagement_proxy"


class WorkerTrustLevel(StrEnum):
    STANDARD = "standard"
    SENSITIVE = "sensitive"
    DYNAMIC = "dynamic"


@dataclass(frozen=True, slots=True)
class WorkerProfile:
    """Immutable supervisor-enforced worker constraints."""

    name: str
    isolation_class: IsolationClass
    trust_level: WorkerTrustLevel
    labels: frozenset[str]
    network_policy: NetworkPolicy
    max_cpu_cores: float
    max_memory_mb: int
    max_disk_mb: int
    max_runtime_seconds: int
    read_only_rootfs: bool = True
    ephemeral_workspace: bool = True
    allow_privileged: bool = False
    allow_docker_socket: bool = False

    def __post_init__(self) -> None:
        if not _PROFILE_RE.fullmatch(self.name):
            raise ValueError("worker profile name must use a constrained slug")
        if not self.labels:
            raise ValueError("worker profile requires at least one capability label")
        if any(not _LABEL_RE.fullmatch(label) for label in self.labels):
            raise ValueError("worker labels must use constrained slugs")
        if not 0.1 <= self.max_cpu_cores <= 32:
            raise ValueError("max_cpu_cores must be between 0.1 and 32")
        if not 128 <= self.max_memory_mb <= 131_072:
            raise ValueError("max_memory_mb must be between 128 and 131072")
        if not 64 <= self.max_disk_mb <= 1_048_576:
            raise ValueError("max_disk_mb must be between 64 and 1048576")
        if not 1 <= self.max_runtime_seconds <= 86_400:
            raise ValueError("max_runtime_seconds must be between 1 and 86400")
        if self.allow_privileged:
            raise ValueError("privileged workers are prohibited")
        if self.allow_docker_socket:
            raise ValueError("mounting the Docker socket into workers is prohibited")
        if not self.read_only_rootfs:
            raise ValueError("worker root filesystems must be read-only")
        if not self.ephemeral_workspace:
            raise ValueError("worker workspaces must be ephemeral")
        if self.trust_level is WorkerTrustLevel.DYNAMIC and self.isolation_class not in {
            IsolationClass.EMULATOR,
            IsolationClass.MICROVM,
        }:
            raise ValueError("dynamic workloads require an emulator or microVM")


DEFAULT_WORKER_PROFILES = (
    WorkerProfile(
        name="web-passive",
        isolation_class=IsolationClass.CONTAINER,
        trust_level=WorkerTrustLevel.STANDARD,
        labels=frozenset({"domain:web", "capability:http", "risk:passive"}),
        network_policy=NetworkPolicy.ENGAGEMENT_ALLOWLIST,
        max_cpu_cores=1.0,
        max_memory_mb=1024,
        max_disk_mb=2048,
        max_runtime_seconds=300,
    ),
    WorkerProfile(
        name="web-active-safe",
        isolation_class=IsolationClass.CONTAINER,
        trust_level=WorkerTrustLevel.SENSITIVE,
        labels=frozenset({"domain:web", "capability:http", "risk:active-low"}),
        network_policy=NetworkPolicy.ENGAGEMENT_ALLOWLIST,
        max_cpu_cores=2.0,
        max_memory_mb=2048,
        max_disk_mb=4096,
        max_runtime_seconds=300,
    ),
    WorkerProfile(
        name="web-validation",
        isolation_class=IsolationClass.MICROVM,
        trust_level=WorkerTrustLevel.DYNAMIC,
        labels=frozenset({"domain:web", "capability:http", "risk:validation"}),
        network_policy=NetworkPolicy.ENGAGEMENT_ALLOWLIST,
        max_cpu_cores=2.0,
        max_memory_mb=4096,
        max_disk_mb=8192,
        max_runtime_seconds=300,
    ),
    WorkerProfile(
        name="mobile-static",
        isolation_class=IsolationClass.CONTAINER,
        trust_level=WorkerTrustLevel.STANDARD,
        labels=frozenset({"domain:mobile", "capability:static", "risk:passive"}),
        network_policy=NetworkPolicy.DENY_ALL,
        max_cpu_cores=2.0,
        max_memory_mb=4096,
        max_disk_mb=8192,
        max_runtime_seconds=900,
    ),
    WorkerProfile(
        name="mobile-runtime",
        isolation_class=IsolationClass.EMULATOR,
        trust_level=WorkerTrustLevel.DYNAMIC,
        labels=frozenset({"domain:mobile", "capability:runtime", "risk:validation"}),
        network_policy=NetworkPolicy.ENGAGEMENT_PROXY,
        max_cpu_cores=4.0,
        max_memory_mb=8192,
        max_disk_mb=16_384,
        max_runtime_seconds=900,
    ),
    WorkerProfile(
        name="reverse-static",
        isolation_class=IsolationClass.CONTAINER,
        trust_level=WorkerTrustLevel.SENSITIVE,
        labels=frozenset(
            {"domain:reverse-engineering", "capability:static", "risk:passive"}
        ),
        network_policy=NetworkPolicy.DENY_ALL,
        max_cpu_cores=4.0,
        max_memory_mb=8192,
        max_disk_mb=16_384,
        max_runtime_seconds=1800,
    ),
    WorkerProfile(
        name="reverse-runtime",
        isolation_class=IsolationClass.MICROVM,
        trust_level=WorkerTrustLevel.DYNAMIC,
        labels=frozenset(
            {"domain:reverse-engineering", "capability:runtime", "risk:validation"}
        ),
        network_policy=NetworkPolicy.DENY_ALL,
        max_cpu_cores=4.0,
        max_memory_mb=8192,
        max_disk_mb=16_384,
        max_runtime_seconds=600,
    ),
    WorkerProfile(
        name="reporting",
        isolation_class=IsolationClass.CONTAINER,
        trust_level=WorkerTrustLevel.STANDARD,
        labels=frozenset({"domain:reporting", "capability:render", "risk:read-only"}),
        network_policy=NetworkPolicy.DENY_ALL,
        max_cpu_cores=1.0,
        max_memory_mb=1024,
        max_disk_mb=2048,
        max_runtime_seconds=120,
    ),
)


class WorkerProfileRegistry:
    """Registry of supervisor-approved worker profiles."""

    def __init__(self, profiles: tuple[WorkerProfile, ...] = DEFAULT_WORKER_PROFILES) -> None:
        self._profiles: dict[str, WorkerProfile] = {}
        for profile in profiles:
            self.register(profile)

    def register(self, profile: WorkerProfile) -> None:
        if profile.name in self._profiles:
            raise ValueError(f"worker profile {profile.name!r} is already registered")
        self._profiles[profile.name] = profile

    def resolve(self, name: str) -> WorkerProfile:
        try:
            return self._profiles[name]
        except KeyError as exc:
            raise KeyError(f"worker profile {name!r} is not registered") from exc

    @property
    def profiles(self) -> tuple[WorkerProfile, ...]:
        return tuple(self._profiles.values())


@dataclass(frozen=True, slots=True)
class WorkerJobEnvelope:
    """Immutable, content-addressed handoff from policy to a worker supervisor."""

    job_id: str
    engagement_id: str
    request_id: str
    request_fingerprint: str
    tool_name: str
    domain: SecurityDomain | None
    target_kind: TargetKind
    target_reference: str | None
    worker_profile: str
    isolation_class: IsolationClass
    network_policy: NetworkPolicy
    validated_arguments: Mapping[str, Any] = field(default_factory=dict)
    approval_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    deadline_at: datetime | None = None
    max_attempts: int = 1
    evidence_required: bool = True
    schema_version: str = "1"

    def __post_init__(self) -> None:
        for name, value in (
            ("job_id", self.job_id),
            ("engagement_id", self.engagement_id),
            ("request_id", self.request_id),
        ):
            if not _ID_RE.fullmatch(value):
                raise ValueError(f"{name} must use a constrained identifier")
        if not _SHA256_RE.fullmatch(self.request_fingerprint):
            raise ValueError("request_fingerprint must be a lowercase SHA-256 digest")
        if not _PROFILE_RE.fullmatch(self.worker_profile):
            raise ValueError("worker_profile must use a constrained slug")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        deadline = self.deadline_at
        if deadline is None:
            raise ValueError("deadline_at is required")
        if deadline.tzinfo is None or deadline.utcoffset() is None:
            raise ValueError("deadline_at must be timezone-aware")
        if deadline <= self.created_at:
            raise ValueError("deadline_at must be after created_at")
        if not 1 <= self.max_attempts <= 2:
            raise ValueError("max_attempts must be one or two")

        arguments = dict(self.validated_arguments)
        try:
            json.dumps(arguments, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("validated_arguments must be JSON serializable") from exc
        object.__setattr__(self, "validated_arguments", MappingProxyType(arguments))

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "created_at": self.created_at.astimezone(UTC).isoformat(),
            "deadline_at": self.deadline_at.astimezone(UTC).isoformat()
            if self.deadline_at is not None
            else None,
            "domain": self.domain.value if self.domain is not None else None,
            "engagement_id": self.engagement_id,
            "evidence_required": self.evidence_required,
            "isolation_class": self.isolation_class.value,
            "job_id": self.job_id,
            "max_attempts": self.max_attempts,
            "network_policy": self.network_policy.value,
            "request_fingerprint": self.request_fingerprint,
            "request_id": self.request_id,
            "schema_version": self.schema_version,
            "target_kind": self.target_kind.value,
            "target_reference": self.target_reference,
            "tool_name": self.tool_name,
            "validated_arguments": dict(self.validated_arguments),
            "worker_profile": self.worker_profile,
        }

    @property
    def envelope_sha256(self) -> str:
        encoded = json.dumps(
            self.canonical_payload(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class AuthorizedJobFactory:
    """Build worker envelopes only from allowed policy decisions."""

    def __init__(
        self,
        definitions: tuple[ToolDefinition, ...],
        profiles: WorkerProfileRegistry | None = None,
    ) -> None:
        self._definitions = {definition.name: definition for definition in definitions}
        if len(self._definitions) != len(definitions):
            raise ValueError("tool definitions must have unique names")
        self._profiles = profiles or WorkerProfileRegistry()

    def build(
        self,
        *,
        job_id: str,
        engagement: Engagement,
        request: ToolRequest,
        decision: PolicyDecision,
        approval: Approval | None = None,
        created_at: datetime | None = None,
    ) -> WorkerJobEnvelope:
        if not decision.allowed:
            raise ValueError("a denied policy decision cannot produce a worker job")
        if request.engagement_id != engagement.engagement_id:
            raise ValueError("request and engagement identifiers do not match")

        try:
            definition = self._definitions[request.tool_name]
        except KeyError as exc:
            raise KeyError(f"tool definition {request.tool_name!r} is not registered") from exc

        try:
            validated = definition.arguments_model.model_validate(dict(request.arguments))
        except ValidationError as exc:
            raise ValueError("tool arguments no longer satisfy the registered schema") from exc

        profile = self._profiles.resolve(definition.worker_profile)
        self._validate_profile_compatibility(definition, profile)
        self._validate_approval(definition, engagement, request, approval)

        timestamp = created_at or datetime.now(UTC)
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")

        target_reference = {
            TargetKind.URL: request.target_url,
            TargetKind.ARTIFACT: request.artifact_id,
            TargetKind.DEVICE_SESSION: request.device_session_id,
            TargetKind.NONE: None,
        }[definition.target_kind]

        return WorkerJobEnvelope(
            job_id=job_id,
            engagement_id=engagement.engagement_id,
            request_id=request.request_id,
            request_fingerprint=request.fingerprint,
            tool_name=definition.name,
            domain=definition.domain,
            target_kind=definition.target_kind,
            target_reference=target_reference,
            worker_profile=profile.name,
            isolation_class=profile.isolation_class,
            network_policy=profile.network_policy,
            validated_arguments=validated.model_dump(mode="json"),
            approval_id=approval.approval_id if approval is not None else None,
            created_at=timestamp,
            deadline_at=timestamp + timedelta(seconds=profile.max_runtime_seconds),
            max_attempts=1,
            evidence_required=True,
        )

    @staticmethod
    def _validate_profile_compatibility(
        definition: ToolDefinition,
        profile: WorkerProfile,
    ) -> None:
        if definition.network_access and profile.network_policy is NetworkPolicy.DENY_ALL:
            raise ValueError("networked tool is assigned to a deny-all worker profile")
        if not definition.network_access and profile.network_policy is not NetworkPolicy.DENY_ALL:
            raise ValueError("offline tool is assigned to a network-enabled worker profile")
        if definition.risk is ToolRisk.VALIDATION and profile.isolation_class not in {
            IsolationClass.EMULATOR,
            IsolationClass.MICROVM,
        }:
            raise ValueError("validation tools require emulator or microVM isolation")

    @staticmethod
    def _validate_approval(
        definition: ToolDefinition,
        engagement: Engagement,
        request: ToolRequest,
        approval: Approval | None,
    ) -> None:
        if definition.risk is not ToolRisk.VALIDATION:
            return
        if approval is None:
            raise ValueError("validation worker jobs require an approval record")
        if (
            approval.status is not ApprovalStatus.APPROVED
            or approval.engagement_id != engagement.engagement_id
            or approval.request_id != request.request_id
            or approval.tool_name != request.tool_name
            or approval.request_fingerprint != request.fingerprint
        ):
            raise ValueError("approval does not bind to the exact worker request")


__all__ = [
    "AuthorizedJobFactory",
    "DEFAULT_WORKER_PROFILES",
    "IsolationClass",
    "NetworkPolicy",
    "WorkerJobEnvelope",
    "WorkerProfile",
    "WorkerProfileRegistry",
    "WorkerTrustLevel",
]
