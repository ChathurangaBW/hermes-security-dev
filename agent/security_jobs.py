"""Immutable worker, evidence, and audit contracts for security jobs.

This module does not dispatch or execute work. It converts an authorised typed
request into a fixed worker job envelope whose isolation profile, network policy,
resource limits, target, approval, and evidence requirements cannot be selected
or altered by the model.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping

from .security import (
    Approval,
    Engagement,
    SecurityDomain,
    TargetKind,
    ToolDefinition,
    ToolRequest,
    ToolRisk,
    TypedToolBroker,
)


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_MEDIA_TYPE_RE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")


class IsolationKind(StrEnum):
    CONTAINER = "container"
    EMULATOR = "emulator"
    MICROVM = "microvm"


class NetworkPolicy(StrEnum):
    DISABLED = "disabled"
    SCOPE_ALLOWLIST = "scope_allowlist"
    ENGAGEMENT_PROXY = "engagement_proxy"


class EvidenceKind(StrEnum):
    HTTP_TRANSCRIPT = "http_transcript"
    ARTIFACT_ANALYSIS = "artifact_analysis"
    RUNTIME_TRACE = "runtime_trace"
    PROCESS_METADATA = "process_metadata"
    SCREENSHOT = "screenshot"
    REPORT_OUTPUT = "report_output"
    TOOL_LOG = "tool_log"


class AuditEventType(StrEnum):
    JOB_AUTHORIZED = "job_authorized"
    JOB_DISPATCHED = "job_dispatched"
    JOB_COMPLETED = "job_completed"
    JOB_FAILED = "job_failed"
    EVIDENCE_RECORDED = "evidence_recorded"


@dataclass(frozen=True, slots=True)
class WorkerProfile:
    name: str
    isolation: IsolationKind
    domains: frozenset[SecurityDomain]
    target_kinds: frozenset[TargetKind]
    network_policy: NetworkPolicy
    max_duration_seconds: int
    max_cpu_cores: float
    max_memory_mb: int
    read_only_rootfs: bool = True
    privileged: bool = False

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(self.name):
            raise ValueError("worker profile name is invalid")
        if not self.target_kinds:
            raise ValueError("worker profile must accept at least one target kind")
        if not 1 <= self.max_duration_seconds <= 3_600:
            raise ValueError("worker duration must be between 1 and 3600 seconds")
        if not 0.1 <= self.max_cpu_cores <= 16:
            raise ValueError("worker CPU limit must be between 0.1 and 16 cores")
        if not 64 <= self.max_memory_mb <= 65_536:
            raise ValueError("worker memory limit must be between 64 and 65536 MB")
        if self.privileged:
            raise ValueError("security worker profiles must never be privileged")


@dataclass(frozen=True, slots=True)
class EvidenceRequirement:
    kind: EvidenceKind
    required: bool
    max_bytes: int

    def __post_init__(self) -> None:
        if not 1 <= self.max_bytes <= 1_073_741_824:
            raise ValueError("evidence max_bytes must be between 1 byte and 1 GiB")


DEFAULT_WORKER_PROFILES: Mapping[str, WorkerProfile] = MappingProxyType(
    {
        "web-passive": WorkerProfile(
            name="web-passive",
            isolation=IsolationKind.CONTAINER,
            domains=frozenset({SecurityDomain.WEB}),
            target_kinds=frozenset({TargetKind.URL}),
            network_policy=NetworkPolicy.SCOPE_ALLOWLIST,
            max_duration_seconds=300,
            max_cpu_cores=1.0,
            max_memory_mb=512,
        ),
        "web-active-safe": WorkerProfile(
            name="web-active-safe",
            isolation=IsolationKind.CONTAINER,
            domains=frozenset({SecurityDomain.WEB}),
            target_kinds=frozenset({TargetKind.URL}),
            network_policy=NetworkPolicy.SCOPE_ALLOWLIST,
            max_duration_seconds=180,
            max_cpu_cores=1.0,
            max_memory_mb=768,
        ),
        "web-validation": WorkerProfile(
            name="web-validation",
            isolation=IsolationKind.MICROVM,
            domains=frozenset({SecurityDomain.WEB}),
            target_kinds=frozenset({TargetKind.URL}),
            network_policy=NetworkPolicy.SCOPE_ALLOWLIST,
            max_duration_seconds=120,
            max_cpu_cores=1.0,
            max_memory_mb=1_024,
        ),
        "mobile-static": WorkerProfile(
            name="mobile-static",
            isolation=IsolationKind.CONTAINER,
            domains=frozenset({SecurityDomain.MOBILE}),
            target_kinds=frozenset({TargetKind.ARTIFACT}),
            network_policy=NetworkPolicy.DISABLED,
            max_duration_seconds=600,
            max_cpu_cores=2.0,
            max_memory_mb=2_048,
        ),
        "mobile-runtime": WorkerProfile(
            name="mobile-runtime",
            isolation=IsolationKind.EMULATOR,
            domains=frozenset({SecurityDomain.MOBILE}),
            target_kinds=frozenset({TargetKind.DEVICE_SESSION}),
            network_policy=NetworkPolicy.ENGAGEMENT_PROXY,
            max_duration_seconds=120,
            max_cpu_cores=2.0,
            max_memory_mb=4_096,
        ),
        "reverse-static": WorkerProfile(
            name="reverse-static",
            isolation=IsolationKind.CONTAINER,
            domains=frozenset({SecurityDomain.REVERSE_ENGINEERING}),
            target_kinds=frozenset({TargetKind.ARTIFACT}),
            network_policy=NetworkPolicy.DISABLED,
            max_duration_seconds=900,
            max_cpu_cores=2.0,
            max_memory_mb=4_096,
        ),
        "reverse-runtime": WorkerProfile(
            name="reverse-runtime",
            isolation=IsolationKind.MICROVM,
            domains=frozenset({SecurityDomain.REVERSE_ENGINEERING}),
            target_kinds=frozenset({TargetKind.ARTIFACT}),
            network_policy=NetworkPolicy.DISABLED,
            max_duration_seconds=120,
            max_cpu_cores=2.0,
            max_memory_mb=4_096,
        ),
        "reporting": WorkerProfile(
            name="reporting",
            isolation=IsolationKind.CONTAINER,
            domains=frozenset(),
            target_kinds=frozenset({TargetKind.NONE}),
            network_policy=NetworkPolicy.DISABLED,
            max_duration_seconds=120,
            max_cpu_cores=1.0,
            max_memory_mb=512,
        ),
    }
)


DEFAULT_EVIDENCE_REQUIREMENTS: Mapping[str, tuple[EvidenceRequirement, ...]] = (
    MappingProxyType(
        {
            "web-passive": (
                EvidenceRequirement(EvidenceKind.HTTP_TRANSCRIPT, True, 50_000_000),
                EvidenceRequirement(EvidenceKind.TOOL_LOG, True, 10_000_000),
            ),
            "web-active-safe": (
                EvidenceRequirement(EvidenceKind.HTTP_TRANSCRIPT, True, 50_000_000),
                EvidenceRequirement(EvidenceKind.TOOL_LOG, True, 10_000_000),
            ),
            "web-validation": (
                EvidenceRequirement(EvidenceKind.HTTP_TRANSCRIPT, True, 50_000_000),
                EvidenceRequirement(EvidenceKind.SCREENSHOT, False, 25_000_000),
                EvidenceRequirement(EvidenceKind.TOOL_LOG, True, 10_000_000),
            ),
            "mobile-static": (
                EvidenceRequirement(EvidenceKind.ARTIFACT_ANALYSIS, True, 100_000_000),
                EvidenceRequirement(EvidenceKind.TOOL_LOG, True, 10_000_000),
            ),
            "mobile-runtime": (
                EvidenceRequirement(EvidenceKind.RUNTIME_TRACE, True, 250_000_000),
                EvidenceRequirement(EvidenceKind.SCREENSHOT, False, 100_000_000),
                EvidenceRequirement(EvidenceKind.TOOL_LOG, True, 25_000_000),
            ),
            "reverse-static": (
                EvidenceRequirement(EvidenceKind.ARTIFACT_ANALYSIS, True, 250_000_000),
                EvidenceRequirement(EvidenceKind.TOOL_LOG, True, 25_000_000),
            ),
            "reverse-runtime": (
                EvidenceRequirement(EvidenceKind.RUNTIME_TRACE, True, 500_000_000),
                EvidenceRequirement(EvidenceKind.PROCESS_METADATA, True, 50_000_000),
                EvidenceRequirement(EvidenceKind.TOOL_LOG, True, 25_000_000),
            ),
            "reporting": (
                EvidenceRequirement(EvidenceKind.REPORT_OUTPUT, True, 100_000_000),
                EvidenceRequirement(EvidenceKind.TOOL_LOG, True, 10_000_000),
            ),
        }
    )
)


@dataclass(frozen=True, slots=True)
class WorkerJobEnvelope:
    job_id: str
    engagement_id: str
    policy_decision_id: str
    request_id: str
    request_fingerprint: str
    tool_name: str
    security_domain: SecurityDomain | None
    worker_profile: str
    isolation: IsolationKind
    network_policy: NetworkPolicy
    target_kind: TargetKind
    target_url: str | None
    artifact_id: str | None
    device_session_id: str | None
    arguments: Mapping[str, Any]
    approval_id: str | None
    max_duration_seconds: int
    max_cpu_cores: float
    max_memory_mb: int
    read_only_rootfs: bool
    privileged: bool
    evidence_requirements: tuple[EvidenceRequirement, ...]
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        for field_name in ("job_id", "engagement_id", "policy_decision_id", "request_id"):
            if not _ID_RE.fullmatch(getattr(self, field_name)):
                raise ValueError(f"{field_name} is invalid")
        if not _SHA256_RE.fullmatch(self.request_fingerprint):
            raise ValueError("request_fingerprint must be a SHA-256 hex digest")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        if self.privileged:
            raise ValueError("worker jobs must never be privileged")

        arguments = dict(self.arguments)
        try:
            json.dumps(arguments, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError("worker arguments must be JSON serializable") from exc
        object.__setattr__(self, "arguments", MappingProxyType(arguments))
        object.__setattr__(self, "request_fingerprint", self.request_fingerprint.lower())

        supplied_targets = sum(
            value is not None
            for value in (self.target_url, self.artifact_id, self.device_session_id)
        )
        if self.target_kind is TargetKind.NONE and supplied_targets:
            raise ValueError("non-targeted jobs must not contain a target")
        if self.target_kind is not TargetKind.NONE and supplied_targets != 1:
            raise ValueError("targeted jobs must contain exactly one target")

    @property
    def job_fingerprint(self) -> str:
        payload = {
            "approval_id": self.approval_id,
            "arguments": dict(self.arguments),
            "artifact_id": self.artifact_id,
            "device_session_id": self.device_session_id,
            "engagement_id": self.engagement_id,
            "evidence_requirements": [
                {
                    "kind": requirement.kind.value,
                    "max_bytes": requirement.max_bytes,
                    "required": requirement.required,
                }
                for requirement in self.evidence_requirements
            ],
            "isolation": self.isolation.value,
            "job_id": self.job_id,
            "max_cpu_cores": self.max_cpu_cores,
            "max_duration_seconds": self.max_duration_seconds,
            "max_memory_mb": self.max_memory_mb,
            "network_policy": self.network_policy.value,
            "policy_decision_id": self.policy_decision_id,
            "privileged": self.privileged,
            "read_only_rootfs": self.read_only_rootfs,
            "request_fingerprint": self.request_fingerprint,
            "request_id": self.request_id,
            "security_domain": self.security_domain.value if self.security_domain else None,
            "target_kind": self.target_kind.value,
            "target_url": self.target_url,
            "tool_name": self.tool_name,
            "worker_profile": self.worker_profile,
        }
        return _hash_json(payload)


@dataclass(frozen=True, slots=True)
class EvidenceArtifact:
    evidence_id: str
    job_id: str
    kind: EvidenceKind
    sha256: str
    media_type: str
    size_bytes: int
    object_key: str
    captured_at: datetime

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(self.evidence_id) or not _ID_RE.fullmatch(self.job_id):
            raise ValueError("evidence_id and job_id must be valid identifiers")
        if not _SHA256_RE.fullmatch(self.sha256):
            raise ValueError("evidence sha256 must be a SHA-256 hex digest")
        if not _MEDIA_TYPE_RE.fullmatch(self.media_type.lower()):
            raise ValueError("media_type is invalid")
        if not 0 <= self.size_bytes <= 1_073_741_824:
            raise ValueError("evidence size must be between 0 bytes and 1 GiB")
        if not self.object_key.strip() or self.object_key.startswith("/") or ".." in self.object_key:
            raise ValueError("object_key must be a relative traversal-free key")
        if self.captured_at.tzinfo is None:
            raise ValueError("captured_at must be timezone-aware")
        object.__setattr__(self, "sha256", self.sha256.lower())
        object.__setattr__(self, "media_type", self.media_type.lower())


@dataclass(frozen=True, slots=True)
class EvidenceManifest:
    manifest_id: str
    job_id: str
    job_fingerprint: str
    artifacts: tuple[EvidenceArtifact, ...]
    sealed_at: datetime

    def __post_init__(self) -> None:
        if not _ID_RE.fullmatch(self.manifest_id) or not _ID_RE.fullmatch(self.job_id):
            raise ValueError("manifest_id and job_id must be valid identifiers")
        if not _SHA256_RE.fullmatch(self.job_fingerprint):
            raise ValueError("job_fingerprint must be a SHA-256 hex digest")
        if self.sealed_at.tzinfo is None:
            raise ValueError("sealed_at must be timezone-aware")
        if any(artifact.job_id != self.job_id for artifact in self.artifacts):
            raise ValueError("all evidence artifacts must belong to the manifest job")
        if len({artifact.evidence_id for artifact in self.artifacts}) != len(self.artifacts):
            raise ValueError("evidence IDs must be unique within a manifest")
        object.__setattr__(self, "job_fingerprint", self.job_fingerprint.lower())

    @property
    def manifest_fingerprint(self) -> str:
        payload = {
            "artifacts": [
                {
                    "captured_at": artifact.captured_at.isoformat(),
                    "evidence_id": artifact.evidence_id,
                    "job_id": artifact.job_id,
                    "kind": artifact.kind.value,
                    "media_type": artifact.media_type,
                    "object_key": artifact.object_key,
                    "sha256": artifact.sha256,
                    "size_bytes": artifact.size_bytes,
                }
                for artifact in self.artifacts
            ],
            "job_fingerprint": self.job_fingerprint,
            "job_id": self.job_id,
            "manifest_id": self.manifest_id,
            "sealed_at": self.sealed_at.isoformat(),
        }
        return _hash_json(payload)


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_id: str
    engagement_id: str
    job_id: str
    event_type: AuditEventType
    actor_id: str
    details: Mapping[str, Any]
    occurred_at: datetime
    previous_event_hash: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("event_id", "engagement_id", "job_id", "actor_id"):
            if not _ID_RE.fullmatch(getattr(self, field_name)):
                raise ValueError(f"{field_name} is invalid")
        if self.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone-aware")
        if self.previous_event_hash is not None and not _SHA256_RE.fullmatch(
            self.previous_event_hash
        ):
            raise ValueError("previous_event_hash must be a SHA-256 hex digest")

        details = dict(self.details)
        try:
            json.dumps(details, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError("audit details must be JSON serializable") from exc
        object.__setattr__(self, "details", MappingProxyType(details))
        if self.previous_event_hash is not None:
            object.__setattr__(self, "previous_event_hash", self.previous_event_hash.lower())

    @property
    def event_hash(self) -> str:
        payload = {
            "actor_id": self.actor_id,
            "details": dict(self.details),
            "engagement_id": self.engagement_id,
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "job_id": self.job_id,
            "occurred_at": self.occurred_at.isoformat(),
            "previous_event_hash": self.previous_event_hash,
        }
        return _hash_json(payload)


class JobAuthorizationError(RuntimeError):
    """Raised when a request cannot become a worker job."""


def build_worker_job(
    *,
    broker: TypedToolBroker,
    engagement: Engagement,
    request: ToolRequest,
    policy_decision_id: str,
    job_id: str,
    approval: Approval | None = None,
    created_at: datetime | None = None,
    profiles: Mapping[str, WorkerProfile] = DEFAULT_WORKER_PROFILES,
    evidence_requirements: Mapping[
        str, tuple[EvidenceRequirement, ...]
    ] = DEFAULT_EVIDENCE_REQUIREMENTS,
) -> WorkerJobEnvelope:
    """Convert an authorised request into a fixed immutable worker job."""
    decision = broker.authorize(
        engagement=engagement,
        request=request,
        approval=approval,
    )
    if not decision.allowed:
        raise JobAuthorizationError(f"{decision.code.value}: {decision.reason}")

    definition = _find_definition(broker, request.tool_name)
    profile = profiles.get(definition.worker_profile)
    if profile is None:
        raise JobAuthorizationError(
            f"worker profile {definition.worker_profile!r} is not centrally registered"
        )
    _validate_definition_profile(definition, profile)

    requested_duration = request.arguments.get("duration_seconds")
    if requested_duration is not None and requested_duration > profile.max_duration_seconds:
        raise JobAuthorizationError("requested duration exceeds the worker profile limit")

    requirements = evidence_requirements.get(profile.name)
    if not requirements:
        raise JobAuthorizationError("worker profile has no evidence requirements")

    if definition.risk is ToolRisk.VALIDATION and approval is None:
        raise JobAuthorizationError("validation job requires a persisted approval")

    return WorkerJobEnvelope(
        job_id=job_id,
        engagement_id=engagement.engagement_id,
        policy_decision_id=policy_decision_id,
        request_id=request.request_id,
        request_fingerprint=request.fingerprint,
        tool_name=request.tool_name,
        security_domain=definition.domain,
        worker_profile=profile.name,
        isolation=profile.isolation,
        network_policy=profile.network_policy,
        target_kind=definition.target_kind,
        target_url=request.target_url,
        artifact_id=request.artifact_id,
        device_session_id=request.device_session_id,
        arguments=request.arguments,
        approval_id=approval.approval_id if approval is not None else None,
        max_duration_seconds=profile.max_duration_seconds,
        max_cpu_cores=profile.max_cpu_cores,
        max_memory_mb=profile.max_memory_mb,
        read_only_rootfs=profile.read_only_rootfs,
        privileged=profile.privileged,
        evidence_requirements=requirements,
        created_at=created_at or datetime.now(UTC),
    )


def _find_definition(broker: TypedToolBroker, tool_name: str) -> ToolDefinition:
    for definition in broker.policy.definitions:
        if definition.name == tool_name:
            return definition
    raise JobAuthorizationError("authorised tool definition disappeared from the broker")


def _validate_definition_profile(
    definition: ToolDefinition,
    profile: WorkerProfile,
) -> None:
    if definition.domain is not None and definition.domain not in profile.domains:
        raise JobAuthorizationError("tool domain is incompatible with its worker profile")
    if definition.domain is None and profile.domains:
        raise JobAuthorizationError("domain-neutral tool must use a domain-neutral profile")
    if definition.target_kind not in profile.target_kinds:
        raise JobAuthorizationError("tool target kind is incompatible with its worker profile")
    if definition.network_access and profile.network_policy is NetworkPolicy.DISABLED:
        raise JobAuthorizationError("networked tool cannot use a network-disabled profile")
    if not definition.network_access and profile.network_policy is not NetworkPolicy.DISABLED:
        raise JobAuthorizationError("offline tool cannot use a network-enabled profile")


def _hash_json(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "AuditEvent",
    "AuditEventType",
    "DEFAULT_EVIDENCE_REQUIREMENTS",
    "DEFAULT_WORKER_PROFILES",
    "EvidenceArtifact",
    "EvidenceKind",
    "EvidenceManifest",
    "EvidenceRequirement",
    "IsolationKind",
    "JobAuthorizationError",
    "NetworkPolicy",
    "WorkerJobEnvelope",
    "WorkerProfile",
    "build_worker_job",
]
