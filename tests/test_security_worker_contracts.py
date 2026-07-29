from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent.capability_packs import (
    CapabilityPackManifest,
    CapabilityPackRegistry,
    DEFAULT_CAPABILITY_PACKS,
    build_default_capability_registry,
)
from agent.security import (
    Approval,
    ApprovalStatus,
    ArtifactKind,
    ArtifactScope,
    DEFAULT_TOOL_DEFINITIONS,
    Engagement,
    EngagementStatus,
    ScopeRule,
    SecurityDomain,
    TargetKind,
    ToolRequest,
    TypedToolBroker,
)
from agent.security_workers import (
    AuthorizedJobFactory,
    IsolationClass,
    NetworkPolicy,
    WorkerProfile,
    WorkerTrustLevel,
)


def web_engagement() -> Engagement:
    return Engagement(
        engagement_id="eng-web-001",
        name="Authorized web assessment",
        status=EngagementStatus.ACTIVE,
        domains=(SecurityDomain.WEB,),
        scope=(ScopeRule(scheme="https", host="example.com", path_prefix="/app"),),
    )


def reverse_engagement() -> Engagement:
    return Engagement(
        engagement_id="eng-rev-001",
        name="Authorized binary assessment",
        status=EngagementStatus.ACTIVE,
        domains=(SecurityDomain.REVERSE_ENGINEERING,),
        artifacts=(
            ArtifactScope(
                artifact_id="artifact-001",
                kind=ArtifactKind.NATIVE_BINARY,
                sha256="a" * 64,
                display_name="sample.elf",
            ),
        ),
    )


def test_default_capability_packs_register_and_enable_independently() -> None:
    registry = build_default_capability_registry()

    assert registry.registered == DEFAULT_CAPABILITY_PACKS
    assert registry.enabled == ()

    registry.enable("mobile-security", "0.1.0")

    assert registry.is_enabled("mobile-security", "0.1.0")
    assert tuple(pack.name for pack in registry.enabled) == ("mobile-security",)
    assert not registry.is_enabled("web-security", "0.1.0")


def test_capability_pack_rejects_unknown_tool() -> None:
    manifest = CapabilityPackManifest(
        name="invalid-pack",
        version="0.1.0",
        domains=frozenset({SecurityDomain.WEB}),
        supported_target_kinds=frozenset({TargetKind.URL}),
        required_worker_profiles=frozenset({"web-passive"}),
        tool_names=("not_a_registered_tool",),
        evidence_schema_ids=("evidence.invalid.v1",),
        finding_template_ids=("finding.invalid.v1",),
        report_section_ids=("report.invalid.v1",),
    )

    with pytest.raises(ValueError, match="unknown tool"):
        CapabilityPackRegistry().register_manifest(manifest)


def test_worker_profile_prohibits_privileged_and_docker_socket_access() -> None:
    common = dict(
        name="unsafe-profile",
        isolation_class=IsolationClass.CONTAINER,
        trust_level=WorkerTrustLevel.STANDARD,
        labels=frozenset({"domain:test"}),
        network_policy=NetworkPolicy.DENY_ALL,
        max_cpu_cores=1.0,
        max_memory_mb=512,
        max_disk_mb=512,
        max_runtime_seconds=60,
    )

    with pytest.raises(ValueError, match="privileged workers are prohibited"):
        WorkerProfile(**common, allow_privileged=True)

    with pytest.raises(ValueError, match="Docker socket"):
        WorkerProfile(**common, allow_docker_socket=True)


def test_authorized_web_request_builds_content_addressed_job() -> None:
    engagement = web_engagement()
    request = ToolRequest(
        request_id="req-web-001",
        engagement_id=engagement.engagement_id,
        tool_name="http_probe",
        target_url="https://example.com/app/health",
        arguments={"method": "HEAD", "timeout_seconds": 10.0},
    )
    decision = TypedToolBroker().authorize(engagement=engagement, request=request)
    assert decision.allowed

    created_at = datetime(2026, 7, 29, 8, 0, tzinfo=UTC)
    factory = AuthorizedJobFactory(DEFAULT_TOOL_DEFINITIONS)
    job = factory.build(
        job_id="job-web-001",
        engagement=engagement,
        request=request,
        decision=decision,
        created_at=created_at,
    )
    same_job = factory.build(
        job_id="job-web-001",
        engagement=engagement,
        request=request,
        decision=decision,
        created_at=created_at,
    )

    assert job.worker_profile == "web-passive"
    assert job.isolation_class is IsolationClass.CONTAINER
    assert job.network_policy is NetworkPolicy.ENGAGEMENT_ALLOWLIST
    assert job.target_reference == "https://example.com/app/health"
    assert job.request_fingerprint == request.fingerprint
    assert job.envelope_sha256 == same_job.envelope_sha256
    assert len(job.envelope_sha256) == 64


def test_denied_policy_decision_cannot_create_job() -> None:
    engagement = web_engagement()
    request = ToolRequest(
        request_id="req-web-denied",
        engagement_id=engagement.engagement_id,
        tool_name="http_probe",
        target_url="https://outside.example.net/",
        arguments={"method": "GET"},
    )
    decision = TypedToolBroker().authorize(engagement=engagement, request=request)
    assert not decision.allowed

    with pytest.raises(ValueError, match="denied policy decision"):
        AuthorizedJobFactory(DEFAULT_TOOL_DEFINITIONS).build(
            job_id="job-web-denied",
            engagement=engagement,
            request=request,
            decision=decision,
        )


def test_dynamic_binary_job_requires_exact_approval_and_microvm() -> None:
    engagement = reverse_engagement()
    request = ToolRequest(
        request_id="req-rev-runtime",
        engagement_id=engagement.engagement_id,
        tool_name="observe_binary_runtime",
        artifact_id="artifact-001",
        arguments={"duration_seconds": 20},
    )
    approval = Approval(
        approval_id="approval-rev-001",
        engagement_id=engagement.engagement_id,
        request_id=request.request_id,
        tool_name=request.tool_name,
        request_fingerprint=request.fingerprint,
        status=ApprovalStatus.APPROVED,
    )
    decision = TypedToolBroker().authorize(
        engagement=engagement,
        request=request,
        approval=approval,
    )
    assert decision.allowed

    factory = AuthorizedJobFactory(DEFAULT_TOOL_DEFINITIONS)
    job = factory.build(
        job_id="job-rev-runtime",
        engagement=engagement,
        request=request,
        decision=decision,
        approval=approval,
        created_at=datetime(2026, 7, 29, 8, 0, tzinfo=UTC),
    )

    assert job.isolation_class is IsolationClass.MICROVM
    assert job.network_policy is NetworkPolicy.DENY_ALL
    assert job.approval_id == approval.approval_id

    altered_request = ToolRequest(
        request_id=request.request_id,
        engagement_id=engagement.engagement_id,
        tool_name=request.tool_name,
        artifact_id="artifact-001",
        arguments={"duration_seconds": 21},
    )
    with pytest.raises(ValueError, match="exact worker request"):
        factory.build(
            job_id="job-rev-altered",
            engagement=engagement,
            request=altered_request,
            decision=decision,
            approval=approval,
        )
