from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent.security import (
    Approval,
    ApprovalStatus,
    ArtifactKind,
    ArtifactScope,
    DeviceSessionScope,
    Engagement,
    EngagementStatus,
    MobilePlatform,
    ScopeRule,
    SecurityDomain,
    ToolRequest,
    TypedToolBroker,
)
from agent.security_jobs import (
    AuditEvent,
    AuditEventType,
    EvidenceArtifact,
    EvidenceKind,
    EvidenceManifest,
    IsolationKind,
    JobAuthorizationError,
    NetworkPolicy,
    build_worker_job,
)


def engagement() -> Engagement:
    return Engagement(
        engagement_id="eng-all",
        name="Authorised multi-discipline assessment",
        status=EngagementStatus.ACTIVE,
        scope=(ScopeRule(scheme="https", host="example.com"),),
        domains=(
            SecurityDomain.WEB,
            SecurityDomain.MOBILE,
            SecurityDomain.REVERSE_ENGINEERING,
        ),
        artifacts=(
            ArtifactScope(
                artifact_id="bin-1",
                kind=ArtifactKind.NATIVE_BINARY,
                sha256="b" * 64,
                display_name="sample.bin",
            ),
        ),
        device_sessions=(
            DeviceSessionScope(
                session_id="android-lab-1",
                platform=MobilePlatform.ANDROID,
            ),
        ),
    )


def approved(request: ToolRequest) -> Approval:
    return Approval(
        approval_id="approval-1",
        engagement_id=request.engagement_id,
        request_id=request.request_id,
        tool_name=request.tool_name,
        request_fingerprint=request.fingerprint,
        status=ApprovalStatus.APPROVED,
    )


def test_web_request_becomes_fixed_scope_allowlisted_container_job() -> None:
    request = ToolRequest(
        request_id="req-web",
        engagement_id="eng-all",
        tool_name="http_probe",
        target_url="https://example.com/",
        arguments={"method": "HEAD"},
    )

    job = build_worker_job(
        broker=TypedToolBroker(),
        engagement=engagement(),
        request=request,
        policy_decision_id="decision-1",
        job_id="job-1",
    )

    assert job.worker_profile == "web-passive"
    assert job.isolation is IsolationKind.CONTAINER
    assert job.network_policy is NetworkPolicy.SCOPE_ALLOWLIST
    assert job.read_only_rootfs
    assert not job.privileged
    assert job.approval_id is None
    assert job.request_fingerprint == request.fingerprint


def test_reverse_static_job_is_offline_and_artifact_bound() -> None:
    request = ToolRequest(
        request_id="req-reverse",
        engagement_id="eng-all",
        tool_name="decompile_function",
        artifact_id="bin-1",
        arguments={"function_identifier": "main"},
    )

    job = build_worker_job(
        broker=TypedToolBroker(),
        engagement=engagement(),
        request=request,
        policy_decision_id="decision-2",
        job_id="job-2",
    )

    assert job.worker_profile == "reverse-static"
    assert job.artifact_id == "bin-1"
    assert job.network_policy is NetworkPolicy.DISABLED
    assert job.isolation is IsolationKind.CONTAINER


def test_validation_request_cannot_become_job_without_approval() -> None:
    request = ToolRequest(
        request_id="req-runtime",
        engagement_id="eng-all",
        tool_name="observe_binary_runtime",
        artifact_id="bin-1",
        arguments={"network_mode": "disabled"},
    )

    with pytest.raises(JobAuthorizationError, match="approval_required"):
        build_worker_job(
            broker=TypedToolBroker(),
            engagement=engagement(),
            request=request,
            policy_decision_id="decision-3",
            job_id="job-3",
        )


def test_approved_reverse_runtime_job_uses_network_disabled_microvm() -> None:
    request = ToolRequest(
        request_id="req-runtime-approved",
        engagement_id="eng-all",
        tool_name="observe_binary_runtime",
        artifact_id="bin-1",
        arguments={"duration_seconds": 60, "network_mode": "disabled"},
    )

    job = build_worker_job(
        broker=TypedToolBroker(),
        engagement=engagement(),
        request=request,
        approval=approved(request),
        policy_decision_id="decision-4",
        job_id="job-4",
    )

    assert job.worker_profile == "reverse-runtime"
    assert job.isolation is IsolationKind.MICROVM
    assert job.network_policy is NetworkPolicy.DISABLED
    assert job.approval_id == "approval-1"
    assert any(
        requirement.kind is EvidenceKind.RUNTIME_TRACE and requirement.required
        for requirement in job.evidence_requirements
    )


def test_model_cannot_override_worker_profile_through_arguments() -> None:
    request = ToolRequest(
        request_id="req-profile-injection",
        engagement_id="eng-all",
        tool_name="http_probe",
        target_url="https://example.com/",
        arguments={"method": "GET", "worker_profile": "reverse-runtime"},
    )

    with pytest.raises(JobAuthorizationError, match="invalid_arguments"):
        build_worker_job(
            broker=TypedToolBroker(),
            engagement=engagement(),
            request=request,
            policy_decision_id="decision-5",
            job_id="job-5",
        )


def test_job_arguments_are_immutable() -> None:
    request = ToolRequest(
        request_id="req-immutable",
        engagement_id="eng-all",
        tool_name="fingerprint_binary",
        artifact_id="bin-1",
        arguments={"calculate_entropy": True},
    )
    job = build_worker_job(
        broker=TypedToolBroker(),
        engagement=engagement(),
        request=request,
        policy_decision_id="decision-6",
        job_id="job-6",
    )

    with pytest.raises(TypeError):
        job.arguments["calculate_entropy"] = False


def test_evidence_manifest_is_bound_to_job_fingerprint() -> None:
    request = ToolRequest(
        request_id="req-evidence",
        engagement_id="eng-all",
        tool_name="fingerprint_binary",
        artifact_id="bin-1",
        arguments={},
    )
    created_at = datetime(2026, 7, 29, 4, 0, tzinfo=UTC)
    job = build_worker_job(
        broker=TypedToolBroker(),
        engagement=engagement(),
        request=request,
        policy_decision_id="decision-7",
        job_id="job-7",
        created_at=created_at,
    )
    artifact = EvidenceArtifact(
        evidence_id="evidence-1",
        job_id="job-7",
        kind=EvidenceKind.ARTIFACT_ANALYSIS,
        sha256="c" * 64,
        media_type="application/json",
        size_bytes=128,
        object_key="eng-all/job-7/evidence-1.json",
        captured_at=created_at,
    )
    manifest = EvidenceManifest(
        manifest_id="manifest-1",
        job_id="job-7",
        job_fingerprint=job.job_fingerprint,
        artifacts=(artifact,),
        sealed_at=created_at,
    )

    assert len(job.job_fingerprint) == 64
    assert len(manifest.manifest_fingerprint) == 64


def test_audit_events_form_hash_chain() -> None:
    occurred_at = datetime(2026, 7, 29, 4, 5, tzinfo=UTC)
    first = AuditEvent(
        event_id="event-1",
        engagement_id="eng-all",
        job_id="job-7",
        event_type=AuditEventType.JOB_AUTHORIZED,
        actor_id="policy-engine",
        details={"decision": "allow"},
        occurred_at=occurred_at,
    )
    second = AuditEvent(
        event_id="event-2",
        engagement_id="eng-all",
        job_id="job-7",
        event_type=AuditEventType.JOB_DISPATCHED,
        actor_id="dispatcher",
        details={"profile": "reverse-static"},
        occurred_at=occurred_at,
        previous_event_hash=first.event_hash,
    )

    assert second.previous_event_hash == first.event_hash
    assert second.event_hash != first.event_hash
