from __future__ import annotations

from agent.security import (
    Approval,
    ApprovalStatus,
    ArtifactKind,
    ArtifactScope,
    DecisionCode,
    DeviceSessionScope,
    Engagement,
    EngagementStatus,
    MobilePlatform,
    ScopeRule,
    SecurityDomain,
    ToolRequest,
    TypedToolBroker,
    match_scope,
)


def web_engagement() -> Engagement:
    return Engagement(
        engagement_id="eng-web",
        name="Example authorised web assessment",
        status=EngagementStatus.ACTIVE,
        scope=(
            ScopeRule(
                scheme="https",
                host="example.com",
                path_prefix="/app",
                include_subdomains=True,
            ),
        ),
        domains=(SecurityDomain.WEB,),
    )


def multi_domain_engagement() -> Engagement:
    return Engagement(
        engagement_id="eng-all",
        name="Example authorised multi-discipline assessment",
        status=EngagementStatus.ACTIVE,
        scope=(ScopeRule(scheme="https", host="example.com"),),
        domains=(
            SecurityDomain.WEB,
            SecurityDomain.MOBILE,
            SecurityDomain.REVERSE_ENGINEERING,
        ),
        artifacts=(
            ArtifactScope(
                artifact_id="apk-1",
                kind=ArtifactKind.ANDROID_APK,
                sha256="a" * 64,
                display_name="example.apk",
            ),
            ArtifactScope(
                artifact_id="bin-1",
                kind=ArtifactKind.NATIVE_BINARY,
                sha256="b" * 64,
                display_name="example.bin",
            ),
        ),
        device_sessions=(
            DeviceSessionScope(
                session_id="android-lab-1",
                platform=MobilePlatform.ANDROID,
            ),
        ),
    )


def approved(request: ToolRequest, approval_id: str = "approval-1") -> Approval:
    return Approval(
        approval_id=approval_id,
        engagement_id=request.engagement_id,
        request_id=request.request_id,
        tool_name=request.tool_name,
        request_fingerprint=request.fingerprint,
        status=ApprovalStatus.APPROVED,
    )


def test_scope_matches_exact_host_and_path_boundary() -> None:
    rules = web_engagement().scope

    assert match_scope("https://example.com/app", rules).matched
    assert match_scope("https://api.example.com/app/users", rules).matched
    assert not match_scope("https://example.com/application", rules).matched
    assert not match_scope("https://evil-example.com/app", rules).matched


def test_scope_rejects_encoded_path_traversal() -> None:
    result = match_scope("https://example.com/app/%2e%2e/admin", web_engagement().scope)

    assert not result.matched
    assert result.reason == "target is outside engagement scope"


def test_policy_denies_generic_shell_even_when_requested_in_scope() -> None:
    request = ToolRequest(
        request_id="req-shell",
        engagement_id="eng-web",
        tool_name="run_shell",
        target_url="https://example.com/app",
        arguments={"command": "whoami"},
    )

    decision = TypedToolBroker().authorize(engagement=web_engagement(), request=request)

    assert not decision.allowed
    assert decision.code is DecisionCode.FORBIDDEN_TOOL


def test_policy_denies_out_of_scope_web_target() -> None:
    request = ToolRequest(
        request_id="req-probe",
        engagement_id="eng-web",
        tool_name="http_probe",
        target_url="https://example.net/",
        arguments={"method": "HEAD"},
    )

    decision = TypedToolBroker().authorize(engagement=web_engagement(), request=request)

    assert not decision.allowed
    assert decision.code is DecisionCode.TARGET_OUT_OF_SCOPE


def test_policy_rejects_untyped_extra_arguments() -> None:
    request = ToolRequest(
        request_id="req-extra",
        engagement_id="eng-web",
        tool_name="http_probe",
        target_url="https://example.com/app",
        arguments={"method": "GET", "command": "curl example.com"},
    )

    decision = TypedToolBroker().authorize(engagement=web_engagement(), request=request)

    assert not decision.allowed
    assert decision.code is DecisionCode.INVALID_ARGUMENTS


def test_validation_requires_exact_request_fingerprint() -> None:
    request = ToolRequest(
        request_id="req-verify",
        engagement_id="eng-web",
        tool_name="verify_candidate_finding",
        target_url="https://example.com/app",
        arguments={
            "finding_id": "finding-123",
            "verification_mode": "safe_recheck",
        },
    )
    broker = TypedToolBroker()

    pending = broker.authorize(engagement=web_engagement(), request=request)
    assert not pending.allowed
    assert pending.code is DecisionCode.APPROVAL_REQUIRED

    wrong_fingerprint = Approval(
        approval_id="approval-wrong",
        engagement_id="eng-web",
        request_id="req-verify",
        tool_name="verify_candidate_finding",
        request_fingerprint="0" * 64,
        status=ApprovalStatus.APPROVED,
    )
    rejected = broker.authorize(
        engagement=web_engagement(),
        request=request,
        approval=wrong_fingerprint,
    )
    assert not rejected.allowed
    assert rejected.code is DecisionCode.APPROVAL_INVALID

    allowed = broker.authorize(
        engagement=web_engagement(),
        request=request,
        approval=approved(request),
    )
    assert allowed.allowed


def test_mobile_static_analysis_accepts_registered_package() -> None:
    request = ToolRequest(
        request_id="req-mobile-static",
        engagement_id="eng-all",
        tool_name="inspect_mobile_manifest",
        artifact_id="apk-1",
        arguments={"platform": "android"},
    )

    decision = TypedToolBroker().authorize(
        engagement=multi_domain_engagement(),
        request=request,
    )

    assert decision.allowed


def test_mobile_tool_rejects_wrong_artifact_kind() -> None:
    request = ToolRequest(
        request_id="req-mobile-wrong-kind",
        engagement_id="eng-all",
        tool_name="inspect_mobile_manifest",
        artifact_id="bin-1",
        arguments={"platform": "android"},
    )

    decision = TypedToolBroker().authorize(
        engagement=multi_domain_engagement(),
        request=request,
    )

    assert not decision.allowed
    assert decision.code is DecisionCode.ARTIFACT_KIND_NOT_ALLOWED


def test_mobile_tool_rejects_platform_mismatch() -> None:
    request = ToolRequest(
        request_id="req-mobile-platform",
        engagement_id="eng-all",
        tool_name="inspect_mobile_manifest",
        artifact_id="apk-1",
        arguments={"platform": "ios"},
    )

    decision = TypedToolBroker().authorize(
        engagement=multi_domain_engagement(),
        request=request,
    )

    assert not decision.allowed
    assert decision.code is DecisionCode.INVALID_ARGUMENTS


def test_reverse_engineering_static_analysis_accepts_registered_binary() -> None:
    request = ToolRequest(
        request_id="req-decompile",
        engagement_id="eng-all",
        tool_name="decompile_function",
        artifact_id="bin-1",
        arguments={"function_identifier": "main"},
    )

    decision = TypedToolBroker().authorize(
        engagement=multi_domain_engagement(),
        request=request,
    )

    assert decision.allowed


def test_domain_must_be_authorized_by_engagement() -> None:
    request = ToolRequest(
        request_id="req-mobile-domain",
        engagement_id="eng-web",
        tool_name="inspect_mobile_manifest",
        artifact_id="apk-1",
        arguments={"platform": "android"},
    )

    decision = TypedToolBroker().authorize(engagement=web_engagement(), request=request)

    assert not decision.allowed
    assert decision.code is DecisionCode.DOMAIN_NOT_AUTHORIZED


def test_mobile_runtime_requires_registered_device_and_approval() -> None:
    request = ToolRequest(
        request_id="req-mobile-runtime",
        engagement_id="eng-all",
        tool_name="observe_mobile_runtime",
        device_session_id="android-lab-1",
        arguments={
            "platform": "android",
            "app_identifier": "com.example.app",
            "network_mode": "disabled",
        },
    )
    broker = TypedToolBroker()

    pending = broker.authorize(engagement=multi_domain_engagement(), request=request)
    assert not pending.allowed
    assert pending.code is DecisionCode.APPROVAL_REQUIRED

    allowed = broker.authorize(
        engagement=multi_domain_engagement(),
        request=request,
        approval=approved(request, "approval-mobile"),
    )
    assert allowed.allowed


def test_binary_runtime_observation_requires_approval() -> None:
    request = ToolRequest(
        request_id="req-bin-runtime",
        engagement_id="eng-all",
        tool_name="observe_binary_runtime",
        artifact_id="bin-1",
        arguments={"network_mode": "disabled"},
    )

    decision = TypedToolBroker().authorize(
        engagement=multi_domain_engagement(),
        request=request,
    )

    assert not decision.allowed
    assert decision.code is DecisionCode.APPROVAL_REQUIRED
    assert decision.requires_approval


def test_request_cannot_mix_target_reference_types() -> None:
    request = ToolRequest(
        request_id="req-mixed-targets",
        engagement_id="eng-all",
        tool_name="fingerprint_binary",
        target_url="https://example.com/",
        artifact_id="bin-1",
        arguments={},
    )

    decision = TypedToolBroker().authorize(
        engagement=multi_domain_engagement(),
        request=request,
    )

    assert not decision.allowed
    assert decision.code is DecisionCode.TARGET_KIND_MISMATCH


def test_export_report_is_non_targeted_and_validated_only() -> None:
    request = ToolRequest(
        request_id="req-report",
        engagement_id="eng-all",
        tool_name="export_report",
        arguments={"format": "markdown", "validated_only": True},
    )

    decision = TypedToolBroker().authorize(
        engagement=multi_domain_engagement(),
        request=request,
    )

    assert decision.allowed
