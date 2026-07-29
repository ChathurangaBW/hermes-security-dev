from __future__ import annotations

from agent.security import (
    Approval,
    ApprovalStatus,
    DecisionCode,
    Engagement,
    EngagementStatus,
    ScopeRule,
    ToolRequest,
    TypedToolBroker,
    match_scope,
)


def active_engagement() -> Engagement:
    return Engagement(
        engagement_id="eng-001",
        name="Example authorised assessment",
        status=EngagementStatus.ACTIVE,
        scope=(
            ScopeRule(
                scheme="https",
                host="example.com",
                path_prefix="/app",
                include_subdomains=True,
            ),
        ),
    )


def test_scope_matches_exact_host_and_path_boundary() -> None:
    rules = active_engagement().scope

    assert match_scope("https://example.com/app", rules).matched
    assert match_scope("https://api.example.com/app/users", rules).matched
    assert not match_scope("https://example.com/application", rules).matched
    assert not match_scope("https://evil-example.com/app", rules).matched


def test_scope_rejects_encoded_path_traversal() -> None:
    result = match_scope("https://example.com/app/%2e%2e/admin", active_engagement().scope)

    assert not result.matched
    assert result.reason == "target is outside engagement scope"


def test_policy_denies_generic_shell_even_when_requested_in_scope() -> None:
    request = ToolRequest(
        request_id="req-shell",
        engagement_id="eng-001",
        tool_name="run_shell",
        target_url="https://example.com/app",
        arguments={"command": "whoami"},
    )

    decision = TypedToolBroker().authorize(
        engagement=active_engagement(),
        request=request,
    )

    assert not decision.allowed
    assert decision.code is DecisionCode.FORBIDDEN_TOOL


def test_policy_denies_out_of_scope_target() -> None:
    request = ToolRequest(
        request_id="req-probe",
        engagement_id="eng-001",
        tool_name="http_probe",
        target_url="https://example.net/",
        arguments={"method": "HEAD"},
    )

    decision = TypedToolBroker().authorize(
        engagement=active_engagement(),
        request=request,
    )

    assert not decision.allowed
    assert decision.code is DecisionCode.TARGET_OUT_OF_SCOPE


def test_policy_rejects_untyped_extra_arguments() -> None:
    request = ToolRequest(
        request_id="req-extra",
        engagement_id="eng-001",
        tool_name="http_probe",
        target_url="https://example.com/app",
        arguments={"method": "GET", "command": "curl example.com"},
    )

    decision = TypedToolBroker().authorize(
        engagement=active_engagement(),
        request=request,
    )

    assert not decision.allowed
    assert decision.code is DecisionCode.INVALID_ARGUMENTS


def test_validation_requires_exact_approved_request() -> None:
    request = ToolRequest(
        request_id="req-verify",
        engagement_id="eng-001",
        tool_name="verify_candidate_finding",
        target_url="https://example.com/app",
        arguments={
            "finding_id": "finding-123",
            "verification_mode": "safe_recheck",
        },
    )
    broker = TypedToolBroker()

    pending = broker.authorize(engagement=active_engagement(), request=request)
    assert not pending.allowed
    assert pending.code is DecisionCode.APPROVAL_REQUIRED
    assert pending.requires_approval

    wrong_approval = Approval(
        approval_id="approval-1",
        engagement_id="eng-001",
        request_id="another-request",
        tool_name="verify_candidate_finding",
        status=ApprovalStatus.APPROVED,
    )
    rejected = broker.authorize(
        engagement=active_engagement(),
        request=request,
        approval=wrong_approval,
    )
    assert not rejected.allowed
    assert rejected.code is DecisionCode.APPROVAL_INVALID

    approval = Approval(
        approval_id="approval-2",
        engagement_id="eng-001",
        request_id="req-verify",
        tool_name="verify_candidate_finding",
        status=ApprovalStatus.APPROVED,
    )
    allowed = broker.authorize(
        engagement=active_engagement(),
        request=request,
        approval=approval,
    )
    assert allowed.allowed
    assert allowed.code is DecisionCode.ALLOW


def test_export_report_is_non_targeted_and_validated_only() -> None:
    request = ToolRequest(
        request_id="req-report",
        engagement_id="eng-001",
        tool_name="export_report",
        arguments={"format": "markdown", "validated_only": True},
    )

    decision = TypedToolBroker().authorize(
        engagement=active_engagement(),
        request=request,
    )

    assert decision.allowed
