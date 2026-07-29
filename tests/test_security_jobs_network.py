from __future__ import annotations

from agent.security import (
    Approval,
    ApprovalStatus,
    DeviceSessionScope,
    Engagement,
    EngagementStatus,
    MobilePlatform,
    SecurityDomain,
    ToolRequest,
    TypedToolBroker,
)
from agent.security_jobs import NetworkPolicy, build_worker_job


def test_mobile_runtime_disabled_network_request_stays_disabled() -> None:
    engagement = Engagement(
        engagement_id="eng-mobile",
        name="Authorised mobile assessment",
        status=EngagementStatus.ACTIVE,
        domains=(SecurityDomain.MOBILE,),
        device_sessions=(
            DeviceSessionScope(
                session_id="android-lab-1",
                platform=MobilePlatform.ANDROID,
            ),
        ),
    )
    request = ToolRequest(
        request_id="req-mobile-runtime",
        engagement_id="eng-mobile",
        tool_name="observe_mobile_runtime",
        device_session_id="android-lab-1",
        arguments={
            "platform": "android",
            "app_identifier": "com.example.app",
            "network_mode": "disabled",
        },
    )
    approval = Approval(
        approval_id="approval-mobile",
        engagement_id="eng-mobile",
        request_id=request.request_id,
        tool_name=request.tool_name,
        request_fingerprint=request.fingerprint,
        status=ApprovalStatus.APPROVED,
    )

    job = build_worker_job(
        broker=TypedToolBroker(),
        engagement=engagement,
        request=request,
        approval=approval,
        policy_decision_id="decision-mobile",
        job_id="job-mobile",
    )

    assert job.network_policy is NetworkPolicy.DISABLED
    assert job.arguments["network_mode"] == "disabled"
