"""Policy engine for typed, scope-bound security tool requests."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import ValidationError

from .domain import (
    Approval,
    ApprovalStatus,
    DecisionCode,
    Engagement,
    EngagementStatus,
    PolicyDecision,
    TargetKind,
    ToolDefinition,
    ToolRequest,
    ToolRisk,
)
from .scope import match_scope


FORBIDDEN_TOOL_NAMES = frozenset(
    {
        "bash",
        "exec",
        "execute_command",
        "powershell",
        "run_command",
        "run_shell",
        "shell",
        "ssh_exec",
        "terminal",
    }
)


class PolicyEngine:
    """Authorize model-proposed tool requests without executing them."""

    def __init__(self, definitions: Iterable[ToolDefinition] = ()) -> None:
        self._definitions: dict[str, ToolDefinition] = {}
        for definition in definitions:
            self.register(definition)

    def register(self, definition: ToolDefinition) -> None:
        if definition.name in FORBIDDEN_TOOL_NAMES:
            raise ValueError(f"tool {definition.name!r} is prohibited")
        if definition.name in self._definitions:
            raise ValueError(f"tool {definition.name!r} is already registered")
        self._definitions[definition.name] = definition

    @property
    def definitions(self) -> tuple[ToolDefinition, ...]:
        return tuple(self._definitions.values())

    def evaluate(
        self,
        *,
        engagement: Engagement,
        request: ToolRequest,
        approval: Approval | None = None,
    ) -> PolicyDecision:
        if request.engagement_id != engagement.engagement_id:
            return PolicyDecision(
                False,
                DecisionCode.ENGAGEMENT_MISMATCH,
                "tool request does not belong to the supplied engagement",
            )

        if engagement.status is not EngagementStatus.ACTIVE:
            return PolicyDecision(
                False,
                DecisionCode.ENGAGEMENT_INACTIVE,
                f"engagement is {engagement.status.value}, not active",
            )

        if request.tool_name in FORBIDDEN_TOOL_NAMES:
            return PolicyDecision(
                False,
                DecisionCode.FORBIDDEN_TOOL,
                "generic command execution is prohibited",
            )

        definition = self._definitions.get(request.tool_name)
        if definition is None:
            return PolicyDecision(
                False,
                DecisionCode.TOOL_NOT_REGISTERED,
                "tool is not present in the security tool catalogue",
            )

        if definition.domain is not None and definition.domain not in engagement.domains:
            return PolicyDecision(
                False,
                DecisionCode.DOMAIN_NOT_AUTHORIZED,
                f"engagement does not authorize the {definition.domain.value} domain",
            )

        try:
            definition.arguments_model.model_validate(dict(request.arguments))
        except ValidationError as exc:
            first_error = exc.errors(include_url=False)[0]
            location = ".".join(str(part) for part in first_error["loc"]) or "arguments"
            return PolicyDecision(
                False,
                DecisionCode.INVALID_ARGUMENTS,
                f"invalid tool arguments at {location}: {first_error['msg']}",
            )

        target_decision = self._authorize_target(
            engagement=engagement,
            request=request,
            definition=definition,
        )
        if target_decision is not None:
            return target_decision

        if definition.risk is ToolRisk.VALIDATION:
            if approval is None or approval.status is ApprovalStatus.PENDING:
                return PolicyDecision(
                    False,
                    DecisionCode.APPROVAL_REQUIRED,
                    "validation action requires explicit human approval",
                    requires_approval=True,
                )
            if (
                approval.status is not ApprovalStatus.APPROVED
                or approval.engagement_id != engagement.engagement_id
                or approval.request_id != request.request_id
                or approval.tool_name != request.tool_name
            ):
                return PolicyDecision(
                    False,
                    DecisionCode.APPROVAL_INVALID,
                    "approval does not authorize this exact tool request",
                    requires_approval=True,
                )

        return PolicyDecision(True, DecisionCode.ALLOW, "policy authorized the tool request")

    @staticmethod
    def _authorize_target(
        *,
        engagement: Engagement,
        request: ToolRequest,
        definition: ToolDefinition,
    ) -> PolicyDecision | None:
        supplied_targets = sum(
            value is not None
            for value in (request.target_url, request.artifact_id, request.device_session_id)
        )

        if definition.target_kind is TargetKind.NONE:
            if supplied_targets:
                return PolicyDecision(
                    False,
                    DecisionCode.TARGET_KIND_MISMATCH,
                    "non-targeted tool requests must not include a target reference",
                )
            return None

        if supplied_targets > 1:
            return PolicyDecision(
                False,
                DecisionCode.TARGET_KIND_MISMATCH,
                "tool requests must contain exactly one target reference",
            )

        if definition.target_kind is TargetKind.URL:
            if not request.target_url:
                return PolicyDecision(
                    False,
                    DecisionCode.TARGET_REQUIRED,
                    "tool requires an explicit target URL",
                )
            scope_match = match_scope(request.target_url, engagement.scope)
            if not scope_match.matched:
                code = (
                    DecisionCode.TARGET_INVALID
                    if scope_match.reason.startswith("target URL")
                    else DecisionCode.TARGET_OUT_OF_SCOPE
                )
                return PolicyDecision(False, code, scope_match.reason)
            return None

        if definition.target_kind is TargetKind.ARTIFACT:
            if not request.artifact_id:
                return PolicyDecision(
                    False,
                    DecisionCode.ARTIFACT_REQUIRED,
                    "tool requires an explicitly registered artefact",
                )
            artifact = next(
                (
                    candidate
                    for candidate in engagement.artifacts
                    if candidate.artifact_id == request.artifact_id
                ),
                None,
            )
            if artifact is None:
                return PolicyDecision(
                    False,
                    DecisionCode.ARTIFACT_NOT_AUTHORIZED,
                    "artefact is not registered in this engagement",
                )
            if definition.artifact_kinds and artifact.kind not in definition.artifact_kinds:
                return PolicyDecision(
                    False,
                    DecisionCode.ARTIFACT_KIND_NOT_ALLOWED,
                    f"tool does not accept artefacts of type {artifact.kind.value}",
                )
            return None

        if definition.target_kind is TargetKind.DEVICE_SESSION:
            if not request.device_session_id:
                return PolicyDecision(
                    False,
                    DecisionCode.DEVICE_SESSION_REQUIRED,
                    "tool requires an explicitly registered device session",
                )
            if request.device_session_id not in engagement.device_session_ids:
                return PolicyDecision(
                    False,
                    DecisionCode.DEVICE_SESSION_NOT_AUTHORIZED,
                    "device session is not registered in this engagement",
                )
            return None

        return PolicyDecision(
            False,
            DecisionCode.TARGET_KIND_MISMATCH,
            "unsupported target kind",
        )
