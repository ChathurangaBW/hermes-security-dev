"""Policy engine for typed, scope-bound pentest tool requests."""

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

        if definition.requires_target:
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
        elif request.target_url is not None:
            return PolicyDecision(
                False,
                DecisionCode.INVALID_ARGUMENTS,
                "non-targeted tool requests must not include target_url",
            )

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
