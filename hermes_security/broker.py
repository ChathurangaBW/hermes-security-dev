"""Typed tool broker authorization boundary."""

from __future__ import annotations

from .catalog import DEFAULT_TOOL_DEFINITIONS
from .domain import Approval, Engagement, PolicyDecision, ToolRequest
from .policy import PolicyEngine


class TypedToolBroker:
    """Policy-check requests before a future isolated worker receives them.

    This first implementation intentionally has no ``execute`` method. Worker
    dispatch will be introduced only after engagement binding, audit events,
    evidence capture, and isolation contracts are defined.
    """

    def __init__(self, policy: PolicyEngine | None = None) -> None:
        self.policy = policy or PolicyEngine(DEFAULT_TOOL_DEFINITIONS)

    def authorize(
        self,
        *,
        engagement: Engagement,
        request: ToolRequest,
        approval: Approval | None = None,
    ) -> PolicyDecision:
        return self.policy.evaluate(
            engagement=engagement,
            request=request,
            approval=approval,
        )
