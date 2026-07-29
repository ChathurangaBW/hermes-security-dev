"""Authorized web-application pentest control-plane primitives."""

from .broker import TypedToolBroker
from .catalog import DEFAULT_TOOL_DEFINITIONS
from .domain import (
    Approval,
    ApprovalStatus,
    DecisionCode,
    Engagement,
    EngagementStatus,
    PolicyDecision,
    ScopeRule,
    ToolDefinition,
    ToolRequest,
    ToolRisk,
)
from .policy import FORBIDDEN_TOOL_NAMES, PolicyEngine
from .scope import ScopeMatch, match_scope

__all__ = [
    "Approval",
    "ApprovalStatus",
    "DEFAULT_TOOL_DEFINITIONS",
    "DecisionCode",
    "Engagement",
    "EngagementStatus",
    "FORBIDDEN_TOOL_NAMES",
    "PolicyDecision",
    "PolicyEngine",
    "ScopeMatch",
    "ScopeRule",
    "ToolDefinition",
    "ToolRequest",
    "ToolRisk",
    "TypedToolBroker",
    "match_scope",
]
