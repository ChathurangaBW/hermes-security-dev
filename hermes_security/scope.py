"""Machine-enforced web target scope matching."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from .domain import ScopeRule, canonical_host, canonical_path


@dataclass(frozen=True, slots=True)
class ScopeMatch:
    matched: bool
    reason: str
    rule: ScopeRule | None = None


def match_scope(target_url: str, rules: tuple[ScopeRule, ...]) -> ScopeMatch:
    """Match an HTTP(S) URL against explicit engagement scope rules."""
    try:
        parsed = urlsplit(target_url)
    except ValueError as exc:
        return ScopeMatch(False, f"target URL is invalid: {exc}")

    if parsed.scheme.lower() not in {"http", "https"}:
        return ScopeMatch(False, "target URL must use http or https")
    if parsed.username is not None or parsed.password is not None:
        return ScopeMatch(False, "userinfo is not permitted in target URLs")
    if parsed.hostname is None:
        return ScopeMatch(False, "target URL must contain a hostname")

    try:
        host = canonical_host(parsed.hostname)
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        path = canonical_path(parsed.path)
    except ValueError as exc:
        return ScopeMatch(False, f"target URL is invalid: {exc}")

    for rule in rules:
        host_matches = host == rule.host or (
            rule.include_subdomains and host.endswith("." + rule.host)
        )
        if not host_matches:
            continue
        if parsed.scheme.lower() != rule.scheme or port != rule.effective_port:
            continue

        prefix = rule.path_prefix
        path_matches = prefix == "/" or path == prefix or path.startswith(prefix + "/")
        if path_matches:
            return ScopeMatch(True, "target is within engagement scope", rule)

    return ScopeMatch(False, "target is outside engagement scope")
