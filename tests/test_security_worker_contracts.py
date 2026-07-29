from __future__ import annotations

import pytest

from agent.capability_packs import (
    CapabilityPackManifest,
    CapabilityPackRegistry,
    DEFAULT_CAPABILITY_PACKS,
    build_default_capability_registry,
)
from agent.security import SecurityDomain, TargetKind
from agent.security_jobs import IsolationKind, NetworkPolicy, WorkerProfile


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


def test_capability_pack_rejects_unknown_worker_profile() -> None:
    manifest = CapabilityPackManifest(
        name="invalid-profile-pack",
        version="0.1.0",
        domains=frozenset({SecurityDomain.WEB}),
        supported_target_kinds=frozenset({TargetKind.URL}),
        required_worker_profiles=frozenset({"model-selected-profile"}),
        tool_names=("http_probe",),
        evidence_schema_ids=("evidence.invalid_profile.v1",),
        finding_template_ids=("finding.invalid_profile.v1",),
        report_section_ids=("report.invalid_profile.v1",),
    )

    with pytest.raises(ValueError, match="unknown worker profile"):
        CapabilityPackRegistry().register_manifest(manifest)


def test_capability_pack_rejects_cross_domain_tool() -> None:
    manifest = CapabilityPackManifest(
        name="cross-domain-pack",
        version="0.1.0",
        domains=frozenset({SecurityDomain.MOBILE}),
        supported_target_kinds=frozenset({TargetKind.URL}),
        required_worker_profiles=frozenset({"web-passive"}),
        tool_names=("http_probe",),
        evidence_schema_ids=("evidence.cross_domain.v1",),
        finding_template_ids=("finding.cross_domain.v1",),
        report_section_ids=("report.cross_domain.v1",),
    )

    with pytest.raises(ValueError, match="outside pack"):
        CapabilityPackRegistry().register_manifest(manifest)


def test_worker_profile_prohibits_privileged_execution() -> None:
    with pytest.raises(ValueError, match="never be privileged"):
        WorkerProfile(
            name="unsafe-profile",
            isolation=IsolationKind.CONTAINER,
            domains=frozenset({SecurityDomain.WEB}),
            target_kinds=frozenset({TargetKind.URL}),
            network_policy=NetworkPolicy.SCOPE_ALLOWLIST,
            max_duration_seconds=60,
            max_cpu_cores=1.0,
            max_memory_mb=512,
            privileged=True,
        )
