# Master Build Specification: Multi-Domain Authorized Security Assessment Platform

This document is the governing product and engineering specification for redeveloping Hermes into a production-grade, authorized security assessment platform.

## Product definition

The product must support modular assessment capabilities for:

- web application and API security;
- Android and iOS application security;
- reverse engineering and binary analysis;
- cloud security;
- container and Kubernetes security;
- source-code review;
- desktop application security;
- infrastructure and network assessment;
- firmware and embedded analysis;
- threat modelling;
- evidence management;
- reporting, remediation, and retesting.

It is not a generic coding CLI, chatbot, or unrestricted autonomous offensive agent. It is a controlled security operations platform where AI assists with planning, execution, triage, validation, evidence handling, and reporting while policy, scope, isolation, and human authorization remain authoritative.

```text
The model proposes.
Policy decides.
Isolated workers execute.
Evidence proves.
A human authorizes sensitive actions.
```

## Runtime foundation

Retain useful generic framework components where they can be separated from personal-assistant behavior:

```text
agent runtime
provider abstraction
tool registry
browser layer
session engine
plugin system
task orchestration
API layer
TUI or desktop shell
```

Do not cosmetically rename the original framework. Replace or heavily redesign its authorization, memory, worker execution, tool contracts, data model, session semantics, reporting, audit system, UI terminology, plugin trust model, credential handling, approval flow, and network access model.

## Required architecture

```text
Operator UI / TUI / API
        ↓
Workspace and Engagement Engine
        ↓
Scope and Authorization Engine
        ↓
Policy and Approval Engine
        ↓
Security Orchestrator
        ↓
Typed Tool Broker
        ↓
Isolated Execution Workers
        ↓
Evidence and Artifact Store
        ↓
Independent Verification Layer
        ↓
Finding Lifecycle
        ↓
Reporting and Remediation
```

## Core domain model

Implement first-class entities for:

```text
Workspace
Organisation
Project
Engagement
Assessment phase
Scope
Target
Asset
Environment
Credential reference
Authorization record
Tool definition
Tool invocation
Policy decision
Approval request
Execution job
Worker
Artifact
Evidence
Candidate finding
Validated finding
False positive
Remediation
Retest
Report
Audit event
Model call
Operator action
```

Every persisted object must have a stable identifier, timestamps, ownership, engagement association, audit history, authorization context, and integrity metadata where applicable.

## Capability packs

Each assessment domain is an independently enableable and versioned capability pack. A capability pack contains:

```text
domain-specific data models
typed tools
policy rules
worker requirements
evidence schemas
finding templates
verification procedures
report sections
UI views
tests
documentation
```

A common interface must expose identity, version, supported target types, required worker labels, tool definitions, policy rules, evidence schemas, finding templates, scope validation, plan proposal, finding verification, and report-section rendering.

## Domain requirements

### Web application security

Support scope-aware crawling, route discovery, HTTP evidence capture, authentication-flow mapping, session handling, header and cookie analysis, TLS review, passive analysis, parameter inventory, access-control review, input-validation review, API discovery, safe validation, verification, and reporting.

Representative typed tools:

```text
crawl_authorized_target
map_routes
capture_http_exchange
analyze_security_headers
analyze_cookie_configuration
inventory_parameters
run_passive_web_scan
compare_access_control_responses
record_web_evidence
verify_web_finding
```

### API security

Support OpenAPI and GraphQL schema ingestion, endpoint inventory, authentication and authorization analysis, rate-limit analysis, object-level access-control review, schema validation, response-difference analysis, evidence, verification, and API-specific reporting.

Representative typed tools:

```text
import_openapi_schema
discover_api_endpoints
inspect_graphql_schema
compare_api_authorization
analyze_rate_limits
validate_api_schema
record_api_evidence
verify_api_finding
```

### Mobile application security

Support APK, AAB, IPA, and application-bundle ingestion; manifest and entitlement parsing; permission, signing, dependency, static code, resource, secret, deep-link, local-storage, network-security, and native-library analysis; controlled emulator or simulator workflows; runtime evidence; and mobile finding templates.

Representative typed tools:

```text
ingest_mobile_package
parse_android_manifest
parse_ios_entitlements
analyze_mobile_permissions
inspect_mobile_storage
inventory_mobile_endpoints
analyze_mobile_signing
analyze_mobile_dependencies
run_mobile_static_analysis
record_mobile_evidence
verify_mobile_finding
```

### Reverse engineering and binary analysis

Support PE, ELF, Mach-O, DEX, WASM, and firmware identification; hashing; strings; symbols; imports and exports; sections; entropy; control-flow metadata; typed decompiler integration; packer and compiler indicators; behavioral hypothesis generation; isolated dynamic analysis; trace and crash evidence; and reverse-engineering reports.

Representative typed tools:

```text
identify_binary_format
hash_artifact
extract_strings
analyze_imports
analyze_exports
analyze_sections
calculate_entropy
run_ghidra_analysis
run_rizin_analysis
collect_dynamic_trace
record_binary_evidence
verify_reverse_engineering_finding
```

Untrusted binaries must never execute on the host. Dynamic execution is restricted to microVMs, KVM virtual machines, sandboxed emulators, or an explicitly justified ephemeral isolated container.

### Source-code security review

Support repository ingestion, language and dependency inventory, secret scanning, static and data-flow analysis, authentication and authorization review, dangerous-API detection, configuration and infrastructure-as-code review, code-to-finding evidence, remediation suggestions, and patch verification.

Representative typed tools:

```text
ingest_repository
inventory_languages
analyze_dependencies
scan_for_secrets
run_static_analysis
trace_sensitive_data_flow
review_authentication_logic
review_authorization_logic
analyze_infrastructure_code
record_code_evidence
verify_code_finding
```

### Cloud security

Support AWS, Azure, and Google Cloud inventory ingestion; IAM, storage exposure, networking, encryption, logging, secrets-management, and serverless configuration review; evidence; verification; and domain-specific reporting. Cloud credentials must be brokered and must not be exposed directly to model context.

### Container and Kubernetes security

Support image ingestion, SBOM generation, dependency and vulnerability inventory, Dockerfile and runtime review, Kubernetes manifest and RBAC analysis, admission policy, secret exposure, network policy, pod security, evidence, verification, and reporting.

### Infrastructure and network assessment

Support only explicitly authorized asset import, service inventory, TLS review, configuration analysis, passive fingerprinting, controlled connectivity checks, evidence capture, and approval-gated active validation. Unscoped discovery is prohibited.

### Firmware and embedded analysis

Support firmware ingestion, format identification, filesystem extraction, component and binary inventory, boot configuration, hard-coded secret detection, web-interface extraction, emulation preparation, evidence, verification, and reporting.

## Tool contract requirements

Never expose an unrestricted command-string interface such as:

```python
run_shell(command: str)
```

Every tool must be a typed operation bound to an engagement and target. It must define:

- name, domain, and operation;
- input and output schemas;
- risk category;
- scope and approval requirements;
- worker requirements;
- timeout;
- network policy;
- evidence policy;
- retry policy;
- audit events;
- fail-closed behavior.

Risk categories are:

```text
read_only
passive
active_low_risk
active_sensitive
dynamic_execution
destructive
prohibited
```

Destructive and prohibited tools must not run automatically.

## Worker architecture

Recommended worker classes are:

```text
static-analysis worker
browser worker
HTTP worker
mobile-analysis worker
Android emulator worker
iOS analysis worker
reverse-engineering worker
microVM dynamic-analysis worker
cloud-analysis worker
container-analysis worker
reporting worker
verification worker
```

Every worker must support registration, capability labels, health checks, leases, heartbeat, job claiming, cancellation, timeouts, resource limits, network controls, ephemeral workspace, output collection, evidence hashing, secure cleanup, and audit attribution. Sensitive workloads must not run in the API process.

## Scope and authorization

Scope enforcement is mandatory and model-independent. Support exact hostnames, domains, IP addresses, CIDR ranges, API endpoints, repositories, mobile package and application identifiers, cloud accounts, container registries, binary and firmware hashes, environment restrictions, test windows, credential permissions, exclusions, and prohibited actions.

Every tool call must be checked against engagement status, operator role, target scope, time window, risk, approval, worker trust level, network policy, and credential permissions.

## Approval engine

Approval workflows are required for active requests, authentication testing, dynamic execution, sensitive browser actions, credential use, state-changing requests, large-scale or rate-intensive operations, runtime instrumentation, binary execution, cloud changes, container runtime actions, and potentially destructive operations.

Approval records must include requesting actor, proposed action, exact target and arguments, risk, reason, expiration, approver, decision, timestamp, conditions, and resulting invocation. Approval must be cryptographically bound to the exact immutable request.

## Evidence system

Evidence is durable, content-addressed, and verifiable. Supported evidence includes HTTP exchanges, screenshots, browser traces, files, logs, scanner output, source references, binary and mobile analysis, cloud snapshots, container manifests, terminal transcripts from constrained workers, tool metadata, model reasoning summaries, operator notes, and validation results.

Every evidence item includes:

```text
SHA-256
byte size
MIME type
source tool
worker identifier
engagement identifier
target identifier
timestamp
operator or agent identity
storage location
integrity verification status
```

An unsupported model statement is never evidence.

## Finding lifecycle

```text
candidate
triaged
needs_validation
approval_required
validated
false_positive
duplicate
accepted_risk
remediation_in_progress
ready_for_retest
fixed
closed
```

Validated findings must include the affected target, technical description, impact, severity, confidence, reproduction summary, evidence links, verification result, remediation, references, operator review, and audit history.

## Multi-agent design

Specialist roles may include engagement orchestrator, web and API analysts, mobile static and runtime analysts, reverse-engineering analyst, source-code reviewer, cloud and container analysts, evidence verifier, finding reviewer, report writer, and remediation reviewer.

Each agent receives only necessary engagement context, allowed typed tools, scoped targets, approved credential references, relevant evidence, and role-specific instructions. Universal access is prohibited by default.

## Memory architecture

Separate engagement memory, target memory, operator preferences, validated knowledge, temporary working memory, domain knowledge, and tool execution history. Engagement data must not leak between customers. Hypotheses must remain distinguishable from validated facts. Credentials must not enter model memory.

## Operator surfaces

Provide a web console, keyboard-first TUI, and versioned API/SDK. Required workflows include workspace and engagement management, scope editing, target inventory, assessment plans, capability selection, tool queues, approvals, worker status, evidence browsing, finding lifecycle, retesting, reporting, auditing, diagnostics, export, authentication, role-based authorization, idempotency, pagination, rate limiting, and structured errors.

## Security boundary

Do not add:

```text
unrestricted shell execution
unscoped network scanning
credential harvesting or exfiltration
persistence
evasion or anti-forensics
destructive actions
autonomous exploitation
malware deployment
data theft
production disruption
self-propagating behaviour
```

Do not execute untrusted files on the host. Do not mount the Docker socket into untrusted workers. Do not expose cloud credentials to model context. Agents must not modify policy, approvals, audit records, or scope without explicit human authorization.

## Incremental build phases

1. **Core runtime:** extract reusable runtime, provider abstraction, typed registry, secure sessions, restricted defaults, structured logs, and tests.
2. **Security domain core:** workspaces, engagements, scope, targets, approvals, tools, jobs, workers, evidence, findings, reports, and audit logs.
3. **Web and API packs:** HTTP capture, crawling, schema ingestion, passive analysis, safe validation, evidence, and reports.
4. **Mobile and reverse engineering:** package ingestion, static analysis, binary analysis, emulator and microVM workers, and runtime evidence.
5. **Cloud, container, source code, and firmware:** modular capability packs, isolated workers, evidence, findings, and reports.
6. **Product experience:** web console, TUI, SDK, deployment, role-based access, diagnostics, backup, export, and migrations.
7. **Hardening and release:** threat model, policy and isolation tests, browser tests, dependency scanning, SBOM, provenance, container scanning, migrations, API contracts, smoke tests, release manifest, and signed artifacts.

## Engineering standards

Use typed schemas, explicit interfaces, modular capability packs, domain services, migrations, structured logs, deterministic serialization, content-addressed evidence, comprehensive tests, least privilege, secure defaults, and fail-closed behavior.

Avoid giant prompts as the control system, implicit authorization, arbitrary shell strings, hidden mutable state, unsandboxed execution, unvalidated plugins, model-generated policy changes, uncontrolled autonomous loops, and cross-engagement data mixing.

## Required deliverables

1. target architecture;
2. migration plan and retained/replaced component map;
3. domain model;
4. capability-pack interface;
5. typed tool contracts;
6. worker architecture;
7. policy and approval models;
8. evidence model;
9. finding lifecycle;
10. API, web console, and TUI designs;
11. security boundary and threat model;
12. implementation and test strategies;
13. deployment and release plans.

Do not describe the platform as complete until critical tests, migrations, isolation, evidence integrity, workflows, and release artifacts have been validated.

```text
a modular, policy-controlled, evidence-driven,
multi-domain authorized security assessment platform
with AI-assisted orchestration and isolated execution
```
