# Authorized Multi-Discipline Security Assessment Architecture

## Operating rule

```text
The model proposes. Policy decides. Isolated workers execute.
Evidence proves. A human authorizes sensitive actions.
```

## Product boundary

This repository is being redeveloped into an authorized security assessment
platform covering web applications and APIs, mobile applications, and reverse
engineering of operator-registered artefacts.

Broad capability does not mean unrestricted execution. The product must not
expose generic shell access, credential-theft workflows, persistence, evasion,
destructive actions, unscoped network activity, autonomous exploitation, or
blind payload execution.

## Supported security domains

### Web and API

Targets are explicit HTTP(S) scope rules containing scheme, canonical host,
port, path prefix, and optional subdomain inclusion. Initial typed operations
cover crawling, safe HTTP probing, header and TLS analysis, passive scanning,
read-only authenticated checks, and approval-gated finding validation.

### Mobile

Static analysis operates only on operator-registered APK, AAB, or IPA artefacts
identified by immutable SHA-256 hashes. Dynamic observation operates only on
registered Android or iOS device/emulator sessions and is classified as a
validation-risk action requiring exact human approval.

### Reverse engineering

Static analysis operates only on registered native binaries, managed
assemblies, firmware images, or explicitly registered mobile packages. Initial
operations cover format fingerprinting, strings, imports, control-flow analysis,
and function decompilation. Runtime observation is approval-gated, routed to a
separate high-isolation worker profile, time-limited, and network-disabled.

## Control flow

```text
Operator UI / TUI / API
        ↓
Engagement, Domain, and Target Registry
        ↓
Policy / Approval Engine
        ↓
Agent Runtime
        ↓
Typed Tool Broker
        ↓
Worker Profile Router
        ↓
Isolated Docker / Emulator / KVM Workers
        ↓
Evidence Store
        ↓
Verifier
        ↓
Finding Lifecycle
        ↓
Report Generator
```

## Phase 1 control-plane slice

The `agent.security` module establishes a non-executing security boundary before
any assessment worker is connected. It lives in the existing packaged agent
namespace but remains separate from the generic conversation loop and legacy
tool execution paths.

It currently provides:

- explicit engagement authorization for web, mobile, and reverse-engineering domains;
- canonical HTTP(S) scope matching for web targets;
- immutable, SHA-256-registered artefacts;
- operator-registered Android and iOS device sessions;
- typed Pydantic argument schemas with unknown fields rejected;
- target-kind enforcement for URLs, artefacts, device sessions, and non-targeted tools;
- artefact-kind and mobile-platform compatibility checks;
- constrained worker-profile selection defined by the tool catalogue;
- explicit denial of generic command-execution tools;
- risk classification for passive, active-safe, and validation actions;
- SHA-256 approval binding to the complete immutable request;
- a broker that authorizes requests but intentionally cannot execute them.

## Worker profiles

The model cannot choose an arbitrary runtime. Each registered tool maps to a
fixed profile such as:

```text
web-passive
web-active-safe
web-validation
mobile-static
mobile-runtime
reverse-static
reverse-runtime
reporting
```

Future dispatch code must resolve these profiles to centrally managed container,
emulator, or microVM specifications with fixed images, resource limits, mounts,
network policies, timeouts, and evidence collectors.

## Deliberate omissions

No worker dispatch, browser integration, network request, device control, binary
execution, shell command, finding persistence, evidence storage, or report
rendering is implemented in this slice. Those capabilities must be added behind
the engagement, policy, audit, isolation, and evidence contracts rather than
connected directly to the model.

## Next implementation slice

1. Add durable engagement, target, approval, invocation, and audit-event storage.
2. Define an immutable worker job envelope containing request fingerprint,
   engagement ID, policy decision ID, worker profile, resource limits, and
   evidence requirements.
3. Add an evidence manifest with content hashes and provenance metadata.
4. Integrate passive web, mobile-static, and reverse-static workers first.
5. Keep all validation-risk workers disabled until approval persistence and
   microVM/emulator isolation are available.
