# Authorized Web-App Pentest Architecture

## Operating rule

```text
The model proposes. Policy decides. Isolated workers execute.
Evidence proves. A human authorizes sensitive actions.
```

## Product boundary

This repository is being redeveloped into an authorized web-application
pentesting platform. It must not expose unrestricted shell execution,
credential-theft workflows, persistence, evasion, destructive actions,
unscoped network activity, autonomous exploitation, or blind payload execution.

## Control flow

```text
Operator UI / TUI / API
        ↓
Engagement and Scope Engine
        ↓
Policy / Approval Engine
        ↓
Agent Runtime
        ↓
Typed Tool Broker
        ↓
Isolated Docker/KVM Workers
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

The initial `hermes_security` package establishes a non-executing security
boundary before any pentest worker is connected.

It currently provides:

- engagement state and explicit HTTP(S) scope rules;
- canonical hostname, port, and path-prefix matching;
- typed Pydantic argument schemas with unknown fields rejected;
- a constrained initial tool catalogue;
- explicit denial of generic command-execution tools;
- risk classification for passive, active-safe, and validation actions;
- exact request-bound approval checks for validation actions;
- a broker that authorizes requests but intentionally cannot execute them.

## Deliberate omissions

No worker dispatch, browser integration, network request, shell command, finding
persistence, evidence storage, or report rendering is implemented in this
slice. Those capabilities must be added behind the engagement, policy, audit,
isolation, and evidence contracts rather than connected directly to the model.

## Next implementation slice

1. Add durable engagement, approval, tool-invocation, and audit-event storage.
2. Define an immutable worker job envelope containing engagement and policy
   decision identifiers.
3. Add an evidence manifest with content hashes and provenance metadata.
4. Integrate only passive tools with an isolated Docker worker.
5. Keep validation-risk tools disabled until approval persistence and microVM
   isolation are available.
