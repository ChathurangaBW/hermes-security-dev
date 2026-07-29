# Security Worker Contracts

## Purpose

The control plane authorizes typed requests. The worker-contract layer converts
an authorized request into an immutable job that a future dispatcher can hand to
an isolated runtime.

This layer performs no execution.

## Job construction

A job may be created only after the `TypedToolBroker` returns an allowed policy
decision. The builder resolves the tool definition from the trusted catalogue and
selects a centrally registered worker profile. The request cannot supply or
override the profile.

Every job records:

- engagement, request, and policy-decision identifiers;
- the request SHA-256 fingerprint;
- tool name and security domain;
- URL, artefact, device-session, or no-target binding;
- fully validated arguments with schema defaults materialized;
- approval identifier for validation-risk work;
- isolation type and least-privilege network policy;
- CPU, memory, and duration ceilings;
- read-only-root and non-privileged requirements;
- mandatory and optional evidence requirements;
- a deterministic job fingerprint.

## Fixed profiles

```text
web-passive       container  scope allowlist
web-active-safe   container  scope allowlist
web-validation    microVM    scope allowlist
mobile-static     container  network disabled
mobile-runtime    emulator   engagement proxy maximum
reverse-static    container  network disabled
reverse-runtime   microVM    network disabled
reporting         container  network disabled
```

Profiles describe the maximum capability. Job construction applies the
least-permissive validated request. For example, a mobile runtime request with
`network_mode=disabled` produces a network-disabled job even though the profile
can support an engagement proxy.

## Evidence contracts

Each profile has centrally defined evidence requirements. Examples include:

- HTTP transcripts for web work;
- artefact-analysis output for static mobile and reverse engineering;
- runtime traces and process metadata for isolated runtime observation;
- screenshots only when requested and permitted;
- a tool log for every profile;
- report output for reporting jobs.

Evidence artefacts carry a SHA-256 digest, media type, bounded size, relative
object key, capture time, and job ID. A sealed evidence manifest is bound to the
job fingerprint and has its own deterministic fingerprint.

## Audit contracts

Audit events are immutable and hashable. An event may reference the previous
event hash, forming an append-only chain across authorization, dispatch,
completion, failure, and evidence-recording transitions.

## Execution boundary still closed

This phase does not implement Docker, emulator, or microVM dispatch. It does not
run binaries, control devices, send network traffic, or execute shell commands.
The next phase must implement a dispatcher that accepts only these envelopes and
maps profile names to pinned runtime images and centrally controlled policies.
