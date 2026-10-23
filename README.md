# Anachron Agent Gateway

An experimental Go execution core for embedding ACP-speaking agents with request-bound approval decisions, explicit MCP configuration admission, cancellation and credential-aware redaction. Maintained by Julian Wiley under Apache-2.0, this source preview includes an in-process host and a synthetic agent fixture, not a production agent service.

## Status

This is an experimental source preview for module path `github.com/AnachronisticAdmin/anachron-agent-gateway`, with a maintainer-led acceptance workflow and no stable API or production-support guarantee. Repository tags, releases and revision-specific workflow results are the publication/evidence records; this file alone does not establish that a particular version has been published or passed CI.

See [VALIDATION.md](VALIDATION.md) for the executed Linux baseline and hosted evidence, and [SECURITY.md](SECURITY.md) for conditional confidential-reporting instructions and security limits. No independent security audit or certification is claimed.

## What is included

- **ACP transport:** Bounded newline-delimited JSON-RPC framing, request correlation, cancellation and backpressure failure.
- **Approval bridge:** Typed requests and decisions correlated to the caller, task, session, request and offered option; ambiguous, stale and free-text approvals do not authorize actions.
- **MCP admission:** Explicit stdio command or HTTP URL admission, strict parsing, credential-aware redaction and refusal of credential-bearing message metadata.
- **Host facade:** Explicit identity, tenant/owner checks, copied bounded task snapshots and no persistence.
- **Synthetic demo:** A local fake subprocess that writes one temporary fixture file only after an explicit synthetic approval.

The `a2a` package is deliberately A2A-shaped, not a complete A2A schema, transport, SDK or conformance claim. There is no HTTP/gRPC/SSE listener, authentication service, push endpoint, production database, provider installation or desktop-media integration.

## Try the fixture

Install Go 1.26.10, the pinned validation toolchain. No real provider credentials, accounts, recordings, native permissions or external modules are needed; the race-enabled checks additionally require a working C compiler.

From the source directory:

```sh
export GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
go run ./cmd/gateway-demo
go run ./cmd/gateway-demo -allow-synthetic-write
go run ./cmd/gateway-demo -cancel
```

The first command denies the action, the second permits only the fake agent's temporary-file write and the third cancels while paused. Each command checks its result, reports zero live sessions after the decision and removes its temporary workspace.

Run the full local checks and the separate bounded fuzz/compilation checks:

```sh
sh ci/check.sh
sh ci/fuzz-and-targets.sh
```

The checked-in GitHub workflow uses the same scripts. [The original source baseline passed both hosted jobs](https://github.com/AnachronisticAdmin/anachron-agent-gateway/actions/runs/39862889659); a prior green run does not prove that a different revision passed, so check the exact commit or tag's workflow result.

## Embedding

- **Authenticate first:** Supply `server.WithPrincipal(ctx, server.Principal{ID: verifiedID, Tenant: verifiedTenant})` only after authenticating the caller, or supply a reviewed `server.Options.Identity` callback. Message metadata is not authoritative identity.
- **Trust configuration explicitly:** Choose the executable, work directory and MCP allowlist as privileged operator configuration. The core runs that executable with the host user's authority; an allowlist is not an operating-system sandbox.
- **Show the real decision:** Render the offered operation and option; send the typed correlated decision, not a prose interpretation or automatically generated approval.
- **Own shutdown:** Close the host/executor and handle cancellation. An embedding application's authentication, transport, persistence, audit and deployment controls remain its responsibility.

The source packages are `acp`, `assistants`, `redact`, `server` and `a2a`. The `internal/acpfake` package is an owned test fixture rather than a real provider integration.

## Important limits

- **Not a sandbox:** Work-directory checks, permission prompts and environment filtering do not confine hostile same-user code, filesystem access, network egress or arbitrary subprocesses.
- **Platform coverage:** Linux is the executed baseline. macOS/Windows compilation is not native acceptance; the Windows/other fallback kills only the direct child, not a contained process tree.
- **Buffered text:** Output is buffered in segments up to 64 KiB before redaction; an oversized segment is withheld. Token-by-token live streaming is not promised.
- **Bounded resources:** Frames are capped at 1 MiB and event/outgoing queues are bounded. The host defaults to 128 tasks, 32 history entries, 64 KiB messages/metadata and 16 bounded artifacts; capacity exhaustion rejects work.
- **Ephemeral state:** Tasks, sessions and decisions are not restart-durable or a compliance audit store. Paused-agent exit is observed on interaction, cancellation or cleanup, not via an implemented push service.
- **Provider scope:** Named profiles are configuration hints, not proof of installation, authentication, compatibility or endorsement. Only the included fake agent is exercised.
- **Redaction scope:** Known credential literals and common token patterns are masked; derived secrets, arbitrary private content and all personally identifying data are not guaranteed to be removed.

## Project material

Read [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), [PROVENANCE.md](PROVENANCE.md), [THIRD-PARTY.md](THIRD-PARTY.md), [CHANGELOG.md](CHANGELOG.md) and [ROADMAP.md](ROADMAP.md). The license is in [LICENSE](LICENSE), attribution is in [NOTICE](NOTICE), and [sbom.source.spdx.json](sbom.source.spdx.json) inventories this source tree rather than a release binary.
