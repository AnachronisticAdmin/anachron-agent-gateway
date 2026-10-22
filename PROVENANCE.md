# Source provenance

Anachron Agent Gateway is an independently buildable extraction and adaptation of owned ACP, MCP configuration and redaction code, maintained by Julian Wiley. The distributed first-party source is provided under Apache-2.0, with relevant copyright and modification notices preserved in files and `NOTICE`.

## Adaptation

- **Transport and lifecycle:** Added bounded frames/queues, write-failure closure, shutdown registration checks and owned Unix process-group cleanup.
- **Permission handling:** Hardened correlation and rejection of stale, ambiguous, malformed or duplicate decisions.
- **Privacy:** Added strict known-credential masking, task-local secret handling, retained-history sanitization and conservative output buffering.
- **Host:** Added a small in-process model/facade with explicit authenticated identity input, tenant/owner checks and bounded snapshots.
- **Fixtures:** Adapted tests and an owned fake subprocess, plus a denial/approval/cancellation demonstration with temporary generated data.
- **Standalone packaging:** Rebased imports to the selected GitHub module path, replaced environment-specific policy material and added standalone checks and a source-inventory tool.

The source inventory describes the distributed tree; confidential source-history and authorization records are not distributed as build inputs. This repository contains no copied production authentication/persistence implementation, customer runtime data, real credentials, agent vendor binary, recorder or desktop-media implementation.

## Limits of provenance

The small `a2a` contract is not a full A2A protocol implementation, and named profiles are configuration descriptors rather than provider-conformance evidence. A source inventory is not a binary-composition, vulnerability, security or legal-clearance certificate.
