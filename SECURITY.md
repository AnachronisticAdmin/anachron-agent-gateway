# Security policy and boundary

Anachron Agent Gateway is an experimental source preview, not an accepted sandbox or production security product. There is no supported stable release, guaranteed response time, security SLA, bug-bounty commitment or claimed independent security certification.

## Confidential reporting

Do not put credentials, transcripts, recordings, private paths, unredacted support bundles or live exploit details into public issues or pull requests. A minimal synthetic reproduction is appropriate for an ordinary non-sensitive bug.

The intended confidential route for public source versions is GitHub private vulnerability reporting, which the maintainer enables and verifies as part of publication. This file cannot enable that service; the repository's actual settings and visible reporting control determine its availability.

On the repository's Security tab, open Advisories and use **Report a vulnerability** only when GitHub presents that private-reporting option. If the option is absent or fails, withhold sensitive details rather than using a public issue or pull request; no alternate mailbox or working confidential route is implied. Configuration guidance is in [GitHub's private-reporting documentation](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository).

## Implemented controls

- **Identity:** Explicit caller identity and tenant/owner checks for task reads, listing, followups and cancellation.
- **Permissions:** Session/request/option correlation, no free-text approvals, ambiguous-decision rejection and default refusal of durable-allow options.
- **MCP configuration:** Explicit target/transport admission, strict bounded parsing and credential-bearing message-metadata refusal.
- **Data handling:** Known-secret redaction, task-local redactors, conservative buffering and bounded/copied retained state.
- **Lifecycle:** Frame/queue limits, write-error closure, cancellation and owned Unix process-group cleanup.

The synthetic regression suite supports these narrow controls, not universal interoperability or resistance to hostile same-user executables. The identity callback, executable configuration and permission UI are trusted embedding components, and the program cannot replace a reviewed authentication boundary or an operating-system sandbox.

## Unsupported or incomplete assurances

- **Windows containment:** Only direct-child termination is implemented; job-object or equivalent descendant containment is not.
- **Native acceptance:** Cross-compilation does not validate macOS/Windows execution, permissions or native behavior.
- **Confidentiality:** Redaction is not a guarantee against every secret, derived value, private document or recording.
- **Durability:** In-memory records and paused decisions do not form a restart-safe session service or compliance audit trail.
- **Network/protocol:** No complete A2A wire/authentication service or general network-egress enforcement is supplied.

No provider installation, desktop capture, native input or hosted service is activated by the fixture. Review findings and the precise application threat model before using real agents or sensitive data.
