# Contributing to Anachron Agent Gateway

Julian Wiley is the designated maintainer and acceptance authority for this experimental source preview. When the repository's public contribution surface is available, discuss non-sensitive behavior changes with the maintainer before a large change and follow [SECURITY.md](SECURITY.md) for sensitive reports; no external reviewer, guaranteed response time or support agreement is implied.

## Local checks

Use the pinned Go 1.26.10 toolchain and a working C compiler for race testing. From the repository root:

```sh
export GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
go run ./cmd/source-sbom
sh ci/check.sh
sh ci/fuzz-and-targets.sh
```

Regenerate the source inventory after changing any distributed file, then review the inventory diff rather than treating regeneration as approval. The checker verifies module/package metadata, file records and relationships as well as checksums.

## Change expectations

- **Boundaries:** Keep the independent module and explicit host authentication contract; do not turn metadata or model-generated prose into authority.
- **Regression evidence:** Add negative permission, identity, cancellation, parser-limit and credential-retention cases for behavioral changes.
- **Dependencies:** Keep the zero-external-module boundary unless a dependency and its license/notice/inventory effects receive review.
- **Fixtures:** Use generated, unissued credentials and temporary directories. Do not attach real account data, recordings, transcripts or credentials.
- **Claims:** Distinguish executed runtime checks from compilation and configuration hints. Do not imply native containment, full A2A interoperability or installed vendors without evidence.
- **Scope:** Native-media capture, persistence, provider authentication and deployment need their own design and review.

## License and contribution terms

The source is provided under Apache-2.0 with notices in `NOTICE`. Section 5 of that license addresses contributions intentionally submitted for inclusion unless explicitly stated otherwise; no separate CLA or DCO agreement is introduced by this file ([Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)).

Only submit material you have authority to contribute. A pull request does not authorize unrelated source publication, private data disclosure, deployment or privileged access.
