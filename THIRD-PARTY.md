# Third-party and build-input inventory

The module has no external Go module dependencies and no `require` or `replace` directive. The check script verifies the one-module closure with external module lookup disabled.

## Distributed material

- **First-party source:** Apache-2.0, with the complete text in `LICENSE` and attribution/modification notices in `NOTICE`.
- **Go notice:** The [Go BSD-3-Clause license](https://go.dev/LICENSE) is reproduced in `third_party/GO-LICENSE`; the toolchain and standard library are not vendored source.
- **No bundled providers/media tools:** No agent vendor binary, browser extension, desktop recorder, hosted backend or external A2A SDK is included.

## Build and validation inputs

The pinned baseline is Go 1.26.10; official toolchain metadata is provided by [Go downloads](https://go.dev/dl/?mode=json). The source SBOM records this build input rather than claiming to inventory a linked executable.

The standalone workflow references, but does not vendor, these MIT-licensed actions at reviewed immutable commits:

- **actions/checkout v7.0.1:** `3d3c42e5aac5ba805825da76410c181273ba90b1`; [release](https://github.com/actions/checkout/releases/tag/v7.0.1) and [license](https://github.com/actions/checkout/blob/main/LICENSE).
- **actions/setup-go v7.0.0:** `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e`; [release](https://github.com/actions/setup-go/releases/tag/v7.0.0) and [license](https://github.com/actions/setup-go/blob/main/LICENSE).

These action pins and the hosted runner image need ongoing review. They are not external dependencies in the Go application's module graph, and their transitive action/runner composition is not enumerated by the source-only inventory.

## Source inventory

`sbom.source.spdx.json` contains SPDX 2.3 source-file checksums and package metadata. Run `go run ./cmd/source-sbom -check sbom.source.spdx.json` to verify the selected module, recorded toolchain, file records and relationships.

The inventory excludes itself, `.git`, local `validation/` outputs and `bin/`; do not distribute those local directories as source artifacts. This is not a vulnerability, binary-composition or legal-clearance report; review additional notices/inventories before distributing binaries or adding dependencies.
