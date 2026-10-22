# Source-preview validation

Executed October 22, 2026 on the independently renamed source preview, using Go 1.26.10 on Linux amd64 with a working C compiler. These are local synthetic checks, not a hosted GitHub run, native macOS/Windows acceptance, vendor authentication, public release or independent security sign-off.

## Reproduce

Use Go 1.26.10 and a working C compiler on the Linux amd64 baseline. From a clean checkout, run `sh ci/check.sh` and `sh ci/fuzz-and-targets.sh`; external module lookup and workspace discovery are disabled by these scripts.

The fake-agent examples exercise only owned temporary fixture data and require no provider credentials or native-media permission. A source-inventory check and a green test suite are not complete secret, vulnerability, privacy or legal audits.

## Observed local results

| Check | Observed result |
| --- | --- |
| Formatting, `go vet ./...`, builds and one-module closure | Passed; zero external Go module dependencies |
| Race-enabled JSON test run | 91 test/subtest pass events, zero skipped test events, zero failures |
| Aggregate statement coverage, including commands/fixtures | 77.6%; concurrent branch coverage can vary, and this is not a completeness or release-threshold claim |
| Decoder fuzzing, two workers, 10-second budget | Passed; 17,550 executions observed |
| MCP parser/admission fuzzing, two workers, 10-second budget | Passed; 233,849 executions observed |
| Independent directory with empty Go build/module caches and lookup disabled | Tests and source-inventory check passed |
| Synthetic denial, explicit one-time fixture approval and cancellation | Passed; expected file/state results and zero live sessions |
| Source inventory | 47 file records excluding the inventory itself, for 48 distributed source files |
| Inventory regressions | Changed/extra files, foreign module, symlink, metadata tampering, unknown fields and trailing JSON are rejected |
| Workflow syntax | `actionlint` v1.7.12 passed |
| Source secret scan | Gitleaks v8.30.1 reported no findings in the local working-directory scan |
| Vulnerability scan | `govulncheck` v1.1.4, source/symbol mode, reported zero findings with Go 1.26.10; database timestamp October 21, 2026, 00:27:29 UTC |

The exported toolchain pin was advanced from 1.26.9 after a module-level standard-library advisory result, without a Gateway symbol call trace. The advisory affects `crypto/x509.Certificate.Verify` and lists the fixed boundary as Go 1.26.10; the later scan used that patch ([GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809)).

## Target and fixture boundaries

Compilation passed for Linux amd64, macOS arm64, macOS amd64 and Windows amd64 with `CGO_ENABLED=0`. Linux is the only executed runtime; compilation does not establish native behavior or Windows process-tree containment.

The denial and cancellation demos do not create the fixture file, while explicit approval creates only the owned temporary fixture. No provider account, real credential, desktop media, native input or deployment is used.

The source-SBOM check validates the declared module, recorded toolchain, file records and relationships; it is not a signed provenance attestation. Scanner results are limited observations, not a guarantee against all secrets, vulnerabilities or private content, and source-only composition is not a complete binary inventory.

## Remaining release gates

Hosted CI has not run, a confidential public reporting route is not yet configured and independent technical/privacy review is outstanding. No repository, public source upload, release tag or binary release is created by these local checks; approval of the exact public payload remains separate.
