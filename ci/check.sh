#!/bin/sh
set -eu
export GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
mkdir -p validation
go version
test -z "$(gofmt -l .)"
go list -m all > validation/modules.txt
test "$(wc -l < validation/modules.txt)" -eq 1
module=$(go list -m)
go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./... > validation/imports.txt
while IFS= read -r import; do
  case "$import" in ""|"$module"/*) ;; *) echo "foreign import: $import" >&2; exit 1 ;; esac
done < validation/imports.txt
go vet ./...
if ! go test -race -count=1 -timeout 120s -coverpkg=./... -coverprofile=validation/coverage.out ./... > validation/tests.log 2>&1; then
  cat validation/tests.log
  exit 1
fi
cat validation/tests.log
go tool cover -func=validation/coverage.out > validation/coverage.txt
tail -1 validation/coverage.txt
go build ./...
go run ./cmd/gateway-demo > validation/demo-deny.json
go run ./cmd/gateway-demo -allow-synthetic-write > validation/demo-allow.json
go run ./cmd/gateway-demo -cancel > validation/demo-cancel.json
cat validation/demo-deny.json validation/demo-allow.json validation/demo-cancel.json
go run ./cmd/source-sbom -check sbom.source.spdx.json
