#!/bin/sh
set -eu
export GOWORK=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
go test -run '^$' -fuzz '^FuzzDecoder$' -fuzztime 10s -parallel 2 ./acp
go test -run '^$' -fuzz '^FuzzMCPServers$' -fuzztime 10s -parallel 2 ./assistants
for target in linux/amd64 darwin/arm64 darwin/amd64 windows/amd64; do
  os=${target%/*}
  arch=${target#*/}
  echo "Compilation only: $target"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build ./...
done
