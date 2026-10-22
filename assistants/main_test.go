// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

package assistants_test

import (
	"os"
	"testing"

	"github.com/AnachronisticAdmin/anachron-agent-gateway/internal/acpfake"
)

func TestMain(m *testing.M) {
	if os.Getenv("ACP_FAKE_AGENT") == "1" {
		os.Exit(acpfake.Run(os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}
