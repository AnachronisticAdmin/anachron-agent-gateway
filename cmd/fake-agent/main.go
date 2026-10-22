// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

// Command fake-agent runs only the synthetic fixture. It installs no provider.
package main

import (
	"os"

	"github.com/AnachronisticAdmin/anachron-agent-gateway/internal/acpfake"
)

func main() { os.Exit(acpfake.Run(os.Stdin, os.Stdout, os.Stderr)) }
