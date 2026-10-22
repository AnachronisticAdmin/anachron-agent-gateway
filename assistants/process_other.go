//go:build !(linux || darwin || freebsd || openbsd || netbsd || dragonfly)

// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

package assistants

import "os/exec"

// This fallback kills only the direct child. Windows job-object containment
// and descendant cleanup require a separate native implementation/review.
func ownGroup(cmd *exec.Cmd) {}
func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
