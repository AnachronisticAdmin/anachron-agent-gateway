//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

package assistants

import (
	"os/exec"
	"syscall"
)

func ownGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Kill()
	}
}
