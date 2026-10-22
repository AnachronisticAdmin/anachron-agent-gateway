//go:build linux

// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

package assistants

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestOwnedProcessGroupTerminatesSyntheticDescendant(t *testing.T) {
	// Only an owned shell and sleep fixture are started. No external agent,
	// credentials, network, desktop permission or user process is touched.
	cmd := exec.Command("sh", "-c", `sleep 60 & child=$!; printf '%s\n' "$child"; wait`)
	ownGroup(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer killGroup(cmd)
	lines := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); lines <- line }()
	var child int
	select {
	case line := <-lines:
		child, err = strconv.Atoi(strings.TrimSpace(line))
		if err != nil || child <= 1 {
			t.Fatal("fixture did not report its owned child")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fixture startup stalled")
	}
	killGroup(cmd)
	waited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("direct child was not reaped")
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", child))
		if os.IsNotExist(err) {
			return
		}
		if err == nil {
			// A killed orphan can briefly be a zombie awaiting the container
			// init's reap. That is terminated, not a running descendant.
			end := strings.LastIndex(string(raw), ") ")
			if end >= 0 && len(raw) > end+2 && raw[end+2] == 'Z' {
				return
			}
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatal("owned descendant is still running")
		}
	}
}
