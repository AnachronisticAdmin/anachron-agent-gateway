// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

package assistants_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AnachronisticAdmin/anachron-agent-gateway/a2a"
	"github.com/AnachronisticAdmin/anachron-agent-gateway/assistants"
	"github.com/AnachronisticAdmin/anachron-agent-gateway/internal/acpfake"
	"github.com/AnachronisticAdmin/anachron-agent-gateway/redact"
)

func TestAmbiguousAndCrossTaskDecisionsStayPaused(t *testing.T) {
	a := newACPHarness(t, nil)
	first := a.send("", nil, a2a.TextPart("synthetic task one"))
	req := pendingRequest(t, first)
	second := a.send("", nil, a2a.TextPart("synthetic task two"))
	other := pendingRequest(t, second)
	paused := a.send(first.ID, nil, decision(other.RequestID, "selected", "allow-once"))
	if pendingRequest(t, paused).RequestID != req.RequestID {
		t.Fatal("another task's approval was accepted")
	}
	paused = a.send(first.ID, nil,
		decision(req.RequestID, "selected", "allow-once"),
		decision(req.RequestID, "selected", "reject"))
	if pendingRequest(t, paused).RequestID != req.RequestID {
		t.Fatal("ambiguous approval was accepted")
	}
	if _, err := os.Stat(filepath.Join(a.root, acpfake.OutputFile)); !os.IsNotExist(err) {
		t.Fatal("refused decisions changed the workspace")
	}
	done := a.send(first.ID, nil, decision(req.RequestID, "selected", "allow-once"))
	if done.Status.State != a2a.TaskStateCompleted {
		t.Fatal("valid single decision did not complete")
	}
}

func TestShortCredentialsAndUserHistoryAreRedacted(t *testing.T) {
	// A deliberately short, unissued synthetic value exercises strict known-
	// credential handling rather than provider-pattern recognition.
	const synthetic = "X!3"
	a := newACPHarness(t, func(c *assistants.ACPConfig) {
		c.MCPAllow = mcpAllow(t, "/opt/mcp/git")
	})
	task := a.send("", map[string]any{assistants.MetaMCPServers: []any{
		map[string]any{"name": "git", "command": "/opt/mcp/git", "env": []any{
			map[string]any{"name": "REPO_TOKEN", "value": synthetic}}},
	}}, a2a.TextPart("LEAK SPLIT synthetic input "+synthetic))
	req := pendingRequest(t, task)
	raw, _ := json.Marshal(task)
	if strings.Contains(string(raw), synthetic) || !strings.Contains(string(raw), redact.Mask) {
		t.Fatal("short credential appeared in paused task or initial history")
	}
	done := a.send(task.ID, nil, decision(req.RequestID, "selected", "allow-once"))
	raw, _ = json.Marshal(done)
	if strings.Contains(string(raw), synthetic) {
		t.Fatal("short credential appeared in completed task")
	}
}

func TestTaskCredentialRedactorsRemainIndependent(t *testing.T) {
	const one = "synthetic-task-one-credential"
	const two = "synthetic-task-two-credential"
	a := newACPHarness(t, func(c *assistants.ACPConfig) { c.MCPAllow = mcpAllow(t, "/opt/mcp/git") })
	meta := func(value string) map[string]any {
		return map[string]any{assistants.MetaMCPServers: []any{map[string]any{
			"name": "git", "command": "/opt/mcp/git", "env": []any{map[string]any{"name": "REPO_TOKEN", "value": value}},
		}}}
	}
	first := a.send("", meta(one), a2a.TextPart("LEAK "+one))
	pendingRequest(t, first)
	second := a.send("", meta(two), a2a.TextPart("LEAK "+one+" "+two))
	pendingRequest(t, second)
	raw, _ := json.Marshal(second)
	if strings.Contains(string(raw), two) || !strings.Contains(string(raw), one) {
		t.Fatal("task-local redactor leaked or mutated another task's values")
	}
}

func TestPassedEnvironmentCredentialsAreNotRetained(t *testing.T) {
	const synthetic = "synthetic-env-only-credential"
	a := newACPHarness(t, func(c *assistants.ACPConfig) {
		c.Env = append(c.Env, "SYNTHETIC_PROVIDER_TOKEN="+synthetic)
	})
	task := a.send("", nil, a2a.TextPart("synthetic prompt "+synthetic))
	pendingRequest(t, task)
	raw, _ := json.Marshal(task)
	if strings.Contains(string(raw), synthetic) {
		t.Fatal("passed environment credential retained in user history")
	}
}
