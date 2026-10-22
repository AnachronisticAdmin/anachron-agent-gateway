// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0
// Derived from the owner-approved snapshot; modified for the standalone candidate.
// See PROVENANCE.md for source and intentional behavior changes.

package assistants_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AnachronisticAdmin/anachron-agent-gateway/a2a"
	"github.com/AnachronisticAdmin/anachron-agent-gateway/assistants"
	"github.com/AnachronisticAdmin/anachron-agent-gateway/internal/acpfake"
	"github.com/AnachronisticAdmin/anachron-agent-gateway/redact"
	"github.com/AnachronisticAdmin/anachron-agent-gateway/server"
)

// acpHarness serves the fake ACP agent (this test binary, re-executed with
// ACP_FAKE_AGENT=1) through the new in-process host facade, not an A2A HTTP server.
type acpHarness struct {
	t    *testing.T
	exec *assistants.ACPExecutor
	h    *server.Handler
	root string
	n    int
}

func newACPHarness(t *testing.T, mutate func(*assistants.ACPConfig)) *acpHarness {
	t.Helper()
	t.Setenv("ACP_FAKE_AGENT", "1")
	root := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	cfg := assistants.ACPConfig{Name: "fake-acp", DisplayName: "Fake ACP agent", Command: []string{os.Args[0], "-test.run=^$"},
		Env: []string{"ACP_FAKE_AGENT=1"}, WorkDir: root, WorkDirRoot: root,
		Redactor: redact.New(), StartTimeout: 10 * time.Second}
	if mutate != nil {
		mutate(&cfg)
	}
	e, err := assistants.NewACPExecutor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := server.NewHandler(e, server.Options{Card: assistants.ACPCard(cfg, nil), TaskTimeout: 30 * time.Second,
		Identity: func(context.Context) (server.Principal, error) {
			return server.Principal{ID: "synthetic-user", Tenant: "synthetic-tenant"}, nil
		}})
	t.Cleanup(func() { h.Close(); _ = e.Close() })
	return &acpHarness{t: t, exec: e, h: h, root: root}
}

func (a *acpHarness) send(taskID string, meta map[string]any, parts ...a2a.Part) *a2a.Task {
	a.t.Helper()
	a.n++
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := a.h.SendMessage(ctx, &a2a.SendMessageRequest{Metadata: meta, Message: &a2a.Message{
		MessageID: "m-" + strings.ReplaceAll(a.t.Name(), "/", "-") + "-" + string(rune('a'+a.n)), TaskID: taskID, Role: a2a.RoleUser, Parts: parts}})
	if err != nil {
		a.t.Fatalf("send: %v", err)
	}
	if res.Task == nil {
		a.t.Fatalf("expected a task, got %+v", res)
	}
	return res.Task
}

func (a *acpHarness) workTree(name string) string {
	dir := filepath.Join(a.root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		a.t.Fatal(err)
	}
	return dir
}

type permissionRequest struct {
	Type      string `json:"type"`
	RequestID string `json:"requestId"`
	ToolName  string `json:"toolName"`
	Kind      string `json:"kind"`
	RawInput  struct {
		Command string `json:"command"`
	} `json:"rawInput"`
	Options []struct {
		OptionID string `json:"optionId"`
		Kind     string `json:"kind"`
	} `json:"options"`
}

func pendingRequest(t *testing.T, task *a2a.Task) permissionRequest {
	t.Helper()
	if task.Status.State != a2a.TaskStateInputRequired || task.Status.Message == nil {
		t.Fatalf("task is %s, want input required: %+v", task.Status.State, task.Status.Message)
	}
	for _, p := range task.Status.Message.Parts {
		var req permissionRequest
		if len(p.Data) > 0 && json.Unmarshal(p.Data, &req) == nil && req.Type == assistants.DataPermissionRequest {
			return req
		}
	}
	t.Fatalf("no permission request data part in %+v", task.Status.Message)
	return permissionRequest{}
}

func decision(requestID, outcome, option string) a2a.Part {
	return a2a.DataPart(map[string]any{"type": assistants.DataPermissionDecision, "requestId": requestID, "outcome": outcome, "optionId": option})
}

func TestACPPermissionRoundTripCompletesWithUsage(t *testing.T) {
	a := newACPHarness(t, nil)
	wt := a.workTree("engagement/run-1")
	task := a.send("", map[string]any{assistants.MetaWorkDir: wt}, a2a.TextPart("Add a note file"))
	req := pendingRequest(t, task)
	if req.ToolName != "Bash" || req.Kind != "execute" || req.RawInput.Command != "git status --short" || len(req.Options) != 3 {
		t.Fatalf("permission request: %+v", req)
	}
	if task.Metadata[assistants.WorkDirMetadataKey] != wt {
		t.Fatalf("workdir metadata: %v", task.Metadata)
	}
	if a.exec.LiveSessions() != 1 {
		t.Fatal("the agent session must stay alive while the task waits for a decision")
	}
	done := a.send(task.ID, nil, decision(req.RequestID, "selected", "allow-once"))
	if done.Status.State != a2a.TaskStateCompleted {
		t.Fatalf("final state %s: %+v", done.Status.State, done.Status.Message)
	}
	if _, err := os.Stat(filepath.Join(wt, acpfake.OutputFile)); err != nil {
		t.Fatalf("agent did not work in the task directory: %v", err)
	}
	usage, _ := done.Metadata[assistants.UsageMetadataKey].(map[string]any)
	if usage["inputTokens"] != float64(1200) && usage["inputTokens"] != int64(1200) || usage["costUsd"] != 0.0421 {
		t.Fatalf("usage metadata: %#v", usage)
	}
	toolEvents := 0
	for _, m := range done.History {
		for _, p := range m.Parts {
			if strings.Contains(string(p.Data), assistants.DataToolCall) {
				toolEvents++
			}
		}
	}
	if toolEvents < 2 {
		t.Fatalf("tool calls were not reported as status updates (%d)", toolEvents)
	}
	if a.exec.LiveSessions() != 0 {
		t.Fatal("the agent process must stop when the turn ends")
	}
}

func TestACPRejectedPermissionMakesNoChanges(t *testing.T) {
	a := newACPHarness(t, nil)
	wt := a.workTree("run-deny")
	task := a.send("", map[string]any{assistants.MetaWorkDir: wt}, a2a.TextPart("Add a note file"))
	req := pendingRequest(t, task)
	done := a.send(task.ID, nil, decision(req.RequestID, "selected", "reject"))
	if done.Status.State != a2a.TaskStateCompleted {
		t.Fatalf("state %s", done.Status.State)
	}
	if _, err := os.Stat(filepath.Join(wt, acpfake.OutputFile)); !os.IsNotExist(err) {
		t.Fatal("a rejected permission must not lead to changes")
	}
}

func TestACPDecisionsAreBoundToTheOfferedRequest(t *testing.T) {
	a := newACPHarness(t, nil)
	task := a.send("", nil, a2a.TextPart("Add a note file"))
	req := pendingRequest(t, task)
	for name, reply := range map[string]a2a.Part{
		"durable allow":   decision(req.RequestID, "selected", "allow-with-updates"),
		"unknown request": decision(req.RequestID+"-other", "selected", "allow-once"),
		"unknown option":  decision(req.RequestID, "selected", "allow-everything"),
		"free text":       a2a.TextPart("yes please"),
	} {
		task = a.send(task.ID, nil, reply)
		again := pendingRequest(t, task)
		if again.RequestID != req.RequestID || !strings.Contains(task.Status.Message.Text(), "Reply not accepted") {
			t.Fatalf("%s: reply was not refused: %+v", name, task.Status.Message)
		}
	}
	done := a.send(task.ID, nil, decision(req.RequestID, "selected", "allow-once"))
	if done.Status.State != a2a.TaskStateCompleted {
		t.Fatalf("valid decision after refusals: %s", done.Status.State)
	}
}

func TestACPSecondPermissionPausesAgain(t *testing.T) {
	a := newACPHarness(t, nil)
	task := a.send("", nil, a2a.TextPart("TWO_APPROVALS please"))
	first := pendingRequest(t, task)
	task = a.send(task.ID, nil, decision(first.RequestID, "selected", "allow-once"))
	second := pendingRequest(t, task)
	if second.RequestID == first.RequestID || second.ToolName != "Write" {
		t.Fatalf("second request: %+v", second)
	}
	done := a.send(task.ID, nil, decision(second.RequestID, "selected", "allow-once"))
	if done.Status.State != a2a.TaskStateCompleted {
		t.Fatalf("state %s", done.Status.State)
	}
}

func TestACPCancelWhilePausedStopsTheAgent(t *testing.T) {
	a := newACPHarness(t, nil)
	task := a.send("", nil, a2a.TextPart("Add a note file"))
	pendingRequest(t, task)
	canceled, err := a.h.CancelTask(context.Background(), &a2a.CancelTaskRequest{ID: task.ID})
	if err != nil || canceled.Status.State != a2a.TaskStateCanceled {
		t.Fatalf("cancel: %v %+v", err, canceled)
	}
	if a.exec.LiveSessions() != 0 {
		t.Fatal("cancel must stop the paused agent process")
	}
	if _, err := os.Stat(filepath.Join(a.root, acpfake.OutputFile)); !os.IsNotExist(err) {
		t.Fatal("cancelled task changed the workspace")
	}
}

func TestACPAgentCrashFailsTheTask(t *testing.T) {
	a := newACPHarness(t, nil)
	task := a.send("", nil, a2a.TextPart("CRASH after asking"))
	req := pendingRequest(t, task)
	done := a.send(task.ID, nil, decision(req.RequestID, "selected", "allow-once"))
	if done.Status.State != a2a.TaskStateFailed || !strings.Contains(done.Status.Message.Text(), "exited before the turn ended") {
		t.Fatalf("crash: %s %+v", done.Status.State, done.Status.Message)
	}
}

func TestACPWorkDirMustStayInsideRoot(t *testing.T) {
	a := newACPHarness(t, nil)
	outside := t.TempDir()
	for _, dir := range []string{outside, a.root, filepath.Join(a.root, "missing"), "relative/path"} {
		task := a.send("", map[string]any{assistants.MetaWorkDir: dir}, a2a.TextPart("hi"))
		if task.Status.State != a2a.TaskStateRejected {
			t.Fatalf("%s: state %s", dir, task.Status.State)
		}
	}
	link := filepath.Join(a.root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if task := a.send("", map[string]any{assistants.MetaWorkDir: link}, a2a.TextPart("hi")); task.Status.State != a2a.TaskStateRejected {
		t.Fatalf("symlink escape: %s", task.Status.State)
	}
	if task := a.send("", map[string]any{assistants.MetaPermissionMode: "bypassPermissions"}, a2a.TextPart("hi")); task.Status.State != a2a.TaskStateRejected {
		t.Fatalf("bypass mode must be refused: %s", task.Status.State)
	}
	noRoot := newACPHarness(t, func(c *assistants.ACPConfig) { c.WorkDirRoot = "" })
	if task := noRoot.send("", map[string]any{assistants.MetaWorkDir: noRoot.workTree("x")}, a2a.TextPart("hi")); task.Status.State != a2a.TaskStateRejected {
		t.Fatalf("per-task directories without a root: %s", task.Status.State)
	}
}

func TestACPToleratesStdoutNoise(t *testing.T) {
	a := newACPHarness(t, nil)
	task := a.send("", nil, a2a.TextPart("NOISE then work"))
	req := pendingRequest(t, task)
	if done := a.send(task.ID, nil, decision(req.RequestID, "cancelled", "")); done.Status.State != a2a.TaskStateFailed {
		// A cancelled permission ends the fake agent's turn as cancelled.
		t.Fatalf("state %s", done.Status.State)
	}
}

func TestACPExecutorRequiresCommand(t *testing.T) {
	if _, err := assistants.NewACPExecutor(assistants.ACPConfig{}); err == nil {
		t.Fatal("missing agent command must be rejected")
	}
	meta := assistants.ClaudeSessionMeta()["claudeCode"].(map[string]any)["options"].(map[string]any)
	if sources := meta["settingSources"].([]string); len(sources) != 0 {
		t.Fatal("Claude sessions must not load personal allow rules")
	}
}

// capturingHarness makes the fake agent record its argv, environment and
// session/new parameters.
func capturingHarness(t *testing.T, mutate func(*assistants.ACPConfig)) (*acpHarness, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "capture.jsonl")
	a := newACPHarness(t, func(c *assistants.ACPConfig) {
		c.Env = append(c.Env, "ACP_FAKE_CAPTURE="+path)
		if mutate != nil {
			mutate(c)
		}
	})
	return a, path
}

func onlyCapture(t *testing.T, path string) acpfake.Capture {
	t.Helper()
	caps, err := acpfake.ReadCaptures(path)
	if err != nil || len(caps) != 1 {
		t.Fatalf("captures: %d %v", len(caps), err)
	}
	return caps[0]
}

const mcpSecret = "mcp-credential-0123456789"

func mcpAllow(t *testing.T, entries ...string) *assistants.MCPAllowlist {
	t.Helper()
	l, err := assistants.ParseMCPAllowlist(entries)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestACPPassesAllowedMCPServersToSessionNew(t *testing.T) {
	a, path := capturingHarness(t, func(c *assistants.ACPConfig) {
		c.MCPAllow = mcpAllow(t, "git=/opt/mcp/git", "https://mcp.example.com/tools/")
	})
	servers := []any{
		map[string]any{"name": "git", "command": "/opt/mcp/git", "args": []any{"--repo", "."},
			"env": []any{map[string]any{"name": "REPO_TOKEN", "value": mcpSecret}}},
		map[string]any{"type": "http", "name": "jira", "url": "https://mcp.example.com/tools/jira",
			"headers": []any{map[string]any{"name": "Authorization", "value": "Bearer " + mcpSecret}}},
	}
	task := a.send("", map[string]any{assistants.MetaMCPServers: servers}, a2a.TextPart("Add a note file"))
	req := pendingRequest(t, task)
	var sessionNew struct {
		MCPServers []map[string]any `json:"mcpServers"`
		Meta       map[string]any   `json:"_meta"`
	}
	if err := json.Unmarshal(onlyCapture(t, path).SessionNew, &sessionNew); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(sessionNew.MCPServers)
	want := `[{"args":["--repo","."],"command":"/opt/mcp/git","env":[{"name":"REPO_TOKEN","value":"` + mcpSecret + `"}],"name":"git"},` +
		`{"headers":[{"name":"Authorization","value":"Bearer ` + mcpSecret + `"}],"name":"jira","type":"http","url":"https://mcp.example.com/tools/jira"}]`
	if string(got) != want {
		t.Fatalf("session/new mcpServers:\n got %s\nwant %s", got, want)
	}
	if sessionNew.Meta != nil {
		t.Fatalf("no session meta was configured: %v", sessionNew.Meta)
	}
	attached, _ := json.Marshal(task.Metadata[assistants.MCPServersMetadataKey])
	if strings.Contains(string(attached), mcpSecret) || !strings.Contains(string(attached), `"allowedBy":"https://mcp.example.com/tools/"`) ||
		!strings.Contains(string(attached), `"allowedBy":"git=/opt/mcp/git"`) {
		t.Fatalf("task metadata must list servers without credentials: %s", attached)
	}
	if done := a.send(task.ID, nil, decision(req.RequestID, "selected", "allow-once")); done.Status.State != a2a.TaskStateCompleted {
		t.Fatalf("state %s", done.Status.State)
	}
}

func TestACPRefusesDisallowedMCPServersBeforeStarting(t *testing.T) {
	allowed := map[string]any{"name": "git", "command": "/opt/mcp/git"}
	for name, tc := range map[string]struct {
		allow   []string
		servers []any
		want    string
	}{
		"passthrough disabled": {nil, []any{allowed}, "-mcp-allow"},
		"one of two refused": {[]string{"/opt/mcp/git"}, []any{allowed,
			map[string]any{"name": "shell", "command": "/bin/sh", "env": []any{map[string]any{"name": "TOKEN", "value": mcpSecret}}}}, `"shell" refused`},
		"name binding": {[]string{"git=/opt/mcp/git"}, []any{map[string]any{"name": "other", "command": "/opt/mcp/git"}}, `"other" refused`},
		"url outside prefix": {[]string{"https://mcp.example.com/tools/"}, []any{map[string]any{"type": "http", "name": "x",
			"url": "https://mcp.example.com/admin?token=" + mcpSecret}}, "no -mcp-allow entry covers this URL on https://mcp.example.com"},
		"malformed":  {[]string{"/opt/mcp/git"}, []any{map[string]any{"name": "git", "command": "git"}}, "clean absolute path"},
		"not a list": {[]string{"/opt/mcp/git"}, nil, "must be an array"},
	} {
		t.Run(name, func(t *testing.T) {
			a, path := capturingHarness(t, func(c *assistants.ACPConfig) {
				if tc.allow != nil {
					c.MCPAllow = mcpAllow(t, tc.allow...)
				}
			})
			var value any = tc.servers
			if tc.servers == nil {
				value = "git"
			}
			task := a.send("", map[string]any{assistants.MetaMCPServers: value}, a2a.TextPart("Add a note file"))
			text := ""
			if task.Status.Message != nil {
				text = task.Status.Message.Text()
			}
			if task.Status.State != a2a.TaskStateRejected || !strings.Contains(text, tc.want) {
				t.Fatalf("state %s: %q (want %q)", task.Status.State, text, tc.want)
			}
			if strings.Contains(text, mcpSecret) {
				t.Fatalf("refusal leaks a credential: %q", text)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("the agent must not start when any MCP server is refused")
			}
			if a.exec.LiveSessions() != 0 {
				t.Fatal("no session may remain")
			}
		})
	}
}

func TestACPRefusesMCPServersInMessageMetadataBeforeStoring(t *testing.T) {
	a, path := capturingHarness(t, func(c *assistants.ACPConfig) { c.MCPAllow = mcpAllow(t, "/opt/mcp/git") })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	servers := []any{map[string]any{"name": "git", "command": "/opt/mcp/git", "env": []any{map[string]any{"name": "REPO_TOKEN", "value": mcpSecret}}}}
	_, err := a.h.SendMessage(ctx, &a2a.SendMessageRequest{Message: &a2a.Message{MessageID: "m-msg-meta", Role: a2a.RoleUser,
		Parts: []a2a.Part{a2a.TextPart("hi")}, Metadata: map[string]any{assistants.MetaMCPServers: servers}}})
	if e := a2a.AsError(err); e == nil || e.Code != a2a.ErrInvalidParams.Code || !strings.Contains(e.Message, "request metadata") {
		t.Fatalf("want invalid params, got %v", err)
	}
	list, err := a.h.ListTasks(ctx, &a2a.ListTasksRequest{})
	if err != nil || len(list.Tasks) != 0 {
		t.Fatalf("a refused message must leave no task (and no stored credential): %v %+v", err, list)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("agent started")
	}
	// Follow-up messages are checked too.
	task := a.send("", nil, a2a.TextPart("Add a note file"))
	req := pendingRequest(t, task)
	_, err = a.h.SendMessage(ctx, &a2a.SendMessageRequest{Message: &a2a.Message{MessageID: "m-msg-meta-2", TaskID: task.ID, Role: a2a.RoleUser,
		Parts: []a2a.Part{decision(req.RequestID, "selected", "allow-once")}, Metadata: map[string]any{assistants.MetaMCPServers: servers}}})
	if a2a.AsError(err) == nil {
		t.Fatal("follow-up with MCP servers in message metadata accepted")
	}
	got, err := a.h.GetTask(ctx, &a2a.GetTaskRequest{ID: task.ID})
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(got); strings.Contains(string(raw), mcpSecret) {
		t.Fatal("credential stored in task history")
	}
}

func TestACPRefusesMCPServersOnFollowUps(t *testing.T) {
	a := newACPHarness(t, func(c *assistants.ACPConfig) { c.MCPAllow = mcpAllow(t, "/opt/mcp/git") })
	task := a.send("", nil, a2a.TextPart("Add a note file"))
	req := pendingRequest(t, task)
	task = a.send(task.ID, map[string]any{assistants.MetaMCPServers: []any{map[string]any{"name": "git", "command": "/opt/mcp/git"}}},
		decision(req.RequestID, "selected", "allow-once"))
	if again := pendingRequest(t, task); again.RequestID != req.RequestID || !strings.Contains(task.Status.Message.Text(), "only read when a task starts") {
		t.Fatalf("follow-up with MCP servers was not refused: %+v", task.Status.Message)
	}
	if done := a.send(task.ID, nil, decision(req.RequestID, "selected", "allow-once")); done.Status.State != a2a.TaskStateCompleted {
		t.Fatalf("state %s", done.Status.State)
	}
}

func TestACPRefusesHTTPMCPWhenTheAgentLacksSupport(t *testing.T) {
	a, _ := capturingHarness(t, func(c *assistants.ACPConfig) {
		c.Env = append(c.Env, "ACP_FAKE_NO_HTTP_MCP=1")
		c.MCPAllow = mcpAllow(t, "https://mcp.example.com/")
	})
	task := a.send("", map[string]any{assistants.MetaMCPServers: []any{map[string]any{"type": "http", "name": "jira", "url": "https://mcp.example.com/jira"}}},
		a2a.TextPart("hi"))
	if task.Status.State != a2a.TaskStateFailed || !strings.Contains(task.Status.Message.Text(), "does not support HTTP MCP servers") {
		t.Fatalf("state %s: %+v", task.Status.State, task.Status.Message)
	}
	if a.exec.LiveSessions() != 0 {
		t.Fatal("the agent must be stopped")
	}
}

func TestACPMasksMCPCredentialsInAgentOutput(t *testing.T) {
	a := newACPHarness(t, func(c *assistants.ACPConfig) { c.MCPAllow = mcpAllow(t, "/opt/mcp/git") })
	task := a.send("", map[string]any{assistants.MetaMCPServers: []any{map[string]any{"name": "git", "command": "/opt/mcp/git",
		"env": []any{map[string]any{"name": "REPO_TOKEN", "value": mcpSecret}}}}}, a2a.TextPart("LEAK the credentials"))
	req := pendingRequest(t, task)
	done := a.send(task.ID, nil, decision(req.RequestID, "selected", "allow-once"))
	raw, _ := json.Marshal(done)
	if strings.Contains(string(raw), mcpSecret) || !strings.Contains(string(raw), redact.Mask) {
		t.Fatalf("MCP credential not masked: %s", raw)
	}
	// A credential streamed across chunks is masked while the task is paused
	// (before the turn ends) and in the stored answer.
	task = a.send("", map[string]any{assistants.MetaMCPServers: []any{map[string]any{"name": "git", "command": "/opt/mcp/git",
		"env": []any{map[string]any{"name": "REPO_TOKEN", "value": mcpSecret}}}}}, a2a.TextPart("LEAK SPLIT the credentials"))
	req = pendingRequest(t, task)
	raw, _ = json.Marshal(task.Artifacts)
	if strings.Contains(string(raw), mcpSecret) || !strings.Contains(string(raw), redact.Mask) {
		t.Fatalf("split MCP credential not masked in the paused task: %s", raw)
	}
	done = a.send(task.ID, nil, decision(req.RequestID, "selected", "allow-once"))
	raw, _ = json.Marshal(done.Artifacts)
	if strings.Contains(string(raw), mcpSecret) || !strings.Contains(string(raw), redact.Mask) {
		t.Fatalf("split MCP credential not masked in the final answer: %s", raw)
	}
}

func TestACPEnvironmentIsAllowlistedPerAgent(t *testing.T) {
	t.Setenv("ACP_TEST_AGENT_KEY", "agent-specific-credential")
	t.Setenv("ACP_TEST_SCOPED_ONE", "1")
	t.Setenv("ANTHROPIC_API_KEY", "fake-anthropic-key-for-tests")
	t.Setenv("UNRELATED_SECRET_TOKEN", "fake-unrelated-token")
	a, path := capturingHarness(t, func(c *assistants.ACPConfig) {
		c.EnvNames, c.EnvPrefixes = []string{"ACP_TEST_AGENT_KEY"}, []string{"ACP_TEST_SCOPED_"}
		c.Command = append(c.Command, "extra-arg")
	})
	task := a.send("", nil, a2a.TextPart("Add a note file"))
	pendingRequest(t, task)
	c := onlyCapture(t, path)
	for _, name := range []string{"ACP_TEST_AGENT_KEY", "ACP_TEST_SCOPED_ONE", "HOME", "PATH"} {
		if c.Env[name] == "" {
			t.Errorf("%s was not passed", name)
		}
	}
	for _, name := range []string{"ANTHROPIC_API_KEY", "UNRELATED_SECRET_TOKEN"} {
		if _, ok := c.Env[name]; ok {
			t.Errorf("%s reached an agent that does not allow it", name)
		}
	}
	if c.Env["TERM"] != "dumb" || c.Env["ACP_TEST_AGENT_KEY"] != "set" {
		t.Fatalf("captured env: TERM=%q key=%q", c.Env["TERM"], c.Env["ACP_TEST_AGENT_KEY"])
	}
	if len(c.Args) == 0 || c.Args[len(c.Args)-1] != "extra-arg" {
		t.Fatalf("command line: %v", c.Args)
	}
}
