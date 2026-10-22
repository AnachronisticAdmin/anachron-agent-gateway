// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0
// Derived from the owner-approved snapshot; modified for the standalone candidate.
// See PROVENANCE.md for source and intentional behavior changes.

// Package acpfake is a scripted ACP agent for tests and local demos. It
// speaks the same JSON-RPC framing as a real agent, asks permission before
// "running" a command and writes one file into its session's working
// directory. Prompt keywords select failure scenarios:
//
//   - TWO_APPROVALS: ask a second permission before writing.
//   - CRASH: exit right after the permission request is answered.
//   - NOISE: print a non-protocol line on stdout first.
//   - LEAK: echo every MCP env and header value of the session (redaction
//     tests); with SPLIT, across two message chunks.
//
// Environment (the gateway passes only allowlisted variables, so tests set
// these through the agent command or ACPConfig.Env):
//
//   - ACP_FAKE_CAPTURE=<file>: append a Capture JSON line per session/new.
//   - ACP_FAKE_NO_HTTP_MCP=1: do not advertise HTTP MCP support.
package acpfake

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/AnachronisticAdmin/anachron-agent-gateway/acp"
)

// OutputFile is the file the fake agent writes when allowed.
const OutputFile = "ANACHRON_FAKE_AGENT.md"

// Capture records how the agent was started and what session/new carried.
// Env maps every variable name the agent received to its value for the
// names in CapturedValues (and ACP_FAKE_* names), and to "set" otherwise, so
// a capture never holds credential values.
type Capture struct {
	Args       []string          `json:"args"`
	Env        map[string]string `json:"env"`
	SessionNew json.RawMessage   `json:"sessionNew"`
}

// CapturedValues are the non-secret variables whose values a Capture keeps.
var CapturedValues = []string{"TERM", "CLAUDE_CODE_EXECUTABLE", "ANTHROPIC_MODEL", "GEMINI_MODEL", "GOOSE_MODE", "GOOSE_MODEL"}

// ReadCaptures reads every Capture appended to path.
func ReadCaptures(path string) ([]Capture, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Capture
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var c Capture
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, sc.Err()
}

func capture(params json.RawMessage) {
	path := os.Getenv("ACP_FAKE_CAPTURE")
	if path == "" {
		return
	}
	c := Capture{Args: os.Args[1:], Env: map[string]string{}, SessionNew: params}
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if slices.Contains(CapturedValues, k) || strings.HasPrefix(k, "ACP_FAKE_") {
			c.Env[k] = v
		} else {
			c.Env[k] = "set"
		}
	}
	line, _ := json.Marshal(c)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(append(line, '\n'))
	_ = f.Close()
}

type agent struct {
	out     io.Writer
	wmu     sync.Mutex
	mu      sync.Mutex
	cwd     map[string]string
	secrets map[string][]string
	wait    map[string]chan *acp.Message
	stop    map[string]chan struct{}
	seq     int
}

// Run serves one agent connection until stdin closes; it returns the exit code.
func Run(stdin io.Reader, stdout, stderr io.Writer) int {
	a := &agent{out: stdout, cwd: map[string]string{}, secrets: map[string][]string{}, wait: map[string]chan *acp.Message{}, stop: map[string]chan struct{}{}}
	dec := acp.NewDecoder(stdin)
	for {
		m, err := dec.Next()
		if err != nil {
			if err == io.EOF {
				return 0
			}
			fmt.Fprintln(stderr, "acpfake:", err)
			continue
		}
		switch m.Kind() {
		case acp.KindResponse:
			a.mu.Lock()
			ch := a.wait[string(m.ID)]
			a.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		case acp.KindNotification:
			if m.Method == acp.MethodSessionCancel {
				var p acp.CancelParams
				_ = json.Unmarshal(m.Params, &p)
				a.mu.Lock()
				if ch, ok := a.stop[p.SessionID]; ok {
					close(ch)
					delete(a.stop, p.SessionID)
				}
				a.mu.Unlock()
			}
		case acp.KindRequest:
			a.request(m)
		}
	}
}

func (a *agent) send(m *acp.Message) {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	_ = acp.Encode(a.out, m)
}

func (a *agent) reply(id json.RawMessage, v any) {
	raw, _ := json.Marshal(v)
	a.send(&acp.Message{ID: id, Result: raw})
}

func (a *agent) request(m *acp.Message) {
	switch m.Method {
	case acp.MethodInitialize:
		caps := mustJSON(acp.AgentCapabilities{MCP: acp.MCPCapabilities{HTTP: os.Getenv("ACP_FAKE_NO_HTTP_MCP") != "1"}})
		a.reply(m.ID, acp.InitializeResult{ProtocolVersion: acp.ProtocolVersion, AgentCapabilities: caps,
			AgentInfo: &acp.Implementation{Name: "acp-fake-agent", Version: "0.1.0"}})
	case acp.MethodSessionNew:
		capture(m.Params)
		var p struct {
			Cwd        string `json:"cwd"`
			MCPServers []struct {
				Env     []acp.EnvVariable `json:"env"`
				Headers []acp.HTTPHeader  `json:"headers"`
			} `json:"mcpServers"`
		}
		_ = json.Unmarshal(m.Params, &p)
		var secrets []string
		for _, s := range p.MCPServers {
			for _, e := range s.Env {
				secrets = append(secrets, e.Value)
			}
			for _, h := range s.Headers {
				secrets = append(secrets, h.Value)
			}
		}
		a.mu.Lock()
		a.seq++
		sid := fmt.Sprintf("fake-session-%d", a.seq)
		a.cwd[sid] = p.Cwd
		a.secrets[sid] = secrets
		a.mu.Unlock()
		a.reply(m.ID, acp.NewSessionResult{SessionID: sid, Modes: &acp.SessionModes{CurrentModeID: "default",
			AvailableModes: []acp.SessionMode{{ID: "default", Name: "Manual"}, {ID: "acceptEdits", Name: "Accept edits"}}}})
	case acp.MethodSessionSetMode:
		a.reply(m.ID, nil)
	case acp.MethodSessionPrompt:
		var p acp.PromptParams
		_ = json.Unmarshal(m.Params, &p)
		stop := make(chan struct{})
		a.mu.Lock()
		a.stop[p.SessionID] = stop
		a.mu.Unlock()
		go a.turn(m.ID, p, stop)
	default:
		a.send(&acp.Message{ID: m.ID, Error: &acp.RPCError{Code: acp.CodeMethodNotFound, Message: "method not found: " + m.Method}})
	}
}

func (a *agent) update(sid string, v map[string]any) {
	raw, _ := json.Marshal(acp.SessionNotification{SessionID: sid, Update: mustJSON(v)})
	a.send(&acp.Message{Method: acp.MethodSessionUpdate, Params: raw})
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func text(s string) map[string]any { return map[string]any{"type": "text", "text": s} }

// ask sends a permission request and waits for its outcome; "" means
// cancelled (by the client's outcome or by session/cancel).
func (a *agent) ask(sid string, call map[string]any, stop chan struct{}) string {
	a.mu.Lock()
	a.seq++
	id := json.RawMessage(fmt.Sprintf(`"perm-%d"`, a.seq))
	ch := make(chan *acp.Message, 1)
	a.wait[string(id)] = ch
	a.mu.Unlock()
	params := map[string]any{"sessionId": sid, "toolCall": call, "options": []acp.PermissionOption{
		{OptionID: "allow-once", Name: "Yes", Kind: acp.OptionAllowOnce},
		{OptionID: "allow-with-updates", Name: "Yes, and don't ask again", Kind: acp.OptionAllowAlways},
		{OptionID: "reject", Name: "No", Kind: acp.OptionRejectOnce},
	}}
	a.send(&acp.Message{ID: id, Method: acp.MethodRequestPermission, Params: mustJSON(params)})
	select {
	case <-stop:
		return ""
	case m := <-ch:
		var res acp.RequestPermissionResult
		if m.Error != nil || json.Unmarshal(m.Result, &res) != nil || res.Outcome.Outcome != "selected" {
			return ""
		}
		return res.Outcome.OptionID
	}
}

func (a *agent) turn(id json.RawMessage, p acp.PromptParams, stop chan struct{}) {
	sid := p.SessionID
	prompt := ""
	for _, b := range p.Prompt {
		prompt += b.Text
	}
	if strings.Contains(prompt, "NOISE") {
		a.wmu.Lock()
		fmt.Fprintln(a.out, "fake agent: this line is not JSON-RPC")
		a.wmu.Unlock()
	}
	finish := func(reason string) {
		a.reply(id, acp.PromptResult{StopReason: reason, Usage: &acp.Usage{InputTokens: 1200, OutputTokens: 340, CachedReadTokens: 800, CachedWriteTokens: 100, TotalTokens: 2440}})
	}
	a.update(sid, map[string]any{"sessionUpdate": acp.UpdateAgentMessageChunk, "content": text("Inspecting the workspace. ")})
	if strings.Contains(prompt, "LEAK") {
		a.mu.Lock()
		leaked := strings.Join(a.secrets[sid], " ")
		a.mu.Unlock()
		chunks := []string{"MCP credentials: " + leaked + ". "}
		if strings.Contains(prompt, "SPLIT") && len(leaked) > 1 {
			// Stream the credential in two pieces, as a model emitting tokens would.
			chunks = []string{"MCP credentials: " + leaked[:len(leaked)/2], leaked[len(leaked)/2:] + ". "}
		}
		for _, c := range chunks {
			a.update(sid, map[string]any{"sessionUpdate": acp.UpdateAgentMessageChunk, "content": text(c)})
		}
	}
	call := map[string]any{"toolCallId": "call-1", "title": "git status --short", "kind": "execute", "status": "pending",
		"rawInput": map[string]any{"command": "git status --short", "description": "Show working tree status"},
		"_meta":    map[string]any{"claudeCode": map[string]any{"toolName": "Bash"}}}
	a.update(sid, map[string]any{"sessionUpdate": acp.UpdateToolCall, "toolCallId": "call-1", "title": call["title"], "kind": "execute",
		"status": "pending", "rawInput": call["rawInput"], "_meta": call["_meta"]})
	choice := a.ask(sid, call, stop)
	if strings.Contains(prompt, "CRASH") {
		os.Exit(3)
	}
	if choice == "" {
		finish(acp.StopCancelled)
		return
	}
	if choice != "allow-once" {
		a.update(sid, map[string]any{"sessionUpdate": acp.UpdateToolCallUpdate, "toolCallId": "call-1", "status": "failed"})
		a.update(sid, map[string]any{"sessionUpdate": acp.UpdateAgentMessageChunk, "content": text("Permission was not granted; no changes made.")})
		finish(acp.StopEndTurn)
		return
	}
	a.update(sid, map[string]any{"sessionUpdate": acp.UpdateToolCallUpdate, "toolCallId": "call-1", "status": "completed", "rawOutput": map[string]any{"stdout": ""}})
	a.mu.Lock()
	cwd := a.cwd[sid]
	a.mu.Unlock()
	target := filepath.Join(cwd, OutputFile)
	edit := map[string]any{"toolCallId": "call-2", "title": "Write " + OutputFile, "kind": "edit", "status": "pending",
		"rawInput":  map[string]any{"file_path": target, "content": "…"},
		"locations": []map[string]any{{"path": target}},
		"_meta":     map[string]any{"claudeCode": map[string]any{"toolName": "Write"}}}
	a.update(sid, mergeMap(map[string]any{"sessionUpdate": acp.UpdateToolCall}, edit))
	if strings.Contains(prompt, "TWO_APPROVALS") {
		if a.ask(sid, edit, stop) != "allow-once" {
			finish(acp.StopCancelled)
			return
		}
	}
	body := fmt.Sprintf("# Fake agent output\n\nPrompt: %s\n", strings.TrimSpace(prompt))
	if err := os.WriteFile(target, []byte(body), 0o644); err != nil {
		a.update(sid, map[string]any{"sessionUpdate": acp.UpdateToolCallUpdate, "toolCallId": "call-2", "status": "failed"})
		finish(acp.StopRefusal)
		return
	}
	a.update(sid, map[string]any{"sessionUpdate": acp.UpdateToolCallUpdate, "toolCallId": "call-2", "status": "completed"})
	a.update(sid, map[string]any{"sessionUpdate": acp.UpdateUsage, "used": 2440, "size": 200000, "cost": map[string]any{"amount": 0.0421, "currency": "USD"}})
	a.update(sid, map[string]any{"sessionUpdate": acp.UpdateAgentMessageChunk, "content": text("Wrote " + OutputFile + ".")})
	finish(acp.StopEndTurn)
}

func mergeMap(a, b map[string]any) map[string]any {
	for k, v := range b {
		a[k] = v
	}
	return a
}
