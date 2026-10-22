// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0
// Derived from the owner-approved snapshot; modified for the standalone candidate.
// See PROVENANCE.md for source and intentional behavior changes.

package assistants

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AnachronisticAdmin/anachron-agent-gateway/a2a"
	"github.com/AnachronisticAdmin/anachron-agent-gateway/acp"
	"github.com/AnachronisticAdmin/anachron-agent-gateway/redact"
	"github.com/AnachronisticAdmin/anachron-agent-gateway/server"
)

// Request metadata understood by the ACP executor (SendMessageRequest.metadata
// or the message's own metadata).
const (
	// MetaWorkDir selects a per-task working directory below ACPConfig.WorkDirRoot.
	MetaWorkDir = "anachron.workDir"
	// MetaPermissionMode selects the agent's session mode (default, acceptEdits or plan).
	MetaPermissionMode = "anachron.permissionMode"
)

// Data part types exchanged with ACP-backed tasks.
const (
	DataPermissionRequest  = "anachron.acp.permission_request"
	DataPermissionDecision = "anachron.acp.permission_decision"
	DataToolCall           = "anachron.acp.tool_call"
	DataPlan               = "anachron.acp.plan"
)

// Task metadata keys written by the ACP executor.
const (
	UsageMetadataKey      = "usage"
	ACPSessionMetadataKey = "acpSessionId"
	WorkDirMetadataKey    = "workDir"
	// MCPServersMetadataKey lists the attached MCP servers (name, type and
	// target, never credentials).
	MCPServersMetadataKey = "mcpServers"
)

// ACPConfig configures an interactive executor for an Agent Client Protocol
// agent (for example Claude Code through @agentclientprotocol/claude-agent-acp,
// or one of the other ACPProfiles).
//
// The agent's permission requests are not answered
// by a fixed access level: each one pauses the A2A task in
// the input-required state and the client decides. Approval authority stays
// with the client; the gateway only relays and binds decisions.
type ACPConfig struct {
	Name        string
	DisplayName string
	// Command is the agent command line, e.g. node .../claude-agent-acp/dist/index.js.
	Command []string
	// Env holds extra KEY=VALUE entries added to the allowlisted environment;
	// they win over inherited values of the same name.
	Env []string
	// EnvNames and EnvPrefixes extend the base environment allowlist
	// (agentEnvNames) with agent-specific variables, such as credentials.
	EnvNames    []string
	EnvPrefixes []string
	// WorkDir is the default session directory.
	WorkDir string
	// WorkDirRoot, when set, lets a task choose a directory strictly below it
	// through MetaWorkDir (for example one git worktree per task).
	WorkDirRoot string
	// SessionMeta is sent as _meta on session/new.
	SessionMeta map[string]any
	// MCPAllow lists the MCP servers a task may attach through
	// MetaMCPServers; nil or empty refuses every server.
	MCPAllow *MCPAllowlist
	// AllowDurablePermissions permits "allow always" options, which make the
	// agent persist allow rules outside the client's approval records.
	AllowDurablePermissions bool
	Redactor                *redact.Redactor
	// MaxConcurrent bounds live agent processes (0 = 4).
	MaxConcurrent int
	// IdleTimeout ends sessions paused for a decision longer than this (0 = 2h).
	IdleTimeout time.Duration
	// StartTimeout bounds initialize and session/new (0 = 60s).
	StartTimeout time.Duration
	Logger       *slog.Logger
}

// ClaudeSessionMeta isolates Claude Code from the operator's personal
// settings (allow rules, hooks, plugins) so the client's approval gate sees
// every guarded action, and disables interactive questions it cannot render.
func ClaudeSessionMeta() map[string]any {
	return map[string]any{"claudeCode": map[string]any{"options": map[string]any{
		"settingSources":  []string{},
		"disallowedTools": []string{"AskUserQuestion"},
	}}}
}

// ACPExecutor runs one ACP agent session per A2A task.
type ACPExecutor struct {
	cfg ACPConfig
	sem chan struct{}

	mu       sync.Mutex
	sessions map[string]*acpSession
	closed   bool
}

// NewACPExecutor validates cfg and returns an executor.
func NewACPExecutor(cfg ACPConfig) (*ACPExecutor, error) {
	if len(cfg.Command) == 0 || cfg.Command[0] == "" {
		return nil, errors.New("assistants: ACP executor requires an agent command")
	}
	if cfg.Name == "" {
		cfg.Name = "acp"
	}
	if cfg.DisplayName == "" {
		cfg.DisplayName = "ACP agent"
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 4
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 2 * time.Hour
	}
	if cfg.StartTimeout <= 0 {
		cfg.StartTimeout = 60 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.WorkDir == "" {
		cfg.WorkDir = "."
	}
	abs, err := filepath.Abs(cfg.WorkDir)
	if err != nil {
		return nil, err
	}
	cfg.WorkDir = abs
	if cfg.WorkDirRoot != "" {
		root, err := filepath.EvalSymlinks(cfg.WorkDirRoot)
		if err != nil {
			return nil, fmt.Errorf("assistants: workdir root: %w", err)
		}
		cfg.WorkDirRoot = root
	}
	return &ACPExecutor{cfg: cfg, sem: make(chan struct{}, cfg.MaxConcurrent), sessions: map[string]*acpSession{}}, nil
}

// Close terminates every live agent session (paused ones included).
func (e *ACPExecutor) Close() error {
	e.mu.Lock()
	e.closed = true
	live := make([]*acpSession, 0, len(e.sessions))
	for _, s := range e.sessions {
		live = append(live, s)
	}
	e.mu.Unlock()
	for _, s := range live {
		e.terminate(s)
	}
	return nil
}

// ACPCard returns an informational host descriptor. It does not implement
// A2A discovery, a wire codec, streaming or a push-notification service.
func ACPCard(cfg ACPConfig, interfaces []a2a.AgentInterface) *a2a.AgentCard {
	name := cfg.DisplayName
	if name == "" {
		name = "ACP agent"
	}
	tags := []string{"coding", "assistant", "acp", "interactive-approvals"}
	if !cfg.MCPAllow.Empty() {
		tags = append(tags, "mcp-passthrough")
	}
	return &a2a.AgentCard{
		Name:                name + " via A2A",
		Description:         name + " over the Agent Client Protocol. Every permission request pauses the task (input required) for the client's decision.",
		Version:             "0.1.0",
		SupportedInterfaces: interfaces,
		Capabilities:        a2a.AgentCapabilities{Streaming: a2a.Bool(false), PushNotifications: a2a.Bool(false)},
		DefaultInputModes:   []string{"text/plain", "application/json"},
		DefaultOutputModes:  []string{"text/plain", "application/json"},
		Skills: []a2a.AgentSkill{{
			ID: cfg.Name + "-coding", Name: name,
			Description: "Modify code in a client-selected working directory, asking the client before every guarded action.",
			Tags:        tags,
			Examples:    []string{"Add input validation to the signup handler and its tests"},
		}},
	}
}

// ---- session state -------------------------------------------------------

type eventKind int

const (
	evUpdate eventKind = iota
	evPermission
	evPromptDone
	evClosed
)

type sessionEvent struct {
	kind   eventKind
	raw    json.RawMessage
	perm   *pendingPermission
	result *acp.PromptResult
	err    error
	bytes  int
}

type pendingPermission struct {
	id      string
	req     *acp.Request
	params  acp.RequestPermissionParams
	call    acp.ToolCall
	message *a2a.Message
}

type acpSession struct {
	taskID, tenant, owner string
	workDir               string
	cmd                   *exec.Cmd
	stdin                 io.Closer
	conn                  *acp.Conn
	stderr                *tailBuffer
	sessionID             string
	red                   *redact.Redactor // also masks the task's MCP credentials

	mu         sync.Mutex
	queue      []sessionEvent
	signal     chan struct{}
	tools      map[string]*acp.ToolCall
	surfaced   *pendingPermission
	asked      int
	idle       *time.Timer
	ended      bool
	queueBytes int
	overloaded bool

	// Owned by the executing goroutine (one at a time per task).
	text     *redact.Stream // agent message text, redacted across chunk boundaries
	streamed bool
	answer   strings.Builder
	costUSD  float64
	hasCost  bool
}

func (s *acpSession) push(ev sessionEvent) {
	s.mu.Lock()
	if s.ended || s.overloaded {
		s.mu.Unlock()
		return
	}
	ev.bytes = len(ev.raw) + 256
	if ev.perm != nil {
		ev.bytes += 2 * len(ev.perm.req.Params)
	}
	overflow := len(s.queue) >= 128 || s.queueBytes+ev.bytes > 4<<20
	if overflow {
		s.overloaded = true
		ev = sessionEvent{kind: evClosed, err: errors.New("agent event queue limit reached"), bytes: 256}
		s.queue = nil
		s.queueBytes = 0
	}
	s.queue = append(s.queue, ev)
	s.queueBytes += ev.bytes
	s.mu.Unlock()
	select {
	case s.signal <- struct{}{}:
	default:
	}
	if overflow {
		_ = s.conn.Close()
	}
}

func (s *acpSession) next(ctx context.Context) (sessionEvent, error) {
	for {
		s.mu.Lock()
		if len(s.queue) > 0 {
			ev := s.queue[0]
			s.queue[0] = sessionEvent{}
			s.queue = s.queue[1:]
			s.queueBytes -= ev.bytes
			s.mu.Unlock()
			return ev, nil
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return sessionEvent{}, ctx.Err()
		case <-s.signal:
		}
	}
}

// Notification implements acp.Handler.
func (s *acpSession) Notification(method string, params json.RawMessage) {
	if method != acp.MethodSessionUpdate {
		return
	}
	var n acp.SessionNotification
	if json.Unmarshal(params, &n) != nil {
		return
	}
	s.mu.Lock()
	id := s.sessionID
	s.mu.Unlock()
	if id == "" || n.SessionID != id {
		return
	}
	s.push(sessionEvent{kind: evUpdate, raw: n.Update})
}

// Request implements acp.Handler. Only permission requests are served:
// this client advertises no file-system or terminal methods (CM-003).
func (s *acpSession) Request(req *acp.Request) {
	if req.Method != acp.MethodRequestPermission {
		_ = req.Fail(&acp.RPCError{Code: acp.CodeMethodNotFound, Message: "method not supported by this client: " + req.Method})
		return
	}
	var p acp.RequestPermissionParams
	if err := json.Unmarshal(req.Params, &p); err != nil || len(p.Options) == 0 || len(p.Options) > 32 {
		_ = req.Fail(&acp.RPCError{Code: acp.CodeInvalidParams, Message: "invalid permission request"})
		return
	}
	s.mu.Lock()
	if s.sessionID == "" || p.SessionID != s.sessionID {
		s.mu.Unlock()
		_ = req.Fail(&acp.RPCError{Code: acp.CodeInvalidParams, Message: "permission request is not for this session"})
		return
	}
	seen := map[string]bool{}
	for _, option := range p.Options {
		validKind := option.Kind == acp.OptionAllowOnce || option.Kind == acp.OptionAllowAlways ||
			option.Kind == acp.OptionRejectOnce || option.Kind == acp.OptionRejectAlways
		if option.OptionID == "" || len(option.OptionID) > 256 || seen[option.OptionID] || !validKind {
			s.mu.Unlock()
			_ = req.Fail(&acp.RPCError{Code: acp.CodeInvalidParams, Message: "invalid permission options"})
			return
		}
		seen[option.OptionID] = true
	}
	s.asked++
	id := fmt.Sprintf("%s-perm-%d", s.taskID, s.asked)
	call := p.ToolCall
	if known := s.tools[call.ToolCallID]; known != nil {
		merged := *known
		merged.Merge(&call)
		call = merged
	}
	s.mu.Unlock()
	s.push(sessionEvent{kind: evPermission, perm: &pendingPermission{id: id, req: req, params: p, call: call}})
}

// ---- execution -----------------------------------------------------------

// Execute implements server.Executor. A new task starts an agent session and
// sends the prompt; a follow-up message on a paused task must carry the
// decision for the pending permission request.
func (e *ACPExecutor) Execute(ctx context.Context, rc *server.RequestContext, w *server.TaskWriter) error {
	if rc.Task != nil {
		s := e.lookup(rc.TaskID)
		if s == nil || s.tenant != rc.Tenant || s.owner != rc.Principal.ID {
			return errors.New("the agent session for this task is no longer running; start a new task")
		}
		s.stopIdle()
		select {
		case <-s.conn.Done():
			e.terminate(s)
			return e.exitError(s, s.conn.Err())
		default:
		}
		if _, ok := rc.Metadata[MetaMCPServers]; ok {
			return e.resurface(s, w, fmt.Errorf("%s is only read when a task starts; reply without it", MetaMCPServers))
		}
		if err := e.decide(s, rc.Message, w); err != nil {
			return e.resurface(s, w, err)
		}
		return e.pump(ctx, s, w)
	}
	workDir, err := e.workDir(rc)
	if err != nil {
		return w.Reject(err.Error())
	}
	mode := metaString(rc, MetaPermissionMode)
	if mode != "" && mode != "default" && mode != "acceptEdits" && mode != "plan" {
		return w.Reject(fmt.Sprintf("permission mode %q is not allowed (use default, acceptEdits or plan)", mode))
	}
	prompt := strings.TrimSpace(renderParts(rc.Message.Parts))
	if prompt == "" {
		return w.Reject("empty prompt")
	}
	servers, attached, err := e.mcpServers(rc)
	if err != nil {
		return w.Reject(err.Error())
	}
	select {
	case e.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	s, err := e.start(ctx, rc, workDir, mode, servers)
	if err != nil {
		<-e.sem
		return err
	}
	_ = w.SetMetadata(ACPSessionMetadataKey, s.sessionID)
	_ = w.SetMetadata(WorkDirMetadataKey, workDir)
	if len(attached) > 0 {
		_ = w.SetMetadata(MCPServersMetadataKey, attached)
	}
	_ = w.Working(fmt.Sprintf("%s is working in %s", e.cfg.DisplayName, filepath.Base(workDir)))
	go func() {
		var res acp.PromptResult
		err := s.conn.Call(context.Background(), acp.MethodSessionPrompt,
			acp.PromptParams{SessionID: s.sessionID, Prompt: []acp.ContentBlock{{Type: "text", Text: prompt}}}, &res)
		s.push(sessionEvent{kind: evPromptDone, result: &res, err: err})
	}()
	return e.pump(ctx, s, w)
}

// CancelTask implements server.TaskCanceler for tasks paused on a decision.
func (e *ACPExecutor) CancelTask(_ context.Context, task *a2a.Task) (bool, error) {
	if s := e.lookup(task.ID); s != nil {
		e.terminate(s)
	}
	return true, nil
}

func (e *ACPExecutor) lookup(taskID string) *acpSession {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sessions[taskID]
}

func metaString(rc *server.RequestContext, key string) string {
	if v, ok := rc.Metadata[key].(string); ok {
		return strings.TrimSpace(v)
	}
	if rc.Message != nil {
		if v, ok := rc.Message.Metadata[key].(string); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ValidateMessage implements server.MessageValidator: MetaMCPServers in
// message metadata is refused before the message, and with it any
// credential, is written to task history.
func (e *ACPExecutor) ValidateMessage(req *a2a.SendMessageRequest) error {
	if req.Message != nil {
		if _, ok := req.Message.Metadata[MetaMCPServers]; ok {
			return fmt.Errorf("send %s in the request metadata, not the message metadata (message metadata is kept in task history)", MetaMCPServers)
		}
	}
	return nil
}

// mcpServers validates the task's MCP servers against the operator
// allowlist and returns them with their task metadata entries. Any refused
// server rejects the whole task: there is no partial passthrough.
func (e *ACPExecutor) mcpServers(rc *server.RequestContext) ([]MCPServer, []map[string]any, error) {
	v, ok := rc.Metadata[MetaMCPServers]
	if !ok || v == nil {
		return nil, nil, nil
	}
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, nil, fmt.Errorf("%s cannot be encoded", MetaMCPServers)
	}
	servers, err := ParseMCPServers(bytes.TrimSpace(raw.Bytes()))
	if err != nil {
		return nil, nil, err
	}
	attached := make([]map[string]any, 0, len(servers))
	for _, s := range servers {
		allowedBy, err := e.cfg.MCPAllow.Check(s)
		if err != nil {
			return nil, nil, fmt.Errorf("MCP server %q refused: %v", s.Name, err)
		}
		attached = append(attached, map[string]any{"name": s.Name, "type": s.Type, "allowedBy": allowedBy})
	}
	return servers, attached, nil
}

// workDir resolves the task's directory. A requested directory must be an
// existing directory strictly inside WorkDirRoot after resolving symlinks.
func (e *ACPExecutor) workDir(rc *server.RequestContext) (string, error) {
	want := metaString(rc, MetaWorkDir)
	if want == "" {
		return e.cfg.WorkDir, nil
	}
	if e.cfg.WorkDirRoot == "" {
		return "", errors.New("per-task working directories are disabled on this gateway (configure -workdir-root)")
	}
	if !filepath.IsAbs(want) {
		return "", errors.New("working directory must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(want)
	if err != nil {
		return "", errors.New("working directory does not exist")
	}
	rel, err := filepath.Rel(e.cfg.WorkDirRoot, resolved)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("working directory is outside the configured root")
	}
	if info, err := os.Stat(resolved); err != nil || !info.IsDir() {
		return "", errors.New("working directory is not a directory")
	}
	return resolved, nil
}

var agentEnvNames = []string{"HOME", "USER", "LOGNAME", "SHELL", "PATH", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"}

// agentEnv passes an allowlist of the gateway environment (agentEnvNames
// plus the agent's own names and prefixes): credentials of unrelated tools
// never reach the agent process. extra entries replace inherited ones.
func agentEnv(names, prefixes, extra []string) []string {
	fixed := map[string]bool{"TERM": true}
	for _, kv := range extra {
		k, _, _ := strings.Cut(kv, "=")
		fixed[k] = true
	}
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if fixed[k] {
			continue
		}
		if slices.Contains(agentEnvNames, k) || slices.Contains(names, k) ||
			slices.ContainsFunc(prefixes, func(p string) bool { return p != "" && strings.HasPrefix(k, p) }) {
			out = append(out, kv)
		}
	}
	return append(append(out, "TERM=dumb"), extra...)
}

func (e *ACPExecutor) start(ctx context.Context, rc *server.RequestContext, workDir, mode string, servers []MCPServer) (*acpSession, error) {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, errors.New("executor is shutting down")
	}
	e.mu.Unlock()
	cmd := exec.Command(e.cfg.Command[0], e.cfg.Command[1:]...)
	cmd.Dir = workDir
	cmd.Env = agentEnv(e.cfg.EnvNames, e.cfg.EnvPrefixes, e.cfg.Env)
	ownGroup(cmd)
	stderr := &tailBuffer{max: 8 << 10}
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", e.cfg.DisplayName, err)
	}
	mcp := make([]any, 0, len(servers))
	var secrets []string
	for _, srv := range servers {
		secrets = append(secrets, srv.secrets()...)
		mcp = append(mcp, srv.ACP())
	}
	for _, entry := range cmd.Env {
		name, value, _ := strings.Cut(entry, "=")
		if secretNameRE.MatchString(name) {
			secrets = append(secrets, value)
		}
	}
	red := e.cfg.Redactor.WithSecrets(secrets...)
	s := &acpSession{taskID: rc.TaskID, tenant: rc.Tenant, owner: rc.Principal.ID, workDir: workDir, red: red, text: red.Stream(), cmd: cmd, stdin: stdin,
		stderr: stderr, signal: make(chan struct{}, 1), tools: map[string]*acp.ToolCall{}}
	s.conn = acp.NewConn(stdout, stdin, s, e.cfg.Logger)
	go func() {
		<-s.conn.Done()
		s.push(sessionEvent{kind: evClosed, err: s.conn.Err()})
	}()
	fail := func(step string, err error) (*acpSession, error) {
		e.kill(s)
		msg := fmt.Sprintf("%s: %s failed: %v", e.cfg.DisplayName, step, err)
		if tail := stderr.String(); tail != "" {
			msg += ": " + lastLines(tail, 5)
		}
		return nil, errors.New(red.String(msg))
	}
	sctx, cancel := context.WithTimeout(ctx, e.cfg.StartTimeout)
	defer cancel()
	var init acp.InitializeResult
	if err := s.conn.Call(sctx, acp.MethodInitialize, acp.InitializeParams{ProtocolVersion: acp.ProtocolVersion,
		ClientInfo: &acp.Implementation{Name: "anachron-agent-gateway", Version: "0.1.0"}}, &init); err != nil {
		return fail("initialize", err)
	}
	if init.ProtocolVersion != acp.ProtocolVersion {
		return fail("initialize", fmt.Errorf("unsupported ACP protocol version %d", init.ProtocolVersion))
	}
	if caps := init.Capabilities(); !caps.MCP.HTTP {
		for _, srv := range servers {
			if srv.Type == MCPHTTP {
				return fail("session/new", fmt.Errorf("the agent does not support HTTP MCP servers (MCP server %q)", srv.Name))
			}
		}
	}
	var created acp.NewSessionResult
	if err := s.conn.Call(sctx, acp.MethodSessionNew, acp.NewSessionParams{Cwd: workDir, MCPServers: mcp, Meta: e.cfg.SessionMeta}, &created); err != nil {
		return fail("session/new", err)
	}
	if created.SessionID == "" {
		return fail("session/new", errors.New("agent returned an empty session ID"))
	}
	s.mu.Lock()
	s.sessionID = created.SessionID
	s.mu.Unlock()
	if mode != "" && created.Modes != nil && created.Modes.CurrentModeID != mode {
		if !slices.ContainsFunc(created.Modes.AvailableModes, func(m acp.SessionMode) bool { return m.ID == mode }) {
			return fail("session/set_mode", fmt.Errorf("agent does not offer mode %q", mode))
		}
		if err := s.conn.Call(sctx, acp.MethodSessionSetMode, acp.SetModeParams{SessionID: s.sessionID, ModeID: mode}, nil); err != nil {
			return fail("session/set_mode", err)
		}
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		e.kill(s)
		return nil, errors.New("executor closed during session initialization")
	}
	e.sessions[s.taskID] = s
	e.mu.Unlock()
	return s, nil
}

// pump relays agent events to the task until the turn ends, a permission
// request pauses the task, the agent exits or ctx ends.
func (e *ACPExecutor) pump(ctx context.Context, s *acpSession, w *server.TaskWriter) error {
	red := s.red
	for {
		ev, err := s.next(ctx)
		if err != nil {
			e.terminate(s)
			return err
		}
		switch ev.kind {
		case evUpdate:
			e.applyUpdate(s, w, ev.raw)
		case evPermission:
			e.emitText(s, w, s.text.Flush())
			p := ev.perm
			p.message = permissionMessage(p, red)
			s.mu.Lock()
			s.surfaced = p
			s.mu.Unlock()
			if err := w.Status(a2a.TaskStateInputRequired, p.message); err != nil {
				e.terminate(s)
				return err
			}
			s.startIdle(e.cfg.IdleTimeout, func() { e.terminate(s) })
			return nil
		case evPromptDone:
			e.emitText(s, w, s.text.Flush())
			// The turn is over: stop the agent before reporting the outcome.
			e.terminate(s)
			if ev.err != nil {
				if errors.Is(ev.err, acp.ErrClosed) {
					return e.exitError(s, ev.err)
				}
				return errors.New(red.String(fmt.Sprintf("%s: %v", e.cfg.DisplayName, ev.err)))
			}
			return e.finish(s, w, ev.result)
		case evClosed:
			e.emitText(s, w, s.text.Flush())
			e.terminate(s)
			return e.exitError(s, ev.err)
		}
	}
}

func (e *ACPExecutor) exitError(s *acpSession, err error) error {
	msg := fmt.Sprintf("%s exited before the turn ended", e.cfg.DisplayName)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, acp.ErrClosed) {
		msg += fmt.Sprintf(" (%v)", err)
	}
	if tail := s.stderr.String(); tail != "" {
		msg += ": " + lastLines(tail, 5)
	}
	return errors.New(s.red.String(msg))
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// emitText streams redacted agent text into the response artifact.
func (e *ACPExecutor) emitText(s *acpSession, w *server.TaskWriter, chunk string) {
	if chunk == "" {
		return
	}
	if s.answer.Len() < 64<<10 {
		s.answer.WriteString(chunk)
	}
	_ = w.Artifact(a2a.Artifact{ArtifactID: ResponseArtifactID, Name: "response", Parts: []a2a.Part{a2a.TextPart(chunk)}}, s.streamed, false)
	s.streamed = true
}

func (e *ACPExecutor) applyUpdate(s *acpSession, w *server.TaskWriter, raw json.RawMessage) {
	red := s.red
	kind, err := acp.UpdateKind(raw)
	if err != nil {
		return
	}
	switch kind {
	case acp.UpdateAgentMessageChunk:
		var u acp.ChunkUpdate
		if json.Unmarshal(raw, &u) != nil || u.Content.Text == "" {
			return
		}
		e.emitText(s, w, s.text.Write(u.Content.Text))
	case acp.UpdateToolCall, acp.UpdateToolCallUpdate:
		var u acp.ToolCall
		if json.Unmarshal(raw, &u) != nil || u.ToolCallID == "" {
			return
		}
		s.mu.Lock()
		call := s.tools[u.ToolCallID]
		changed := call == nil || (u.Status != "" && u.Status != call.Status) || (u.Title != "" && u.Title != call.Title)
		if call == nil {
			call = &u
			s.tools[u.ToolCallID] = call
		} else {
			call.Merge(&u)
		}
		snapshot := *call
		s.mu.Unlock()
		if changed {
			_ = w.Status(a2a.TaskStateWorking, toolMessage(&snapshot, red))
		}
	case acp.UpdatePlan:
		var u acp.PlanUpdate
		if json.Unmarshal(raw, &u) == nil && len(u.Entries) > 0 {
			for i := range u.Entries {
				u.Entries[i].Content = red.String(u.Entries[i].Content)
			}
			_ = w.Status(a2a.TaskStateWorking, &a2a.Message{Role: a2a.RoleAgent, Parts: []a2a.Part{
				a2a.TextPart(fmt.Sprintf("Plan updated (%d steps)", len(u.Entries))),
				a2a.DataPart(map[string]any{"type": DataPlan, "entries": u.Entries}),
			}})
		}
	case acp.UpdateUsage:
		var u acp.UsageUpdate
		if json.Unmarshal(raw, &u) == nil && u.Cost != nil && u.Cost.Currency == "USD" {
			s.costUSD, s.hasCost = u.Cost.Amount, true
		}
	}
}

func (e *ACPExecutor) finish(s *acpSession, w *server.TaskWriter, res *acp.PromptResult) error {
	usage := map[string]any{}
	if res.Usage != nil {
		usage["inputTokens"] = res.Usage.InputTokens
		usage["outputTokens"] = res.Usage.OutputTokens
		usage["cachedReadTokens"] = res.Usage.CachedReadTokens
		usage["cachedWriteTokens"] = res.Usage.CachedWriteTokens
	}
	if s.hasCost {
		usage["costUsd"] = s.costUSD
	}
	if len(usage) > 0 {
		_ = w.SetMetadata(UsageMetadataKey, usage)
	}
	// Chunks are redacted one at a time; redacting the whole answer again also
	// masks a credential split across chunks in the final artifact.
	answer := strings.TrimSpace(s.red.String(s.answer.String()))
	switch res.StopReason {
	case acp.StopEndTurn, acp.StopMaxTokens, acp.StopMaxTurnRequests:
	case acp.StopRefusal:
		return fmt.Errorf("%s refused the request", e.cfg.DisplayName)
	case acp.StopCancelled:
		return fmt.Errorf("%s cancelled the turn", e.cfg.DisplayName)
	default:
		return fmt.Errorf("%s ended the turn with unknown stop reason %q", e.cfg.DisplayName, s.red.String(res.StopReason))
	}
	meta := map[string]any{"assistant": e.cfg.Name, "stopReason": res.StopReason, UsageMetadataKey: usage}
	final := answer
	if final == "" {
		final = "Turn ended (" + res.StopReason + ")"
	}
	if err := w.Artifact(a2a.Artifact{ArtifactID: ResponseArtifactID, Name: "response", Parts: []a2a.Part{a2a.TextPart(final)}, Metadata: meta}, false, true); err != nil {
		return err
	}
	if res.StopReason != acp.StopEndTurn {
		final += "\n[stopped: " + res.StopReason + "]"
	}
	return w.Complete(final)
}

// decide validates the client's reply against the surfaced request and
// relays it. The decision is bound to the request ID and the offered option
// IDs; anything else leaves the request pending (CM-005).
func (e *ACPExecutor) decide(s *acpSession, m *a2a.Message, w *server.TaskWriter) error {
	s.mu.Lock()
	p := s.surfaced
	s.mu.Unlock()
	if p == nil {
		return errors.New("no permission request is pending for this task")
	}
	var d struct {
		Type      string `json:"type"`
		RequestID string `json:"requestId"`
		Outcome   string `json:"outcome"`
		OptionID  string `json:"optionId"`
	}
	found := false
	for _, part := range m.Parts {
		candidate := d
		if len(part.Data) > 0 && json.Unmarshal(part.Data, &candidate) == nil && candidate.Type == DataPermissionDecision {
			if found {
				return errors.New("reply must contain exactly one permission decision")
			}
			d, found = candidate, true
		}
	}
	switch {
	case !found:
		return fmt.Errorf("reply with a %s data part", DataPermissionDecision)
	case d.RequestID != p.id:
		return fmt.Errorf("decision is for request %q, but %q is pending", d.RequestID, p.id)
	}
	var result acp.RequestPermissionResult
	note := ""
	switch d.Outcome {
	case "cancelled":
		result, note = acp.Cancelled(), "Permission request cancelled"
	case "selected":
		i := slices.IndexFunc(p.params.Options, func(o acp.PermissionOption) bool { return o.OptionID == d.OptionID })
		if i < 0 {
			return fmt.Errorf("option %q was not offered", d.OptionID)
		}
		opt := p.params.Options[i]
		if opt.Kind == acp.OptionAllowAlways && !e.cfg.AllowDurablePermissions {
			return errors.New("durable \"allow always\" options are disabled on this gateway")
		}
		result = acp.Selected(opt.OptionID)
		note = "Permission " + map[bool]string{true: "granted", false: "denied"}[strings.HasPrefix(opt.Kind, "allow")]
	default:
		return fmt.Errorf("unknown outcome %q", d.Outcome)
	}
	if err := p.req.Reply(result); err != nil {
		return fmt.Errorf("relay decision: %w", err)
	}
	s.mu.Lock()
	s.surfaced = nil
	s.mu.Unlock()
	_ = w.Working(note + ": " + s.red.String(p.call.Title))
	return nil
}

// resurface keeps the task paused on the same request after an invalid reply.
func (e *ACPExecutor) resurface(s *acpSession, w *server.TaskWriter, cause error) error {
	s.mu.Lock()
	p := s.surfaced
	s.mu.Unlock()
	if p == nil {
		return cause
	}
	m := *p.message
	m.Parts = append([]a2a.Part{a2a.TextPart("Reply not accepted: " + cause.Error())}, p.message.Parts...)
	if err := w.Status(a2a.TaskStateInputRequired, &m); err != nil {
		return err
	}
	s.startIdle(e.cfg.IdleTimeout, func() { e.terminate(s) })
	return nil
}

func (s *acpSession) startIdle(d time.Duration, fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idle != nil {
		s.idle.Stop()
	}
	s.idle = time.AfterFunc(d, fn)
}

func (s *acpSession) stopIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idle != nil {
		s.idle.Stop()
		s.idle = nil
	}
}

// terminate cancels the turn, withdraws the open permission request and
// stops the agent's process group. It is idempotent.
func (e *ACPExecutor) terminate(s *acpSession) {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	p := s.surfaced
	s.surfaced = nil
	if s.idle != nil {
		s.idle.Stop()
	}
	s.mu.Unlock()
	if p != nil {
		_ = p.req.Reply(acp.Cancelled())
	}
	if s.sessionID != "" {
		_ = s.conn.Notify(acp.MethodSessionCancel, acp.CancelParams{SessionID: s.sessionID})
	}
	drain, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	s.conn.Drain(drain)
	cancel()
	e.mu.Lock()
	if e.sessions[s.taskID] == s {
		delete(e.sessions, s.taskID)
		<-e.sem
	}
	e.mu.Unlock()
	e.kill(s)
}

func (e *ACPExecutor) kill(s *acpSession) {
	_ = s.stdin.Close()
	if s.conn != nil {
		_ = s.conn.Close()
	}
	// Always terminate the owned group, even if the direct child exited
	// first. Waiting only for that child can otherwise leave descendants.
	killGroup(s.cmd)
	_ = s.cmd.Wait()
}

// ---- A2A message shapes --------------------------------------------------

const maxRawInput = 8 << 10

// redactedJSON redacts the JSON text (patterns such as "api_key": "…" need
// the keys) and then every decoded string, which catches literals that JSON
// escaping hid from the first pass.
func redactedJSON(raw json.RawMessage, red *redact.Redactor) any {
	if len(raw) == 0 {
		return nil
	}
	text := red.String(string(raw))
	if len(text) > maxRawInput {
		var v any
		if json.Unmarshal(raw, &v) == nil {
			if b, err := json.Marshal(redactStrings(v, red)); err == nil {
				text = red.String(string(b))
			}
		}
		return text[:min(len(text), maxRawInput)] + "…"
	}
	var v any
	if json.Unmarshal([]byte(text), &v) == nil {
		return redactStrings(v, red)
	}
	return text
}

func redactStrings(v any, red *redact.Redactor) any {
	switch t := v.(type) {
	case string:
		return red.String(t)
	case []any:
		for i := range t {
			t[i] = redactStrings(t[i], red)
		}
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, item := range t {
			out[red.String(k)] = redactStrings(item, red)
		}
		return out
	}
	return v
}

func toolData(c *acp.ToolCall, red *redact.Redactor) map[string]any {
	d := map[string]any{"toolCallId": c.ToolCallID, "title": red.String(c.Title), "kind": c.Kind, "status": c.Status}
	if name := c.ToolName(); name != "" {
		d["toolName"] = red.String(name)
	}
	if in := redactedJSON(c.RawInput, red); in != nil {
		d["rawInput"] = in
	}
	if len(c.Locations) > 0 {
		locations := make([]acp.Location, len(c.Locations))
		for i, l := range c.Locations {
			locations[i] = acp.Location{Path: red.String(l.Path), Line: l.Line}
		}
		d["locations"] = locations
	}
	return d
}

func toolMessage(c *acp.ToolCall, red *redact.Redactor) *a2a.Message {
	d := toolData(c, red)
	d["type"] = DataToolCall
	status := c.Status
	if status == "" {
		status = "pending"
	}
	return &a2a.Message{Role: a2a.RoleAgent, Parts: []a2a.Part{a2a.TextPart(fmt.Sprintf("%s (%s)", d["title"], status)), a2a.DataPart(d)}}
}

func permissionMessage(p *pendingPermission, red *redact.Redactor) *a2a.Message {
	d := toolData(&p.call, red)
	d["type"] = DataPermissionRequest
	d["requestId"] = p.id
	options := make([]acp.PermissionOption, len(p.params.Options))
	for i, o := range p.params.Options {
		options[i] = acp.PermissionOption{OptionID: o.OptionID, Name: red.String(o.Name), Kind: o.Kind}
	}
	d["options"] = options
	title := red.String(p.call.Title)
	if title == "" {
		title = "a tool call"
	}
	return &a2a.Message{Role: a2a.RoleAgent, Parts: []a2a.Part{a2a.TextPart("Permission required: " + title), a2a.DataPart(d)}}
}

// LiveSessions reports the number of running agent processes.
func (e *ACPExecutor) LiveSessions() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.sessions)
}
