// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0
// Derived from the owner-approved snapshot; modified for the standalone candidate.
// See PROVENANCE.md for source and intentional behavior changes.

package acp

import (
	"encoding/json"
	"fmt"
)

// ProtocolVersion is the ACP major version this client speaks.
const ProtocolVersion = 1

// Method names (client→agent and agent→client).
const (
	MethodInitialize        = "initialize"
	MethodSessionNew        = "session/new"
	MethodSessionPrompt     = "session/prompt"
	MethodSessionCancel     = "session/cancel"
	MethodSessionSetMode    = "session/set_mode"
	MethodSessionUpdate     = "session/update"
	MethodRequestPermission = "session/request_permission"
)

// Stop reasons of a prompt turn.
const (
	StopEndTurn         = "end_turn"
	StopMaxTokens       = "max_tokens"
	StopMaxTurnRequests = "max_turn_requests"
	StopRefusal         = "refusal"
	StopCancelled       = "cancelled"
)

// Permission option kinds.
const (
	OptionAllowOnce    = "allow_once"
	OptionAllowAlways  = "allow_always"
	OptionRejectOnce   = "reject_once"
	OptionRejectAlways = "reject_always"
)

// Implementation identifies a client or agent.
type Implementation struct {
	Name    string `json:"name"`
	Title   string `json:"title,omitempty"`
	Version string `json:"version,omitempty"`
}

// FSCapabilities advertises client file-system methods.
type FSCapabilities struct {
	ReadTextFile  bool `json:"readTextFile"`
	WriteTextFile bool `json:"writeTextFile"`
}

// ClientCapabilities advertises what the client implements. This client
// offers no file-system or terminal methods: the agent works directly in
// its working directory and asks permission through session/request_permission.
type ClientCapabilities struct {
	FS       FSCapabilities `json:"fs"`
	Terminal bool           `json:"terminal"`
}

// InitializeParams starts a connection.
type InitializeParams struct {
	ProtocolVersion    int                `json:"protocolVersion"`
	ClientCapabilities ClientCapabilities `json:"clientCapabilities"`
	ClientInfo         *Implementation    `json:"clientInfo,omitempty"`
}

// InitializeResult is the agent's answer to initialize.
type InitializeResult struct {
	ProtocolVersion   int             `json:"protocolVersion"`
	AgentCapabilities json.RawMessage `json:"agentCapabilities,omitempty"`
	AgentInfo         *Implementation `json:"agentInfo,omitempty"`
}

// AgentCapabilities is the subset of agentCapabilities this client reads.
type AgentCapabilities struct {
	MCP MCPCapabilities `json:"mcpCapabilities"`
}

// MCPCapabilities lists the MCP transports an agent accepts besides stdio,
// which every agent must support.
type MCPCapabilities struct {
	HTTP bool `json:"http"`
	SSE  bool `json:"sse"`
}

// Capabilities decodes the agent's capabilities. Absent or malformed
// fields read as false.
func (r *InitializeResult) Capabilities() AgentCapabilities {
	var c AgentCapabilities
	if len(r.AgentCapabilities) > 0 {
		_ = json.Unmarshal(r.AgentCapabilities, &c)
	}
	return c
}

// EnvVariable is one environment variable of a stdio MCP server.
type EnvVariable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HTTPHeader is one request header of an HTTP MCP server.
type HTTPHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// MCPServerStdio is an MCP server the agent launches as a subprocess.
// The ACP schema requires args and env, so encode empty slices, not nil.
type MCPServerStdio struct {
	Name    string        `json:"name"`
	Command string        `json:"command"`
	Args    []string      `json:"args"`
	Env     []EnvVariable `json:"env"`
}

// MCPServerHTTP is an MCP server reached over streamable HTTP. Agents
// accept it only when they advertise mcpCapabilities.http.
type MCPServerHTTP struct {
	Type    string       `json:"type"`
	Name    string       `json:"name"`
	URL     string       `json:"url"`
	Headers []HTTPHeader `json:"headers"`
}

// NewSessionParams creates a session rooted at Cwd. MCPServers holds
// MCPServerStdio and MCPServerHTTP values.
type NewSessionParams struct {
	Cwd        string         `json:"cwd"`
	MCPServers []any          `json:"mcpServers"`
	Meta       map[string]any `json:"_meta,omitempty"`
}

// SessionMode is one permission/behaviour mode offered by the agent.
type SessionMode struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// SessionModes lists the agent's modes.
type SessionModes struct {
	CurrentModeID  string        `json:"currentModeId"`
	AvailableModes []SessionMode `json:"availableModes"`
}

// NewSessionResult is the agent's answer to session/new.
type NewSessionResult struct {
	SessionID string        `json:"sessionId"`
	Modes     *SessionModes `json:"modes,omitempty"`
}

// SetModeParams switches the session mode.
type SetModeParams struct {
	SessionID string `json:"sessionId"`
	ModeID    string `json:"modeId"`
}

// ContentBlock is prompt or message content; only text is used here.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// PromptParams sends one user turn.
type PromptParams struct {
	SessionID string         `json:"sessionId"`
	Prompt    []ContentBlock `json:"prompt"`
}

// Usage is the token tally of a turn.
type Usage struct {
	InputTokens       int64 `json:"inputTokens"`
	OutputTokens      int64 `json:"outputTokens"`
	CachedReadTokens  int64 `json:"cachedReadTokens,omitempty"`
	CachedWriteTokens int64 `json:"cachedWriteTokens,omitempty"`
	TotalTokens       int64 `json:"totalTokens,omitempty"`
}

// PromptResult ends a turn.
type PromptResult struct {
	StopReason string `json:"stopReason"`
	Usage      *Usage `json:"usage,omitempty"`
}

// CancelParams interrupts the session's current turn.
type CancelParams struct {
	SessionID string `json:"sessionId"`
}

// SessionNotification carries one session/update.
type SessionNotification struct {
	SessionID string          `json:"sessionId"`
	Update    json.RawMessage `json:"update"`
}

// Session update discriminators handled by this client.
const (
	UpdateAgentMessageChunk = "agent_message_chunk"
	UpdateAgentThoughtChunk = "agent_thought_chunk"
	UpdateToolCall          = "tool_call"
	UpdateToolCallUpdate    = "tool_call_update"
	UpdatePlan              = "plan"
	UpdateUsage             = "usage_update"
)

// UpdateKind returns the sessionUpdate discriminator of a raw update.
func UpdateKind(raw json.RawMessage) (string, error) {
	var head struct {
		Kind string `json:"sessionUpdate"`
	}
	if err := json.Unmarshal(raw, &head); err != nil || head.Kind == "" {
		return "", fmt.Errorf("acp: session update without sessionUpdate")
	}
	return head.Kind, nil
}

// ChunkUpdate is an agent message or thought chunk.
type ChunkUpdate struct {
	Content ContentBlock `json:"content"`
}

// Location is a file a tool call touches.
type Location struct {
	Path string `json:"path"`
	Line *int   `json:"line,omitempty"`
}

// ToolCall is a tool call, a tool call update (fields optional) or the
// tool call embedded in a permission request.
type ToolCall struct {
	ToolCallID string          `json:"toolCallId"`
	Title      string          `json:"title,omitempty"`
	Kind       string          `json:"kind,omitempty"`
	Status     string          `json:"status,omitempty"`
	RawInput   json.RawMessage `json:"rawInput,omitempty"`
	RawOutput  json.RawMessage `json:"rawOutput,omitempty"`
	Locations  []Location      `json:"locations,omitempty"`
	Meta       json.RawMessage `json:"_meta,omitempty"`
}

// ToolName returns the agent's own tool name when it reports one
// (claude-agent-acp: _meta.claudeCode.toolName).
func (t *ToolCall) ToolName() string {
	var meta struct {
		ClaudeCode struct {
			ToolName string `json:"toolName"`
		} `json:"claudeCode"`
	}
	if len(t.Meta) == 0 || json.Unmarshal(t.Meta, &meta) != nil {
		return ""
	}
	return meta.ClaudeCode.ToolName
}

// Merge applies the fields set in u (a tool_call_update) onto t.
func (t *ToolCall) Merge(u *ToolCall) {
	if u.Title != "" {
		t.Title = u.Title
	}
	if u.Kind != "" {
		t.Kind = u.Kind
	}
	if u.Status != "" {
		t.Status = u.Status
	}
	if len(u.RawInput) > 0 {
		t.RawInput = u.RawInput
	}
	if len(u.RawOutput) > 0 {
		t.RawOutput = u.RawOutput
	}
	if len(u.Locations) > 0 {
		t.Locations = u.Locations
	}
	if len(u.Meta) > 0 {
		t.Meta = u.Meta
	}
}

// PlanEntry is one item of an agent plan.
type PlanEntry struct {
	Content  string `json:"content"`
	Priority string `json:"priority,omitempty"`
	Status   string `json:"status,omitempty"`
}

// PlanUpdate replaces the agent's plan.
type PlanUpdate struct {
	Entries []PlanEntry `json:"entries"`
}

// Cost is a monetary amount.
type Cost struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

// UsageUpdate reports context usage and the session's cumulative cost.
type UsageUpdate struct {
	Used int64 `json:"used"`
	Size int64 `json:"size"`
	Cost *Cost `json:"cost,omitempty"`
}

// PermissionOption is one choice of a permission request.
type PermissionOption struct {
	OptionID string `json:"optionId"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
}

// RequestPermissionParams asks the client to authorise a tool call.
type RequestPermissionParams struct {
	SessionID string             `json:"sessionId"`
	ToolCall  ToolCall           `json:"toolCall"`
	Options   []PermissionOption `json:"options"`
}

// PermissionOutcome is "selected" (with OptionID) or "cancelled".
type PermissionOutcome struct {
	Outcome  string `json:"outcome"`
	OptionID string `json:"optionId,omitempty"`
}

// RequestPermissionResult answers a permission request.
type RequestPermissionResult struct {
	Outcome PermissionOutcome `json:"outcome"`
}

// Selected answers a permission request with one of its options.
func Selected(optionID string) RequestPermissionResult {
	return RequestPermissionResult{Outcome: PermissionOutcome{Outcome: "selected", OptionID: optionID}}
}

// Cancelled answers a permission request whose turn was cancelled.
func Cancelled() RequestPermissionResult {
	return RequestPermissionResult{Outcome: PermissionOutcome{Outcome: "cancelled"}}
}
