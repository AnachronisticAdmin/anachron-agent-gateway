// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

// Package a2a defines the candidate's deliberately small host-side message
// contract. It is not a complete A2A schema, transport, SDK or conformance claim.
// Production adapters must authenticate callers and translate their A2A SDK's
// messages and errors explicitly.
package a2a

import (
	"encoding/json"
	"errors"
	"strings"
)

type Role string

const (
	RoleUser  Role = "user"
	RoleAgent Role = "agent"
)

type Part struct {
	Text string          `json:"text,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

func TextPart(text string) Part { return Part{Text: text} }
func DataPart(value any) Part {
	raw, err := json.Marshal(value)
	if err != nil {
		return Part{}
	}
	return Part{Data: raw}
}

type Message struct {
	MessageID string         `json:"messageId,omitempty"`
	TaskID    string         `json:"taskId,omitempty"`
	Role      Role           `json:"role"`
	Parts     []Part         `json:"parts"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

func (m *Message) Text() string {
	if m == nil {
		return ""
	}
	var parts []string
	for _, p := range m.Parts {
		if p.Text != "" {
			parts = append(parts, p.Text)
		}
	}
	return strings.Join(parts, "\n")
}

type TaskState string

const (
	TaskStateSubmitted     TaskState = "submitted"
	TaskStateWorking       TaskState = "working"
	TaskStateInputRequired TaskState = "input-required"
	TaskStateCompleted     TaskState = "completed"
	TaskStateCanceled      TaskState = "canceled"
	TaskStateFailed        TaskState = "failed"
	TaskStateRejected      TaskState = "rejected"
)

func Terminal(s TaskState) bool {
	return s == TaskStateCompleted || s == TaskStateCanceled || s == TaskStateFailed || s == TaskStateRejected
}

type TaskStatus struct {
	State     TaskState `json:"state"`
	Message   *Message  `json:"message,omitempty"`
	Timestamp string    `json:"timestamp"`
}

type Artifact struct {
	ArtifactID string         `json:"artifactId"`
	Name       string         `json:"name,omitempty"`
	Parts      []Part         `json:"parts"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

type Task struct {
	ID        string         `json:"id"`
	Status    TaskStatus     `json:"status"`
	History   []Message      `json:"history,omitempty"`
	Artifacts []Artifact     `json:"artifacts,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type SendMessageRequest struct {
	Message  *Message       `json:"message"`
	Metadata map[string]any `json:"metadata,omitempty"`
}
type SendMessageResponse struct {
	Task *Task `json:"task,omitempty"`
}
type GetTaskRequest struct{ ID string }
type CancelTaskRequest struct{ ID string }
type ListTasksRequest struct{}
type ListTasksResponse struct{ Tasks []*Task }

type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string { return e.Message }

var (
	ErrInvalidParams = &APIError{Code: -32602, Message: "invalid parameters"}
	ErrTaskNotFound  = &APIError{Code: -32001, Message: "task not found"}
	ErrUnauthorized  = &APIError{Code: -32002, Message: "explicit caller identity is required"}
)

func AsError(err error) *APIError {
	if err == nil {
		return nil
	}
	var api *APIError
	if errors.As(err, &api) {
		return api
	}
	return &APIError{Code: -32603, Message: "internal gateway error"}
}

// These descriptors are informational; the candidate implements no HTTP
// endpoint, SSE transport, push notification service or public discovery URL.
type AgentInterface struct {
	URL     string `json:"url"`
	Binding string `json:"binding,omitempty"`
}
type AgentProvider struct {
	Organization string `json:"organization"`
	URL          string `json:"url"`
}
type AgentCapabilities struct {
	Streaming         *bool `json:"streaming,omitempty"`
	PushNotifications *bool `json:"pushNotifications,omitempty"`
}
type AgentSkill struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Examples    []string `json:"examples,omitempty"`
}
type AgentCard struct {
	Name                string            `json:"name"`
	Description         string            `json:"description"`
	Version             string            `json:"version"`
	SupportedInterfaces []AgentInterface  `json:"supportedInterfaces,omitempty"`
	Provider            *AgentProvider    `json:"provider,omitempty"`
	Capabilities        AgentCapabilities `json:"capabilities"`
	DefaultInputModes   []string          `json:"defaultInputModes"`
	DefaultOutputModes  []string          `json:"defaultOutputModes"`
	Skills              []AgentSkill      `json:"skills"`
}

func Bool(value bool) *bool { return &value }
