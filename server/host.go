// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

// Package server is a new, in-process host facade, not the private platform
// server. It exposes no network listener or persistence. Identity must be
// supplied explicitly by an authenticated embedding application.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/AnachronisticAdmin/anachron-agent-gateway/a2a"
	"github.com/AnachronisticAdmin/anachron-agent-gateway/redact"
)

const maxMessageBytes = 64 << 10
const maxArtifactBytes = 1 << 20

type Principal struct{ ID, Tenant string }
type identityKey struct{}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, identityKey{}, p)
}

type RequestContext struct {
	TaskID    string
	Tenant    string
	Principal Principal
	Task      *a2a.Task
	Message   *a2a.Message
	Metadata  map[string]any
}

type Executor interface {
	Execute(context.Context, *RequestContext, *TaskWriter) error
}
type MessageValidator interface {
	ValidateMessage(*a2a.SendMessageRequest) error
}
type MessageSanitizer interface {
	SanitizeMessage(*a2a.SendMessageRequest) (*a2a.Message, error)
}
type TaskCanceler interface {
	CancelTask(context.Context, *a2a.Task) (bool, error)
}

type Options struct {
	Card        *a2a.AgentCard
	TaskTimeout time.Duration
	MaxTasks    int
	MaxHistory  int
	// Identity is called on every operation. A nil function reads only the
	// explicit WithPrincipal context value; there is no anonymous default.
	Identity func(context.Context) (Principal, error)
}

type record struct {
	execMu sync.Mutex
	mu     sync.Mutex
	owner  Principal
	task   a2a.Task
	cancel context.CancelFunc
}

type Handler struct {
	mu     sync.Mutex
	exec   Executor
	opts   Options
	tasks  map[string]*record
	closed bool
	active sync.WaitGroup
}

func NewHandler(ex Executor, options Options) *Handler {
	if options.TaskTimeout <= 0 {
		options.TaskTimeout = 30 * time.Second
	}
	if options.MaxTasks <= 0 {
		options.MaxTasks = 128
	}
	if options.MaxHistory <= 0 {
		options.MaxHistory = 32
	}
	return &Handler{exec: ex, opts: options, tasks: make(map[string]*record)}
}

func (h *Handler) identity(ctx context.Context) (Principal, error) {
	var p Principal
	var err error
	if h.opts.Identity != nil {
		p, err = h.opts.Identity(ctx)
	} else {
		p, _ = ctx.Value(identityKey{}).(Principal)
	}
	if err != nil || strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.Tenant) == "" {
		return Principal{}, a2a.ErrUnauthorized
	}
	return p, nil
}

func invalid(message string) error {
	return &a2a.APIError{Code: a2a.ErrInvalidParams.Code, Message: message}
}

func clone[T any](value T) (T, error) {
	var out T
	raw, err := json.Marshal(value)
	if err == nil {
		err = json.Unmarshal(raw, &out)
	}
	return out, err
}

func snapshot(r *record) *a2a.Task {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, _ := clone(r.task) // all writes validate JSON before storing it
	return &t
}

func (h *Handler) begin() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.exec == nil {
		return errors.New("gateway is closed or has no executor")
	}
	h.active.Add(1)
	return nil
}

func (h *Handler) SendMessage(ctx context.Context, request *a2a.SendMessageRequest) (*a2a.SendMessageResponse, error) {
	p, err := h.identity(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil || request.Message == nil {
		return nil, invalid("a user message is required")
	}
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > 2*maxMessageBytes {
		return nil, invalid("request is not valid bounded JSON")
	}
	req, err := clone(*request)
	if err != nil {
		return nil, invalid("request cannot be copied")
	}
	m := req.Message
	if m.Role != a2a.RoleUser || m.MessageID == "" || len(m.MessageID) > 256 || len(m.Parts) == 0 {
		return nil, invalid("message needs a user role, bounded message ID and parts")
	}
	if raw, _ := json.Marshal(m); len(raw) > maxMessageBytes {
		return nil, invalid("message exceeds the size limit")
	}
	if v, ok := h.exec.(MessageValidator); ok {
		if err := v.ValidateMessage(&req); err != nil {
			return nil, invalid(redact.String(err.Error()))
		}
	}
	stored, err := clone(m)
	if sanitizer, ok := h.exec.(MessageSanitizer); ok {
		stored, err = sanitizer.SanitizeMessage(&req)
	}
	if err != nil || stored == nil {
		return nil, invalid("message cannot be safely retained")
	}
	if raw, err := json.Marshal(stored); err != nil || len(raw) > maxMessageBytes {
		return nil, invalid("sanitized message exceeds the size limit")
	}
	if err := h.begin(); err != nil {
		return nil, err
	}
	defer h.active.Done()

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, errors.New("gateway is closed")
	}
	var r *record
	followup := m.TaskID != ""
	if followup {
		r = h.tasks[m.TaskID]
		if r == nil || r.owner != p {
			h.mu.Unlock()
			return nil, a2a.ErrTaskNotFound
		}
	} else {
		if len(h.tasks) >= h.opts.MaxTasks {
			h.mu.Unlock()
			return nil, errors.New("gateway task capacity reached")
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			h.mu.Unlock()
			return nil, errors.New("task ID generation failed")
		}
		id := hex.EncodeToString(nonce[:])
		r = &record{owner: p, task: a2a.Task{ID: id, Metadata: map[string]any{}, Status: a2a.TaskStatus{State: a2a.TaskStateSubmitted}}}
		h.tasks[id] = r
	}
	h.mu.Unlock()
	r.execMu.Lock()
	defer r.execMu.Unlock()
	previous := snapshot(r)
	if followup && previous.Status.State != a2a.TaskStateInputRequired {
		return nil, invalid("task is not waiting for input")
	}
	execCtx, cancel := context.WithTimeout(ctx, h.opts.TaskTimeout)
	defer cancel()
	r.mu.Lock()
	r.cancel = cancel
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.cancel = nil; r.mu.Unlock() }()
	writer := &TaskWriter{r: r, maxHistory: h.opts.MaxHistory}
	writer.history(*stored)
	rc := &RequestContext{TaskID: previous.ID, Tenant: p.Tenant, Principal: p, Message: m, Metadata: req.Metadata}
	if rc.Metadata == nil {
		rc.Metadata = map[string]any{}
	}
	if followup {
		rc.Task = previous
	}
	if err := h.exec.Execute(execCtx, rc, writer); err != nil {
		_ = writer.Status(a2a.TaskStateFailed, &a2a.Message{Role: a2a.RoleAgent, Parts: []a2a.Part{a2a.TextPart(redact.String(err.Error()))}})
	}
	return &a2a.SendMessageResponse{Task: snapshot(r)}, nil
}

func (h *Handler) owned(ctx context.Context, id string) (*record, error) {
	p, err := h.identity(ctx)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	r := h.tasks[id]
	h.mu.Unlock()
	if r == nil || r.owner != p {
		return nil, a2a.ErrTaskNotFound
	}
	return r, nil
}

func (h *Handler) GetTask(ctx context.Context, req *a2a.GetTaskRequest) (*a2a.Task, error) {
	if req == nil {
		return nil, invalid("task ID is required")
	}
	r, err := h.owned(ctx, req.ID)
	if err != nil {
		return nil, err
	}
	return snapshot(r), nil
}

func (h *Handler) ListTasks(ctx context.Context, _ *a2a.ListTasksRequest) (*a2a.ListTasksResponse, error) {
	p, err := h.identity(ctx)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	var records []*record
	for _, r := range h.tasks {
		if r.owner == p {
			records = append(records, r)
		}
	}
	h.mu.Unlock()
	out := &a2a.ListTasksResponse{Tasks: []*a2a.Task{}}
	for _, r := range records {
		out.Tasks = append(out.Tasks, snapshot(r))
	}
	sort.Slice(out.Tasks, func(i, j int) bool { return out.Tasks[i].ID < out.Tasks[j].ID })
	return out, nil
}

func (h *Handler) CancelTask(ctx context.Context, req *a2a.CancelTaskRequest) (*a2a.Task, error) {
	if req == nil {
		return nil, invalid("task ID is required")
	}
	r, err := h.owned(ctx, req.ID)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if a2a.Terminal(r.task.Status.State) {
		r.mu.Unlock()
		return nil, invalid("task is already terminal")
	}
	r.task.Status = a2a.TaskStatus{State: a2a.TaskStateCanceled, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	if r.cancel != nil {
		r.cancel()
	}
	r.mu.Unlock()
	if c, ok := h.exec.(TaskCanceler); ok {
		if _, err := c.CancelTask(ctx, snapshot(r)); err != nil {
			return nil, errors.New("executor cancellation failed")
		}
	}
	return snapshot(r), nil
}

// Close withdraws sessions, cancels active calls, and waits for their cleanup.
func (h *Handler) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	var records []*record
	for _, r := range h.tasks {
		records = append(records, r)
	}
	h.mu.Unlock()
	for _, r := range records {
		r.mu.Lock()
		if r.cancel != nil {
			r.cancel()
		}
		r.mu.Unlock()
	}
	if closer, ok := h.exec.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	h.active.Wait()
}

type TaskWriter struct {
	r          *record
	maxHistory int
}

func (w *TaskWriter) history(m a2a.Message) {
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	w.appendHistory(m)
}

func (w *TaskWriter) appendHistory(m a2a.Message) {
	w.r.task.History = append(w.r.task.History, m)
	if len(w.r.task.History) > w.maxHistory {
		w.r.task.History = append([]a2a.Message{}, w.r.task.History[len(w.r.task.History)-w.maxHistory:]...)
	}
}

func (w *TaskWriter) Status(state a2a.TaskState, message *a2a.Message) error {
	switch state {
	case a2a.TaskStateSubmitted, a2a.TaskStateWorking, a2a.TaskStateInputRequired,
		a2a.TaskStateCompleted, a2a.TaskStateCanceled, a2a.TaskStateFailed, a2a.TaskStateRejected:
	default:
		return invalid("unknown task state")
	}
	msg, err := clone(message)
	raw, encodeErr := json.Marshal(msg)
	if err != nil || encodeErr != nil || len(raw) > maxMessageBytes {
		return invalid("status is not valid bounded JSON")
	}
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	if a2a.Terminal(w.r.task.Status.State) {
		return errors.New("task is already terminal")
	}
	w.r.task.Status = a2a.TaskStatus{State: state, Message: msg, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	if msg != nil {
		w.appendHistory(*msg)
	}
	return nil
}

func (w *TaskWriter) Working(text string) error {
	return w.Status(a2a.TaskStateWorking, &a2a.Message{Role: a2a.RoleAgent, Parts: []a2a.Part{a2a.TextPart(text)}})
}
func (w *TaskWriter) Complete(text string) error {
	return w.Status(a2a.TaskStateCompleted, &a2a.Message{Role: a2a.RoleAgent, Parts: []a2a.Part{a2a.TextPart(text)}})
}
func (w *TaskWriter) Reject(text string) error {
	return w.Status(a2a.TaskStateRejected, &a2a.Message{Role: a2a.RoleAgent, Parts: []a2a.Part{a2a.TextPart(text)}})
}

func (w *TaskWriter) SetMetadata(key string, value any) error {
	if key == "" || len(key) > 128 {
		return invalid("metadata key is not bounded")
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > maxMessageBytes {
		return invalid("metadata is not valid bounded JSON")
	}
	var copy any
	_ = json.Unmarshal(raw, &copy)
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	if a2a.Terminal(w.r.task.Status.State) {
		return errors.New("task is already terminal")
	}
	next := make(map[string]any, len(w.r.task.Metadata)+1)
	for k, v := range w.r.task.Metadata {
		next[k] = v
	}
	next[key] = copy
	if raw, err := json.Marshal(next); err != nil || len(next) > 32 || len(raw) > maxMessageBytes {
		return invalid("task metadata capacity reached")
	}
	w.r.task.Metadata = next
	return nil
}

func (w *TaskWriter) Artifact(value a2a.Artifact, appendParts, _ bool) error {
	artifact, err := clone(value)
	raw, encodeErr := json.Marshal(artifact)
	if err != nil || encodeErr != nil || len(raw) > maxArtifactBytes || artifact.ArtifactID == "" {
		return invalid("artifact is not valid bounded JSON")
	}
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	if a2a.Terminal(w.r.task.Status.State) {
		return errors.New("task is already terminal")
	}
	for i, old := range w.r.task.Artifacts {
		if old.ArtifactID != artifact.ArtifactID {
			continue
		}
		if appendParts {
			artifact.Parts = append(old.Parts, artifact.Parts...)
		}
		if raw, _ := json.Marshal(artifact); len(raw) > maxArtifactBytes {
			return invalid("combined artifact exceeds the size limit")
		}
		w.r.task.Artifacts[i] = artifact
		return nil
	}
	if len(w.r.task.Artifacts) >= 16 {
		return invalid("artifact capacity reached")
	}
	w.r.task.Artifacts = append(w.r.task.Artifacts, artifact)
	return nil
}
