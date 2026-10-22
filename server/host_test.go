// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AnachronisticAdmin/anachron-agent-gateway/a2a"
)

type executorFunc func(context.Context, *RequestContext, *TaskWriter) error

func (f executorFunc) Execute(ctx context.Context, r *RequestContext, w *TaskWriter) error {
	return f(ctx, r, w)
}

func identity(user, tenant string) context.Context {
	return WithPrincipal(context.Background(), Principal{ID: user, Tenant: tenant})
}
func request(id string) *a2a.SendMessageRequest {
	return &a2a.SendMessageRequest{Message: &a2a.Message{MessageID: "synthetic-message", TaskID: id,
		Role: a2a.RoleUser, Parts: []a2a.Part{a2a.TextPart("synthetic prompt")}}}
}

func TestExplicitIdentityAndTenantIsolation(t *testing.T) {
	h := NewHandler(executorFunc(func(_ context.Context, _ *RequestContext, w *TaskWriter) error {
		return w.Status(a2a.TaskStateInputRequired, nil)
	}), Options{})
	defer h.Close()
	if _, err := h.SendMessage(context.Background(), request("")); !errors.Is(err, a2a.ErrUnauthorized) {
		t.Fatalf("anonymous operation accepted: %v", err)
	}
	owner := identity("owner", "tenant-a")
	response, err := h.SendMessage(owner, request(""))
	if err != nil {
		t.Fatal(err)
	}
	id := response.Task.ID
	for _, other := range []context.Context{identity("other", "tenant-a"), identity("owner", "tenant-b")} {
		if _, err := h.GetTask(other, &a2a.GetTaskRequest{ID: id}); !errors.Is(err, a2a.ErrTaskNotFound) {
			t.Fatalf("cross-identity read: %v", err)
		}
		if _, err := h.SendMessage(other, request(id)); !errors.Is(err, a2a.ErrTaskNotFound) {
			t.Fatalf("cross-identity followup: %v", err)
		}
		if _, err := h.CancelTask(other, &a2a.CancelTaskRequest{ID: id}); !errors.Is(err, a2a.ErrTaskNotFound) {
			t.Fatalf("cross-identity cancel: %v", err)
		}
		list, err := h.ListTasks(other, &a2a.ListTasksRequest{})
		if err != nil || len(list.Tasks) != 0 {
			t.Fatal("task enumeration crossed identity")
		}
	}
}

func TestSnapshotsDoNotShareMutableState(t *testing.T) {
	h := NewHandler(executorFunc(func(_ context.Context, _ *RequestContext, w *TaskWriter) error {
		_ = w.SetMetadata("nested", map[string]any{"value": "original"})
		return w.Complete("done")
	}), Options{})
	defer h.Close()
	ctx := identity("owner", "tenant")
	response, err := h.SendMessage(ctx, request(""))
	if err != nil {
		t.Fatal(err)
	}
	response.Task.Metadata["nested"].(map[string]any)["value"] = "changed"
	response.Task.History[0].Parts[0].Text = "changed"
	task, err := h.GetTask(ctx, &a2a.GetTaskRequest{ID: response.Task.ID})
	if err != nil || task.Metadata["nested"].(map[string]any)["value"] != "original" || task.History[0].Text() != "synthetic prompt" {
		t.Fatal("returned snapshot aliases retained state")
	}
}

func TestCapacityInputLimitsAndTerminalFollowups(t *testing.T) {
	h := NewHandler(executorFunc(func(_ context.Context, _ *RequestContext, w *TaskWriter) error {
		return w.Complete("done")
	}), Options{MaxTasks: 1})
	defer h.Close()
	ctx := identity("owner", "tenant")
	bad := request("")
	bad.Message.Parts[0].Text = strings.Repeat("x", maxMessageBytes+1)
	if _, err := h.SendMessage(ctx, bad); err == nil {
		t.Fatal("oversized request accepted")
	}
	response, err := h.SendMessage(ctx, request(""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.SendMessage(ctx, request(response.Task.ID)); err == nil {
		t.Fatal("terminal task accepted a followup")
	}
	if _, err := h.SendMessage(ctx, request("")); err == nil {
		t.Fatal("task capacity ignored")
	}
}

func TestCancelAndCloseInterruptRunningCalls(t *testing.T) {
	for _, mode := range []string{"cancel", "close"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{})
			h := NewHandler(executorFunc(func(ctx context.Context, _ *RequestContext, w *TaskWriter) error {
				_ = w.Working("synthetic work")
				close(started)
				<-ctx.Done()
				return ctx.Err()
			}), Options{TaskTimeout: 5 * time.Second})
			ctx := identity("owner", "tenant")
			done := make(chan *a2a.SendMessageResponse, 1)
			go func() { result, _ := h.SendMessage(ctx, request("")); done <- result }()
			<-started
			tasks, _ := h.ListTasks(ctx, &a2a.ListTasksRequest{})
			if mode == "cancel" {
				task, err := h.CancelTask(ctx, &a2a.CancelTaskRequest{ID: tasks.Tasks[0].ID})
				if err != nil || task.Status.State != a2a.TaskStateCanceled {
					t.Fatal("cancel did not become terminal")
				}
			} else {
				h.Close()
			}
			select {
			case response := <-done:
				if response == nil || (mode == "cancel" && response.Task.Status.State != a2a.TaskStateCanceled) {
					t.Fatal("late executor failure overwrote cancellation")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("call did not stop")
			}
			h.Close()
			if _, err := h.SendMessage(ctx, request("")); err == nil {
				t.Fatal("closed host accepted a call")
			}
		})
	}
}

func TestConcurrentSnapshotReadsAndBoundedHistory(t *testing.T) {
	h := NewHandler(executorFunc(func(_ context.Context, _ *RequestContext, w *TaskWriter) error {
		for range 100 {
			if err := w.Working("synthetic status"); err != nil {
				return err
			}
		}
		return w.Status(a2a.TaskStateInputRequired, nil)
	}), Options{MaxHistory: 4})
	defer h.Close()
	ctx := identity("owner", "tenant")
	response, err := h.SendMessage(ctx, request(""))
	if err != nil || len(response.Task.History) != 4 {
		t.Fatalf("history bound: %v", err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				task, err := h.GetTask(ctx, &a2a.GetTaskRequest{ID: response.Task.ID})
				if err != nil {
					t.Error(err)
				}
				if _, err := json.Marshal(task); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
}
