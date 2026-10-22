// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

// Command gateway-demo exercises only its own synthetic subprocess. It never
// installs a provider, opens a listener, or captures desktop/audio/video data.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AnachronisticAdmin/anachron-agent-gateway/a2a"
	"github.com/AnachronisticAdmin/anachron-agent-gateway/assistants"
	"github.com/AnachronisticAdmin/anachron-agent-gateway/internal/acpfake"
	"github.com/AnachronisticAdmin/anachron-agent-gateway/server"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--internal-fake-acp" {
		os.Exit(acpfake.Run(os.Stdin, os.Stdout, os.Stderr))
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "synthetic demo failed:", err)
		os.Exit(1)
	}
}

func run() error {
	allow := flag.Bool("allow-synthetic-write", false, "explicitly permit only the fake fixture's temporary-file write")
	cancel := flag.Bool("cancel", false, "cancel the synthetic paused task without approving it")
	flag.Parse()
	if *allow && *cancel {
		return errors.New("choose approval or cancellation, not both")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	root, err := os.MkdirTemp("", "agent-gateway-synthetic-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	executor, err := assistants.NewACPExecutor(assistants.ACPConfig{
		Command: []string{exe, "--internal-fake-acp"}, WorkDir: root, WorkDirRoot: root,
	})
	if err != nil {
		return err
	}
	host := server.NewHandler(executor, server.Options{})
	defer host.Close()
	ctx := server.WithPrincipal(context.Background(), server.Principal{ID: "synthetic-demo", Tenant: "synthetic-local"})
	first, err := host.SendMessage(ctx, &a2a.SendMessageRequest{Message: &a2a.Message{
		MessageID: "synthetic-initial", Role: a2a.RoleUser, Parts: []a2a.Part{a2a.TextPart("synthetic permission demonstration")},
	}})
	if err != nil {
		return err
	}
	task := first.Task
	if task.Status.State != a2a.TaskStateInputRequired || task.Status.Message == nil {
		return errors.New("fixture did not pause for permission")
	}
	output := filepath.Join(root, acpfake.OutputFile)
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		return errors.New("fixture changed the workspace before approval")
	}
	decision := "reject"
	if *cancel {
		decision = "cancel"
		task, err = host.CancelTask(ctx, &a2a.CancelTaskRequest{ID: task.ID})
	} else {
		var permission assistants.PermissionRequestData
		for _, part := range task.Status.Message.Parts {
			if len(part.Data) != 0 {
				_ = json.Unmarshal(part.Data, &permission)
				if permission.Type == assistants.DataPermissionRequest {
					break
				}
			}
		}
		if permission.RequestID == "" {
			return errors.New("fixture did not supply a correlated permission request")
		}
		if *allow {
			decision = "allow-once"
		}
		result, sendErr := host.SendMessage(ctx, &a2a.SendMessageRequest{Message: &a2a.Message{
			MessageID: "synthetic-decision", TaskID: task.ID, Role: a2a.RoleUser,
			Parts: []a2a.Part{a2a.DataPart(map[string]any{
				"type": assistants.DataPermissionDecision, "requestId": permission.RequestID,
				"outcome": "selected", "optionId": decision,
			})},
		}})
		err = sendErr
		if result != nil {
			task = result.Task
		}
	}
	if err != nil {
		return err
	}
	_, statErr := os.Stat(output)
	created := statErr == nil
	if created != *allow || !a2a.Terminal(task.Status.State) || executor.LiveSessions() != 0 {
		return errors.New("fixture result or owned-process cleanup did not match the decision")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"fixture": "local-synthetic-only", "pausedBeforeDecision": true, "fileExistedBeforeDecision": false,
		"decision": decision, "finalState": task.Status.State, "syntheticFileCreated": created,
		"liveSessionsAfterDecision": executor.LiveSessions(), "desktopMediaCaptured": false,
	})
}
