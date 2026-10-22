// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

package assistants

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"

	"github.com/AnachronisticAdmin/anachron-agent-gateway/a2a"
)

const ResponseArtifactID = "response"

// Initial prompts require text. Permission replies use typed data parts.
func renderParts(parts []a2a.Part) string {
	m := a2a.Message{Parts: parts}
	return m.Text()
}

type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = append([]byte{}, b.buf[len(b.buf)-b.max:]...)
	}
	return n, nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(bytes.TrimSpace(b.buf))
}

// SanitizeMessage keeps known per-request MCP credentials out of retained
// user history without modifying the prompt sent to the selected agent.
func (e *ACPExecutor) SanitizeMessage(req *a2a.SendMessageRequest) (*a2a.Message, error) {
	red := e.cfg.Redactor
	var environmentSecrets []string
	for _, entry := range agentEnv(e.cfg.EnvNames, e.cfg.EnvPrefixes, e.cfg.Env) {
		if name, value, ok := strings.Cut(entry, "="); ok && secretNameRE.MatchString(name) {
			environmentSecrets = append(environmentSecrets, value)
		}
	}
	red = red.WithSecrets(environmentSecrets...)
	if value, present := req.Metadata[MetaMCPServers]; present {
		raw, err := json.Marshal(value)
		servers, parseErr := ParseMCPServers(raw)
		if err != nil || parseErr != nil {
			return &a2a.Message{MessageID: req.Message.MessageID, TaskID: req.Message.TaskID, Role: req.Message.Role,
				Parts: []a2a.Part{a2a.TextPart("[invalid MCP request: user message withheld from history]")}}, nil
		}
		var values []string
		for _, s := range servers {
			values = append(values, s.secrets()...)
		}
		red = red.WithSecrets(values...)
	}
	raw, err := json.Marshal(req.Message)
	if err != nil {
		return nil, err
	}
	var result a2a.Message
	if err = json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	result.MessageID = red.String(result.MessageID)
	result.TaskID = red.String(result.TaskID)
	for i := range result.Parts {
		result.Parts[i].Text = red.String(result.Parts[i].Text)
		if len(result.Parts[i].Data) != 0 {
			result.Parts[i].Data, err = json.Marshal(redactedJSON(result.Parts[i].Data, red))
			if err != nil {
				return nil, err
			}
		}
	}
	if result.Metadata != nil {
		result.Metadata = redactStrings(result.Metadata, red).(map[string]any)
	}
	return &result, nil
}
