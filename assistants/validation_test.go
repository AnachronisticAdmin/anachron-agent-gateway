// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

package assistants

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/AnachronisticAdmin/anachron-agent-gateway/acp"
	"github.com/AnachronisticAdmin/anachron-agent-gateway/redact"
)

func TestAgentPermissionsRejectWrongSessionsAndAmbiguousOptions(t *testing.T) {
	option := acp.PermissionOption{OptionID: "allow", Kind: acp.OptionAllowOnce, Name: "synthetic allow"}
	for name, params := range map[string]acp.RequestPermissionParams{
		"wrong session": {SessionID: "other", Options: []acp.PermissionOption{option}},
		"duplicate IDs": {SessionID: "expected", Options: []acp.PermissionOption{option, option}},
		"unknown kind": {SessionID: "expected", Options: []acp.PermissionOption{
			{OptionID: "unknown", Kind: "allow_everything"}}},
		"empty ID": {SessionID: "expected", Options: []acp.PermissionOption{
			{Kind: acp.OptionAllowOnce}}},
		"oversized ID": {SessionID: "expected", Options: []acp.PermissionOption{
			{OptionID: strings.Repeat("x", 257), Kind: acp.OptionAllowOnce}}},
		"no options": {SessionID: "expected"},
	} {
		t.Run(name, func(t *testing.T) {
			clientRead, peerWrite := io.Pipe()
			peerRead, clientWrite := io.Pipe()
			s := &acpSession{taskID: "synthetic", sessionID: "expected", signal: make(chan struct{}, 1)}
			s.conn = acp.NewConn(clientRead, clientWrite, s, nil)
			t.Cleanup(func() { _ = s.conn.Close(); _ = peerWrite.Close(); _ = peerRead.Close() })
			raw, _ := json.Marshal(params)
			if err := acp.Encode(peerWrite, &acp.Message{ID: json.RawMessage(`1`),
				Method: acp.MethodRequestPermission, Params: raw}); err != nil {
				t.Fatal(err)
			}
			replies := make(chan *acp.Message, 1)
			go func() { reply, _ := acp.NewDecoder(peerRead).Next(); replies <- reply }()
			select {
			case reply := <-replies:
				if reply == nil || reply.Error == nil || reply.Error.Code != acp.CodeInvalidParams {
					t.Fatal("malformed permission not rejected")
				}
			case <-time.After(time.Second):
				t.Fatal("malformed permission reply stalled")
			}
			s.mu.Lock()
			queued := len(s.queue)
			s.mu.Unlock()
			if queued != 0 {
				t.Fatal("malformed permission became an approval event")
			}
		})
	}
}

func TestSessionEventQueueFailsClosedAtItsBound(t *testing.T) {
	reader, peerWrite := io.Pipe()
	peerRead, writer := io.Pipe()
	s := &acpSession{signal: make(chan struct{}, 1)}
	s.conn = acp.NewConn(reader, writer, nil, nil)
	defer s.conn.Close()
	defer peerWrite.Close()
	defer peerRead.Close()
	for range 1000 {
		s.push(sessionEvent{kind: evUpdate, raw: json.RawMessage(`{}`)})
	}
	if !s.overloaded || len(s.queue) != 1 || s.queue[0].kind != evClosed {
		t.Fatal("session event backlog not replaced by bounded failure")
	}
	select {
	case <-s.conn.Done():
	default:
		t.Fatal("overflow did not close the transport")
	}
}

func TestStructuredCredentialsAreRedactedBeforeDisplayTruncation(t *testing.T) {
	secret := strings.Repeat("X!3", 2600) + "&\n\"<>"
	raw, _ := json.Marshal(map[string]any{
		"aPadding": strings.Repeat("p", maxRawInput-64),
		"zContent": secret,
	})
	value := redactedJSON(raw, redact.New(secret))
	encoded, _ := json.Marshal(value)
	if strings.Contains(string(encoded), strings.Repeat("X!3", 3)) {
		t.Fatal("escaped credential fragment survived display truncation")
	}
}
