// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0
// Derived from the owner-approved snapshot; modified for the standalone candidate.
// See PROVENANCE.md for source and intentional behavior changes.

package acp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

func TestDecoderFramesAcrossPartialReads(t *testing.T) {
	in := "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\r\n" +
		"\n   \n" +
		`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"a\nb"}}}}` + "\n" +
		`{"jsonrpc":"2.0","id":"x","result":null}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"nope"}}` // final frame without newline
	d := NewDecoder(iotest.OneByteReader(strings.NewReader(in)))
	want := []Kind{KindRequest, KindNotification, KindResponse, KindResponse}
	for i, k := range want {
		m, err := d.Next()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if m.Kind() != k {
			t.Fatalf("frame %d: kind %s, want %s", i, m.Kind(), k)
		}
	}
	if _, err := d.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestDecoderRecoversFromBadFrames(t *testing.T) {
	in := "not json at all\n" +
		`{"jsonrpc":"1.0","id":1,"method":"x"}` + "\n" +
		`{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"both"}}` + "\n" +
		strings.Repeat("x", 300) + "\n" +
		`{"jsonrpc":"2.0","method":"ok"}` + "\n"
	d := NewDecoderSize(strings.NewReader(in), 200)
	for i := 0; i < 4; i++ {
		var fe *FrameError
		if _, err := d.Next(); !errors.As(err, &fe) {
			t.Fatalf("bad frame %d: want FrameError, got %v", i, err)
		}
	}
	m, err := d.Next()
	if err != nil || m.Method != "ok" {
		t.Fatalf("decoder did not resynchronise: %v %+v", err, m)
	}
}

func TestEncodeIsOneLine(t *testing.T) {
	var buf bytes.Buffer
	params, _ := json.Marshal(map[string]string{"text": "line1\nline2"})
	if err := Encode(&buf, &Message{Method: "m", Params: params}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") || !strings.Contains(out, `"jsonrpc":"2.0"`) {
		t.Fatalf("frame is not a single JSON line: %q", out)
	}
	m, err := NewDecoder(&buf).Next()
	if err != nil || m.Kind() != KindNotification {
		t.Fatalf("round trip: %v %+v", err, m)
	}
}

// recorder collects notifications and answers requests through a callback.
type recorder struct {
	mu    sync.Mutex
	notes []string
	onReq func(*Request)
}

func (r *recorder) Notification(method string, _ json.RawMessage) {
	r.mu.Lock()
	r.notes = append(r.notes, method)
	r.mu.Unlock()
}
func (r *recorder) Request(req *Request) { r.onReq(req) }

// pipePeer connects a Conn to a scripted peer: the peer reads the client's
// frames from clientOut and writes its own frames to peerOut.
func pipePeer(t *testing.T, h Handler) (*Conn, *Decoder, io.WriteCloser) {
	t.Helper()
	clientOutR, clientOutW := io.Pipe()
	peerOutR, peerOutW := io.Pipe()
	c := NewConn(peerOutR, clientOutW, h, nil)
	t.Cleanup(func() { _ = peerOutW.Close(); _ = clientOutR.Close() })
	return c, NewDecoder(clientOutR), peerOutW
}

func TestConnCorrelatesResponsesAndServesRequests(t *testing.T) {
	rec := &recorder{onReq: func(r *Request) {
		if r.Method == MethodRequestPermission {
			go func() { _ = r.Reply(Selected("allow-once")) }()
			return
		}
		_ = r.Fail(&RPCError{Code: CodeMethodNotFound, Message: "unsupported"})
	}}
	c, peerIn, peerOut := pipePeer(t, rec)
	done := make(chan error, 2)
	var r1, r2 InitializeResult
	go func() { done <- c.Call(context.Background(), "a", nil, &r1) }()
	go func() { done <- c.Call(context.Background(), "b", nil, &r2) }()
	reqs := map[string]json.RawMessage{}
	for i := 0; i < 2; i++ {
		m, err := peerIn.Next()
		if err != nil || m.Kind() != KindRequest {
			t.Fatalf("peer read: %v %+v", err, m)
		}
		reqs[m.Method] = m.ID
	}
	// Answer out of order, interleaved with agent traffic.
	_ = Encode(peerOut, &Message{Method: MethodSessionUpdate, Params: json.RawMessage(`{}`)})
	_ = Encode(peerOut, &Message{ID: json.RawMessage(`"p1"`), Method: MethodRequestPermission, Params: json.RawMessage(`{}`)})
	_ = Encode(peerOut, &Message{ID: json.RawMessage(`"f1"`), Method: "fs/read_text_file", Params: json.RawMessage(`{}`)})
	_ = Encode(peerOut, &Message{ID: reqs["b"], Result: json.RawMessage(`{"protocolVersion":2}`)})
	_ = Encode(peerOut, &Message{ID: reqs["a"], Result: json.RawMessage(`{"protocolVersion":1}`)})
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if r1.ProtocolVersion != 1 || r2.ProtocolVersion != 2 {
		t.Fatalf("responses were not correlated: %d %d", r1.ProtocolVersion, r2.ProtocolVersion)
	}
	answers := map[string]*Message{}
	for i := 0; i < 2; i++ {
		m, err := peerIn.Next()
		if err != nil || m.Kind() != KindResponse {
			t.Fatalf("peer answer: %v %+v", err, m)
		}
		answers[string(m.ID)] = m
	}
	var perm RequestPermissionResult
	if err := json.Unmarshal(answers[`"p1"`].Result, &perm); err != nil || perm.Outcome.OptionID != "allow-once" {
		t.Fatalf("permission answer: %s", answers[`"p1"`].Result)
	}
	if e := answers[`"f1"`].Error; e == nil || e.Code != CodeMethodNotFound {
		t.Fatalf("unsupported client method must be refused: %+v", answers[`"f1"`])
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.notes) != 1 || rec.notes[0] != MethodSessionUpdate {
		t.Fatalf("notifications: %v", rec.notes)
	}
}

func TestConnFailsPendingCallsWhenAgentExits(t *testing.T) {
	c, peerIn, peerOut := pipePeer(t, &recorder{onReq: func(r *Request) {}})
	errc := make(chan error, 1)
	go func() { errc <- c.Call(context.Background(), MethodSessionPrompt, nil, nil) }()
	if _, err := peerIn.Next(); err != nil {
		t.Fatal(err)
	}
	_ = peerOut.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("want ErrClosed, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending call was not released")
	}
	if err := c.Call(context.Background(), "late", nil, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("call after close: %v", err)
	}
	if err := c.Err(); !errors.Is(err, io.EOF) {
		t.Fatalf("close reason: %v", err)
	}
}

func TestToolCallMergeAndToolName(t *testing.T) {
	var call ToolCall
	_ = json.Unmarshal([]byte(`{"toolCallId":"t1","title":"ls","kind":"execute","status":"pending","_meta":{"claudeCode":{"toolName":"Bash"}}}`), &call)
	call.Merge(&ToolCall{ToolCallID: "t1", Status: "completed", RawOutput: json.RawMessage(`"ok"`)})
	if call.Status != "completed" || call.Title != "ls" || call.ToolName() != "Bash" || string(call.RawOutput) != `"ok"` {
		t.Fatalf("merge: %+v", call)
	}
	if kind, err := UpdateKind(json.RawMessage(`{"sessionUpdate":"plan","entries":[]}`)); err != nil || kind != UpdatePlan {
		t.Fatalf("update kind: %q %v", kind, err)
	}
	if _, err := UpdateKind(json.RawMessage(`{}`)); err == nil {
		t.Fatal("update without discriminator must be rejected")
	}
}
