// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type brokenWriter struct{ err error }

func (w brokenWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWriteFailureClosesPendingCalls(t *testing.T) {
	reader, peer := io.Pipe()
	defer peer.Close()
	sentinel := errors.New("synthetic write failure")
	c := NewConn(reader, brokenWriter{sentinel}, &recorder{}, nil)
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Call(ctx, "synthetic", nil, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("pending call did not fail promptly: %v", err)
	}
	if !errors.Is(c.Err(), sentinel) {
		t.Fatal("write failure reason lost")
	}
}

func TestOutgoingBackpressureIsBounded(t *testing.T) {
	reader, peerOut := io.Pipe()
	peerIn, writer := io.Pipe()
	defer peerOut.Close()
	defer peerIn.Close()
	c := NewConn(reader, writer, &recorder{}, nil)
	defer c.Close()
	var err error
	for range 1000 {
		err = c.Notify("synthetic", map[string]string{"text": "synthetic"})
		if err != nil {
			break
		}
	}
	if err == nil {
		t.Fatal("unbounded queue accepted all notifications")
	}
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Fatal("saturated connection remained open")
	}
}

func TestInvalidIDsAndFramesDoNotRetainRawSecrets(t *testing.T) {
	for _, id := range []string{"true", "false", "{}", "[]"} {
		line := `{"jsonrpc":"2.0","id":` + id + `,"method":"synthetic","params":{"password":"synthetic-sensitive-value"}}` + "\n"
		_, err := NewDecoder(strings.NewReader(line)).Next()
		if err == nil || strings.Contains(err.Error(), "synthetic-sensitive-value") {
			t.Fatalf("invalid ID accepted or frame content retained: %v", err)
		}
	}
}

func FuzzDecoder(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n"))
	f.Add([]byte("not-json\n"))
	f.Add([]byte(`{"jsonrpc":"2.0","id":false,"result":null}` + "\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		d := NewDecoderSize(strings.NewReader(string(raw)), 1024)
		for range 16 {
			m, err := d.Next()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				continue
			}
			if m.Kind() == KindInvalid || m.JSONRPC != "2.0" {
				t.Fatal("invalid frame accepted")
			}
			if _, err := json.Marshal(m); err != nil {
				t.Fatal(err)
			}
		}
	})
}
