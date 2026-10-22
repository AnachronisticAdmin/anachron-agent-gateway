// Copyright 2026 Julian Wiley
// SPDX-License-Identifier: Apache-2.0
// Derived from the owner-approved snapshot; modified for the standalone candidate.
// See PROVENANCE.md for source and intentional behavior changes.

// Package acp is a client for the Agent Client Protocol (ACP,
// https://agentclientprotocol.com): JSON-RPC 2.0 messages framed as
// newline-delimited JSON over an agent subprocess's stdio.
//
// The gateway is the ACP client; the coding agent (for example Claude Code
// through @agentclientprotocol/claude-agent-acp) is the ACP agent.
package acp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxFrameBytes bounds one JSON-RPC frame in this candidate (1 MiB).
const MaxFrameBytes = 1 << 20

// JSON-RPC 2.0 error codes used by this package.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// Message is one JSON-RPC 2.0 frame: a request, notification or response.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// Kind classifies a Message.
type Kind int

const (
	KindInvalid Kind = iota
	KindRequest
	KindNotification
	KindResponse
)

func (k Kind) String() string {
	return [...]string{"invalid", "request", "notification", "response"}[k]
}

// Kind reports whether m is a request (method and id), a notification
// (method, no id) or a response (id and exactly one of result or error).
func (m *Message) Kind() Kind {
	if m == nil {
		return KindInvalid
	}
	hasID := len(m.ID) > 0 && string(m.ID) != "null"
	if hasID {
		id := bytes.TrimSpace(m.ID)
		if len(id) == 0 || (id[0] != '"' && id[0] != '-' && (id[0] < '0' || id[0] > '9')) {
			return KindInvalid
		}
	}
	switch {
	case m.Method != "" && hasID && m.Result == nil && m.Error == nil:
		return KindRequest
	case m.Method != "" && !hasID && m.Result == nil && m.Error == nil:
		return KindNotification
	case m.Method == "" && hasID && (m.Result != nil) != (m.Error != nil):
		return KindResponse
	}
	return KindInvalid
}

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("acp: %s (code %d)", e.Message, e.Code) }

// FrameError reports one unusable frame. The stream stays usable: the
// decoder resynchronises at the next newline.
type FrameError struct {
	Reason string
	// Excerpt is reserved for caller-provided diagnostics. The decoder
	// deliberately does not populate it, to avoid retaining protocol secrets.
	Excerpt string
}

func (e *FrameError) Error() string {
	if e.Excerpt == "" {
		return "acp: " + e.Reason
	}
	return fmt.Sprintf("acp: %s: %q", e.Reason, e.Excerpt)
}

// Decoder reads newline-delimited JSON-RPC frames.
type Decoder struct {
	r   *bufio.Reader
	max int
}

// NewDecoder returns a Decoder limited to MaxFrameBytes per frame.
func NewDecoder(r io.Reader) *Decoder { return NewDecoderSize(r, MaxFrameBytes) }

// NewDecoderSize returns a Decoder limited to max bytes per frame.
func NewDecoderSize(r io.Reader, max int) *Decoder {
	return &Decoder{r: bufio.NewReaderSize(r, 64<<10), max: max}
}

// Next returns the next frame. Blank lines are skipped and a trailing CR is
// tolerated. Malformed or oversized frames yield a *FrameError, after which
// Next may be called again. The end of input yields io.EOF.
func (d *Decoder) Next() (*Message, error) {
	for {
		line, err := d.readLine()
		if err != nil {
			return nil, err
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var m Message
		if err := json.Unmarshal(line, &m); err != nil {
			return nil, &FrameError{Reason: "malformed JSON frame"}
		}
		if m.JSONRPC != "2.0" || m.Kind() == KindInvalid {
			return nil, &FrameError{Reason: "not a JSON-RPC 2.0 message"}
		}
		return &m, nil
	}
}

func (d *Decoder) readLine() ([]byte, error) {
	var buf []byte
	oversize := false
	for {
		chunk, err := d.r.ReadSlice('\n')
		if !oversize {
			if len(buf)+len(chunk) > d.max {
				oversize, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case err == nil, errors.Is(err, io.EOF) && (len(buf) > 0 || oversize):
			if oversize {
				return nil, &FrameError{Reason: fmt.Sprintf("frame exceeds %d bytes", d.max)}
			}
			return buf, nil
		default:
			return nil, err
		}
	}
}

// Encode writes m as one compact JSON line. encoding/json escapes newlines
// inside strings, so a frame never spans lines.
func Encode(w io.Writer, m *Message) error {
	if m == nil {
		return errors.New("acp: nil message")
	}
	copy := *m
	if copy.JSONRPC == "" {
		copy.JSONRPC = "2.0"
	}
	b, err := json.Marshal(&copy)
	if err != nil {
		return err
	}
	frame := append(b, '\n')
	n, err := w.Write(frame)
	if err == nil && n != len(frame) {
		return io.ErrShortWrite
	}
	return err
}
