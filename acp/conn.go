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
	"log/slog"
	"strconv"
	"sync"
	"time"
)

// ErrClosed is returned for calls on a connection whose agent went away.
var ErrClosed = errors.New("acp: connection closed")

// Request is an agent→client request. Handlers answer it exactly once,
// possibly later and from another goroutine, with Reply or Fail.
type Request struct {
	ID     json.RawMessage
	Method string
	Params json.RawMessage

	conn *Conn
	once sync.Once
}

// Reply sends a successful result (nil encodes as JSON null).
func (r *Request) Reply(result any) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return r.Fail(&RPCError{Code: CodeInternalError, Message: "result cannot be encoded"})
	}
	return r.send(&Message{ID: r.ID, Result: raw})
}

// Fail sends an error response.
func (r *Request) Fail(e *RPCError) error { return r.send(&Message{ID: r.ID, Error: e}) }

func (r *Request) send(m *Message) error {
	err := errors.New("acp: request already answered")
	r.once.Do(func() { err = r.conn.write(m) })
	return err
}

// Handler receives agent→client traffic in arrival order. Both methods are
// called from the read loop and must not block; answer requests later.
type Handler interface {
	Notification(method string, params json.RawMessage)
	Request(req *Request)
}

// Conn is a JSON-RPC connection to one ACP agent.
// Outgoing frames are queued and written by a dedicated goroutine, so the
// read loop never blocks on a full stdin pipe while the agent is blocked on
// its stdout (the classic two-pipe deadlock).
type Conn struct {
	handler Handler
	log     *slog.Logger

	mu        sync.Mutex
	nextID    int64
	pending   map[string]chan *Message
	err       error
	done      chan struct{}
	closeOnce sync.Once
	reader    io.Closer
	writer    io.Closer

	outMu       sync.Mutex
	out         [][]byte
	writing     bool
	queuedBytes int
	outSig      chan struct{}
}

// NewConn starts reading frames from r; requests go out on w.
func NewConn(r io.Reader, w io.Writer, h Handler, log *slog.Logger) *Conn {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	c := &Conn{handler: h, log: log, pending: map[string]chan *Message{}, done: make(chan struct{}), outSig: make(chan struct{}, 1)}
	c.reader, _ = r.(io.Closer)
	c.writer, _ = w.(io.Closer)
	go c.readLoop(NewDecoder(r))
	go c.writeLoop(w)
	return c
}

// Done is closed when the agent's output ends.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Close stops the connection and closes endpoints that implement io.Closer.
// NewConn takes ownership of those endpoints for its lifetime.
func (c *Conn) Close() error {
	c.finish(ErrClosed)
	return nil
}

func (c *Conn) finish(err error) {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.err = err
		c.mu.Unlock()
		close(c.done)
		if c.reader != nil {
			_ = c.reader.Close()
		}
		if c.writer != nil {
			_ = c.writer.Close()
		}
	})
}

// Err reports why the connection closed (io.EOF for a clean end).
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Conn) write(m *Message) error {
	var buf bytes.Buffer
	if err := Encode(&buf, m); err != nil {
		return err
	}
	if buf.Len() > MaxFrameBytes {
		return errors.New("acp: outgoing frame exceeds limit")
	}
	select {
	case <-c.done:
		return ErrClosed
	default:
	}
	c.outMu.Lock()
	if len(c.out) >= 128 || c.queuedBytes+buf.Len() > 4<<20 {
		c.outMu.Unlock()
		err := errors.New("acp: outgoing queue limit reached")
		c.finish(err)
		return err
	}
	c.out = append(c.out, buf.Bytes())
	c.queuedBytes += buf.Len()
	c.outMu.Unlock()
	select {
	case c.outSig <- struct{}{}:
	default:
	}
	return nil
}

func (c *Conn) writeLoop(w io.Writer) {
	for {
		select {
		case <-c.done:
			return
		case <-c.outSig:
		}
		c.outMu.Lock()
		batch := c.out
		c.out, c.writing = nil, true
		c.queuedBytes = 0
		c.outMu.Unlock()
		for _, frame := range batch {
			n, err := w.Write(frame)
			if err == nil && n != len(frame) {
				err = io.ErrShortWrite
			}
			if err != nil {
				c.log.Warn("acp: write failed", "err", err)
				c.finish(err)
				return
			}
		}
		c.outMu.Lock()
		c.writing = false
		c.outMu.Unlock()
	}
}

// Drain waits until queued frames are written, the connection closes or
// ctx ends, so a final cancellation reaches the agent before its stdin closes.
func (c *Conn) Drain(ctx context.Context) {
	for {
		c.outMu.Lock()
		idle := len(c.out) == 0 && !c.writing
		c.outMu.Unlock()
		if idle {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// Call sends a request and decodes its result into out (which may be nil).
func (c *Conn) Call(ctx context.Context, method string, params, out any) error {
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return ErrClosed
	}
	c.nextID++
	id := strconv.FormatInt(c.nextID, 10)
	ch := make(chan *Message, 1)
	c.pending[id] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()
	if err := c.write(&Message{ID: json.RawMessage(id), Method: method, Params: raw}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		// A response that raced the close is still delivered.
		select {
		case m := <-ch:
			return decodeResult(m, out)
		default:
			return ErrClosed
		}
	case m := <-ch:
		return decodeResult(m, out)
	}
}

func decodeResult(m *Message, out any) error {
	if m.Error != nil {
		return m.Error
	}
	if out == nil || string(m.Result) == "null" {
		return nil
	}
	return json.Unmarshal(m.Result, out)
}

// Notify sends a notification.
func (c *Conn) Notify(method string, params any) error {
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	return c.write(&Message{Method: method, Params: raw})
}

func (c *Conn) readLoop(d *Decoder) {
	var err error
	for {
		var m *Message
		m, err = d.Next()
		var fe *FrameError
		if errors.As(err, &fe) {
			// Agents must keep stdout for protocol frames; tolerate and log noise.
			c.log.Warn("acp: skipped frame", "reason", fe.Reason)
			continue
		}
		if err != nil {
			break
		}
		switch m.Kind() {
		case KindResponse:
			c.mu.Lock()
			ch := c.pending[string(m.ID)]
			c.mu.Unlock()
			if ch != nil {
				// A repeated or late response must not block the read loop.
				select {
				case ch <- m:
				default:
				}
			}
		case KindNotification:
			if c.handler != nil {
				c.handler.Notification(m.Method, m.Params)
			}
		case KindRequest:
			req := &Request{ID: m.ID, Method: m.Method, Params: m.Params, conn: c}
			if c.handler == nil {
				_ = req.Fail(&RPCError{Code: CodeMethodNotFound, Message: "no client handler registered"})
			} else {
				c.handler.Request(req)
			}
		}
	}
	c.finish(err)
}
