// Teleport
// Copyright (C) 2026 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package authcallout

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/gravitational/trace"
)

const (
	// streamWindow is the most stream bytes the pool sends to the proxy
	// before the proxy acknowledges them. The proxy acknowledges every
	// 256 KiB, so a window of 1 MiB keeps data flowing while an ack is on
	// its way.
	streamWindow = 1 << 20
	// streamMessage is the largest message the pool writes on a stream.
	streamMessage = 64 << 10
	// maxPendingRead bounds the bytes from the proxy that wait for a
	// reader. The proxy sends little on a stream: TLS records of requests.
	maxPendingRead = 8 << 20
	// streamIdle closes a stream that has carried no bytes either way for
	// this long, so that a proxy that stops acking or never closes cannot
	// keep a stream and its goroutines forever. The edge closes idle
	// streams after 30 seconds.
	streamIdle = 2 * time.Minute
	// closeTimeout bounds the WebSocket close handshake.
	closeTimeout = 5 * time.Second
)

// flowConn is a [net.Conn] over one on-demand stream. Binary messages carry
// stream bytes in both directions. The proxy sends text "ack <n>", where n
// is the total number of stream bytes it has passed on, and Write keeps at
// most [streamWindow] bytes unacknowledged. A reader goroutine reads the
// WebSocket at all times, so acks arrive even while nobody calls Read.
type flowConn struct {
	ws            *websocket.Conn
	local, remote net.Addr

	mu      sync.Mutex
	cond    *sync.Cond
	pending []byte
	readErr error
	sent    int64
	acked   int64
	closed  bool
	// rdl and wdl are the read and write deadlines.
	rdl, wdl time.Time

	// active is when bytes last crossed in either direction.
	active time.Time

	writeMu   sync.Mutex
	closeOnce sync.Once
	done      chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
}

// newFlowConn wraps ws and starts its reader. Cancelling ctx closes the
// conn.
func newFlowConn(ctx context.Context, ws *websocket.Conn, local, remote net.Addr) *flowConn {
	ctx, cancel := context.WithCancel(ctx)
	c := &flowConn{ws: ws, local: local, remote: remote, done: make(chan struct{}), ctx: ctx, cancel: cancel, active: time.Now()}
	c.cond = sync.NewCond(&c.mu)
	go c.readLoop()
	go c.closeWhenIdle()
	go func() {
		<-ctx.Done()
		c.Close()
	}()
	return c
}

// closeWhenIdle closes the conn once no bytes have crossed for
// [streamIdle].
func (c *flowConn) closeWhenIdle() {
	t := time.NewTimer(streamIdle)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
		}
		c.mu.Lock()
		idle := time.Since(c.active)
		c.mu.Unlock()
		if idle >= streamIdle {
			c.Close()
			return
		}
		t.Reset(streamIdle - idle)
	}
}

// readLoop reads messages until the WebSocket fails: binary messages are
// queued for Read, and text acks open the write window.
func (c *flowConn) readLoop() {
	for {
		typ, msg, err := c.ws.Read(c.ctx)
		c.mu.Lock()
		if err != nil {
			c.readErr = err
			c.cond.Broadcast()
			c.mu.Unlock()
			// A WebSocket that cannot be read carries no more acks, so a
			// writer would wait for good. Close it.
			c.Close()
			return
		}
		switch typ {
		case websocket.MessageBinary:
			if len(c.pending)+len(msg) > maxPendingRead {
				c.readErr = trace.LimitExceeded("more than %d stream bytes wait for a reader", maxPendingRead)
				c.cond.Broadcast()
				c.mu.Unlock()
				c.Close()
				return
			}
			c.pending = append(c.pending, msg...)
			c.active = time.Now()
		case websocket.MessageText:
			n, ok := parseAck(string(msg))
			if !ok || n > c.sent || n < c.acked {
				c.readErr = trace.BadParameter("bad ack on stream")
				c.cond.Broadcast()
				c.mu.Unlock()
				c.Close()
				return
			}
			c.acked = n
			c.active = time.Now()
		}
		c.cond.Broadcast()
		c.mu.Unlock()
	}
}

// parseAck parses "ack <n>".
func parseAck(text string) (int64, bool) {
	rest, ok := strings.CutPrefix(text, "ack ")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	return n, err == nil && n >= 0
}

// Read reads stream bytes from the proxy.
func (c *flowConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.pending) == 0 {
		if c.closed {
			return 0, net.ErrClosed
		}
		if c.readErr != nil {
			return 0, c.readErr
		}
		if !c.rdl.IsZero() && !time.Now().Before(c.rdl) {
			return 0, timeoutError{}
		}
		c.wait(c.rdl)
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	if len(c.pending) == 0 {
		c.pending = nil
	}
	return n, nil
}

// Write writes b as one or more messages, waiting while the window is
// full.
func (c *flowConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	wdl := c.wdl
	c.mu.Unlock()
	if !wdl.IsZero() && !time.Now().Before(wdl) {
		return 0, timeoutError{}
	}
	written := 0
	for len(b) > 0 {
		chunk := b[:min(len(b), streamMessage)]
		c.mu.Lock()
		for c.sent-c.acked+int64(len(chunk)) > streamWindow {
			if c.closed {
				c.mu.Unlock()
				return written, net.ErrClosed
			}
			if c.readErr != nil {
				err := c.readErr
				c.mu.Unlock()
				return written, err
			}
			if !c.wdl.IsZero() && !time.Now().Before(c.wdl) {
				c.mu.Unlock()
				return written, timeoutError{}
			}
			c.wait(c.wdl)
		}
		c.sent += int64(len(chunk))
		c.active = time.Now()
		wdl := c.wdl
		c.mu.Unlock()
		ctx, cancel := c.ctx, context.CancelFunc(func() {})
		if !wdl.IsZero() {
			ctx, cancel = context.WithDeadline(c.ctx, wdl)
		}
		err := c.ws.Write(ctx, websocket.MessageBinary, chunk)
		cancel()
		if err != nil {
			c.mu.Lock()
			closed := c.closed
			c.mu.Unlock()
			if closed {
				return written, net.ErrClosed
			}
			if !wdl.IsZero() && !time.Now().Before(wdl) {
				return written, timeoutError{}
			}
			return written, trace.Wrap(err)
		}
		written += len(chunk)
		b = b[len(chunk):]
	}
	return written, nil
}

// wait waits on cond, waking up at deadline if it is set. c.mu must be
// held.
func (c *flowConn) wait(deadline time.Time) {
	if deadline.IsZero() {
		c.cond.Wait()
		return
	}
	t := time.AfterFunc(time.Until(deadline), func() {
		c.mu.Lock()
		c.cond.Broadcast()
		c.mu.Unlock()
	})
	c.cond.Wait()
	t.Stop()
}

// Close closes the WebSocket. It interrupts a blocked Read or Write.
func (c *flowConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.cond.Broadcast()
		c.mu.Unlock()
		// Close before cancelling: cancelling ctx makes the WebSocket
		// drop the connection with no close frame, which the edge would
		// see as a network drop.
		closed := make(chan struct{})
		go func() {
			c.ws.Close(websocket.StatusNormalClosure, "")
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(closeTimeout):
		}
		c.cancel()
		close(c.done)
	})
	return nil
}

// LocalAddr returns the local address of the WebSocket's TCP connection.
func (c *flowConn) LocalAddr() net.Addr { return c.local }

// RemoteAddr returns the proxy's address, a [*net.TCPAddr].
func (c *flowConn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline sets the read and write deadlines.
func (c *flowConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

// SetReadDeadline sets the read deadline. A Read waiting for bytes returns
// a timeout error when it passes.
func (c *flowConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdl = t
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline sets the write deadline. A Write waiting for the window
// returns a timeout error when it passes.
func (c *flowConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wdl = t
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

// timeoutError is the error of a Read or Write whose deadline passed.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
