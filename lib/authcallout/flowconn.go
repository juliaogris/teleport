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
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/gravitational/trace"
)

const (
	// streamWindow is the most stream bytes either end sends before the
	// other acknowledges them. Each end acknowledges every ackEvery, so a
	// window of 1 MiB keeps data flowing while an ack is on its way. The
	// proxy closes a stream that queues more than 1 MiB, so the window
	// must not grow past that.
	streamWindow = 1 << 20
	// ackEvery is how many received bytes Read hands on between acks.
	ackEvery = 256 << 10
	// streamMessage is the largest message the pool writes on a stream.
	streamMessage = 64 << 10
	// maxPendingRead bounds the bytes from the proxy that wait for a
	// reader. A proxy that applies the window sends at most streamWindow
	// before an ack. Only a proxy without the window reaches this limit,
	// and an upload to an app that reads slower than the link then fails.
	maxPendingRead = 8 << 20
	// streamIdle closes a stream that has carried no bytes either way for
	// this long, so that a proxy that stops acking or never closes cannot
	// keep a stream and its goroutines forever. The proxy closes idle
	// streams after 30 seconds.
	streamIdle = 2 * time.Minute
	// closeTimeout bounds the WebSocket close handshake.
	closeTimeout = 5 * time.Second
)

// flowConn is a [net.Conn] over one on-demand stream. Binary messages carry
// stream bytes in both directions. Each end sends text "ack <n>", where n
// is the total number of stream bytes it has passed on, and keeps at most
// [streamWindow] bytes unacknowledged. A reader goroutine reads the
// WebSocket at all times, so acks arrive even while nobody calls Read.
type flowConn struct {
	ws            *websocket.Conn
	local, remote net.Addr

	mu      sync.Mutex
	cond    *sync.Cond
	pending []byte
	readErr error
	// sent and acked count the bytes written to the proxy and the bytes
	// the proxy acknowledged.
	sent  int64
	acked int64
	// received and ackSent count the bytes Read handed on and the bytes
	// acknowledged to the proxy.
	received      int64
	ackSent       int64
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time

	// active is when bytes last crossed in either direction.
	active time.Time

	writeMu sync.Mutex
	// ackMu orders the acks to the proxy, which must not go backwards.
	ackMu     sync.Mutex
	closeOnce sync.Once
	done      chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
}

// newFlowConn wraps ws and starts its reader. Cancelling ctx closes the
// conn.
func newFlowConn(ctx context.Context, ws *websocket.Conn, local, remote net.Addr) *flowConn {
	ctx, cancel := context.WithCancel(ctx)
	c := &flowConn{
		ws:     ws,
		local:  local,
		remote: remote,
		active: time.Now(),
		done:   make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
	}
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
//
// The read is not bound to the conn's context. A read that ends with the
// context drops the connection with no close frame, so Close ends it
// through the close handshake instead.
func (c *flowConn) readLoop() {
	for {
		typ, msg, err := c.ws.Read(context.Background())
		if err != nil {
			c.fail(readError(err))
			return
		}
		if err := c.receive(typ, msg); err != nil {
			c.fail(err)
			return
		}
	}
}

// readError maps a close with status 1000 or 1001 to [io.EOF], which is
// what the layers above expect from a peer that is done.
func readError(err error) error {
	switch websocket.CloseStatus(err) {
	case websocket.StatusNormalClosure, websocket.StatusGoingAway:
		return io.EOF
	}
	return err
}

// receive queues a binary message for Read or applies a text ack.
func (c *flowConn) receive(typ websocket.MessageType, msg []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.cond.Broadcast()
	switch typ {
	case websocket.MessageBinary:
		if len(c.pending)+len(msg) > maxPendingRead {
			return trace.LimitExceeded("more than %d stream bytes wait for a reader", maxPendingRead)
		}
		c.pending = append(c.pending, msg...)
	case websocket.MessageText:
		n, ok := parseAck(string(msg))
		if !ok || n > c.sent || n < c.acked {
			return trace.BadParameter("bad ack on stream")
		}
		c.acked = n
	}
	c.active = time.Now()
	return nil
}

// fail records err as the error of every later Read and closes the conn.
//
// A WebSocket that cannot be read carries no more acks, so a writer would
// otherwise wait for good.
func (c *flowConn) fail(err error) {
	c.mu.Lock()
	c.readErr = err
	c.cond.Broadcast()
	c.mu.Unlock()
	c.Close()
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

// Read reads stream bytes from the proxy and acknowledges them after every
// [ackEvery].
func (c *flowConn) Read(b []byte) (int, error) {
	n, err := c.take(b)
	if err != nil {
		return 0, err
	}
	c.ack()
	return n, nil
}

// take moves pending bytes into b, waiting for some if none are pending.
func (c *flowConn) take(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.pending) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		if c.closed {
			return 0, net.ErrClosed
		}
		if deadlinePassed(c.readDeadline) {
			return 0, timeoutError{}
		}
		c.wait(c.readDeadline)
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	if len(c.pending) == 0 {
		c.pending = nil
	}
	c.received += int64(n)
	return n, nil
}

// ack sends the proxy the total of bytes handed on, once ackEvery more
// have been since the last ack.
//
// A failed write is not reported: it also fails readLoop's Read, which
// closes the conn.
func (c *flowConn) ack() {
	c.ackMu.Lock()
	defer c.ackMu.Unlock()
	c.mu.Lock()
	if c.received-c.ackSent < ackEvery {
		c.mu.Unlock()
		return
	}
	c.ackSent = c.received
	total := c.received
	c.mu.Unlock()
	c.ws.Write(c.ctx, websocket.MessageText, []byte("ack "+strconv.FormatInt(total, 10)))
}

// Write writes b as one or more messages, waiting while the window is
// full.
func (c *flowConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	deadline := c.writeDeadline
	c.mu.Unlock()
	if deadlinePassed(deadline) {
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
			if deadlinePassed(c.writeDeadline) {
				c.mu.Unlock()
				return written, timeoutError{}
			}
			c.wait(c.writeDeadline)
		}
		c.sent += int64(len(chunk))
		c.active = time.Now()
		deadline := c.writeDeadline
		c.mu.Unlock()
		ctx, cancel := c.writeContext(deadline)
		err := c.ws.Write(ctx, websocket.MessageBinary, chunk)
		cancel()
		if err != nil {
			c.mu.Lock()
			closed := c.closed
			c.mu.Unlock()
			if closed {
				return written, net.ErrClosed
			}
			if deadlinePassed(deadline) {
				return written, timeoutError{}
			}
			return written, trace.Wrap(err)
		}
		written += len(chunk)
		b = b[len(chunk):]
	}
	return written, nil
}

// writeContext returns the context for one WebSocket write: the conn's
// context, bounded by deadline if it is set.
func (c *flowConn) writeContext(deadline time.Time) (context.Context, context.CancelFunc) {
	if deadline.IsZero() {
		return c.ctx, func() {}
	}
	return context.WithDeadline(c.ctx, deadline)
}

// deadlinePassed reports whether deadline is set and has passed.
func deadlinePassed(deadline time.Time) bool {
	return !deadline.IsZero() && !time.Now().Before(deadline)
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

// Close closes the WebSocket with a close handshake. It interrupts a
// blocked Read or Write.
func (c *flowConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.cond.Broadcast()
		c.mu.Unlock()
		closeGracefully(c.ws, websocket.StatusNormalClosure)
		c.cancel()
		close(c.done)
	})
	return nil
}

// closeGracefully performs the close handshake with code, and drops the
// connection if the handshake takes longer than [closeTimeout].
func closeGracefully(ws *websocket.Conn, code websocket.StatusCode) {
	closed := make(chan struct{})
	go func() {
		ws.Close(code, "")
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(closeTimeout):
		ws.CloseNow()
	}
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
	c.readDeadline = t
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline sets the write deadline. A Write waiting for the window
// returns a timeout error when it passes.
func (c *flowConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

// timeoutError is the error of a Read or Write whose deadline passed.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
