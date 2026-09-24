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
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/gravitational/trace"
)

// conn is a [net.Conn] over one WebSocket. Each binary message is a run of
// stream bytes. Reads return first the message the pool read before the
// hand-over.
type conn struct {
	ws *websocket.Conn

	readMu  sync.Mutex
	pending []byte
	reader  io.Reader

	writeMu sync.Mutex

	closeOnce sync.Once
	done      chan struct{}
}

func newConn(ws *websocket.Conn, first []byte) *conn {
	return &conn{ws: ws, pending: first, done: make(chan struct{})}
}

// Read reads stream bytes across WebSocket message boundaries.
func (c *conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	for {
		if c.reader == nil {
			typ, r, err := c.ws.NextReader()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					return 0, io.EOF
				}
				return 0, trace.Wrap(err)
			}
			if typ != websocket.BinaryMessage {
				return 0, trace.BadParameter("unexpected WebSocket message type %d", typ)
			}
			c.reader = r
		}
		n, err := c.reader.Read(b)
		if err == io.EOF {
			c.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

// Write sends b as one binary message.
func (c *conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, trace.Wrap(err)
	}
	return len(b), nil
}

// Close sends a close frame and closes the WebSocket. The pool then opens a
// new one.
func (c *conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.writeMu.Lock()
		msg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
		_ = c.ws.WriteControl(websocket.CloseMessage, msg, time.Now().Add(closeWriteWait))
		c.writeMu.Unlock()
		err = c.ws.Close()
		close(c.done)
	})
	return trace.Wrap(err)
}

// LocalAddr returns the local address of the WebSocket's TCP connection.
func (c *conn) LocalAddr() net.Addr { return c.ws.LocalAddr() }

// RemoteAddr returns the proxy's address, a [*net.TCPAddr].
func (c *conn) RemoteAddr() net.Addr { return c.ws.RemoteAddr() }

// SetDeadline sets the read and write deadlines. After a read deadline
// passes, the WebSocket cannot be read again.
func (c *conn) SetDeadline(t time.Time) error {
	if err := c.ws.SetReadDeadline(t); err != nil {
		return trace.Wrap(err)
	}
	return trace.Wrap(c.ws.SetWriteDeadline(t))
}

// SetReadDeadline sets the read deadline. After it passes, the WebSocket
// cannot be read again.
func (c *conn) SetReadDeadline(t time.Time) error { return trace.Wrap(c.ws.SetReadDeadline(t)) }

// SetWriteDeadline sets the write deadline.
func (c *conn) SetWriteDeadline(t time.Time) error { return trace.Wrap(c.ws.SetWriteDeadline(t)) }
