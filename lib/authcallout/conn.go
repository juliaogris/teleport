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
	"sync"

	"github.com/coder/websocket"
	"github.com/gravitational/trace"
)

// conn is a [net.Conn] over one WebSocket. Each binary message is a run of
// stream bytes. Reads return first the message the pool read before the
// hand-over. A deadline that passes during a Read or Write closes the conn.
type conn struct {
	net.Conn

	readMu  sync.Mutex
	pending []byte

	local  net.Addr
	remote net.Addr

	closeOnce sync.Once
	done      chan struct{}
}

// newConn wraps ws. Cancelling ctx closes the conn. first is the message
// the pool read before the hand-over. local and remote are the addresses
// of the WebSocket's TCP connection.
func newConn(ctx context.Context, ws *websocket.Conn, first []byte, local, remote net.Addr) *conn {
	nc := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	// NetConn disables the read limit.
	ws.SetReadLimit(readLimit)
	return &conn{
		Conn:    nc,
		pending: first,
		local:   local,
		remote:  remote,
		done:    make(chan struct{}),
	}
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
	return c.Conn.Read(b)
}

// Close closes the WebSocket. It interrupts a blocked Read or Write.
func (c *conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.Conn.Close()
		close(c.done)
	})
	return trace.Wrap(err)
}

// LocalAddr returns the local address of the WebSocket's TCP connection.
func (c *conn) LocalAddr() net.Addr { return c.local }

// RemoteAddr returns the proxy's address, a [*net.TCPAddr].
func (c *conn) RemoteAddr() net.Addr { return c.remote }
