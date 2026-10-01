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
	"errors"
	"net"
	"sync"
)

// listener yields connections from a TCP listener and streams from a pool.
type listener struct {
	net.Listener
	pool *Pool

	accepted chan acceptResult
	closed   chan struct{}
	once     sync.Once
}

type acceptResult struct {
	conn net.Conn
	err  error
}

// NewListener returns a listener whose Accept returns both the connections
// of l and the streams of pool. Addr is the address of l. Close closes l but
// not the pool.
func NewListener(l net.Listener, pool *Pool) net.Listener {
	ml := &listener{
		Listener: l,
		pool:     pool,
		accepted: make(chan acceptResult),
		closed:   make(chan struct{}),
	}
	go ml.acceptTCP()
	go ml.acceptPool()
	return ml
}

// acceptTCP forwards every Accept result of the TCP listener until the
// listener is closed. Other errors, such as EMFILE, are forwarded and the
// loop goes on.
func (l *listener) acceptTCP() {
	for {
		c, err := l.Listener.Accept()
		select {
		case l.accepted <- acceptResult{c, err}:
		case <-l.closed:
			if c != nil {
				c.Close()
			}
			return
		}
		if errors.Is(err, net.ErrClosed) {
			return
		}
	}
}

// acceptPool forwards every stream of the pool until the pool or the
// listener is closed.
func (l *listener) acceptPool() {
	for {
		c, err := l.pool.Accept()
		if err != nil {
			return
		}
		select {
		case l.accepted <- acceptResult{c, nil}:
		case <-l.closed:
			c.Close()
			return
		}
	}
}

// Accept returns the next TCP connection or pool stream.
func (l *listener) Accept() (net.Conn, error) {
	select {
	case r := <-l.accepted:
		return r.conn, r.err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close closes the TCP listener.
func (l *listener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.closed)
		err = l.Listener.Close()
	})
	return err
}
