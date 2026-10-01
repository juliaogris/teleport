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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

// countingConn counts the bytes read from a [net.Conn].
type countingConn struct {
	net.Conn
	read *atomic.Int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read.Add(int64(n))
	return n, err
}

// TestReadLimitCountsInflatedBytes checks the library behavior the pool's
// read limit relies on: the limit counts the bytes of a message after
// inflation, not the bytes on the wire.
func TestReadLimitCountsInflatedBytes(t *testing.T) {
	const limit = 64 << 10
	compressed := &websocket.AcceptOptions{CompressionMode: websocket.CompressionContextTakeover}
	ctx := t.Context()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, compressed)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		if err := ws.Write(ctx, websocket.MessageBinary, make([]byte, 4*limit)); err != nil {
			return
		}
		ws.Read(ctx)
	}))
	t.Cleanup(srv.Close)

	var wire atomic.Int64
	transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := net.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		return &countingConn{Conn: c, read: &wire}, nil
	}}
	opts := &websocket.DialOptions{
		HTTPClient:      &http.Client{Transport: transport},
		CompressionMode: websocket.CompressionContextTakeover,
	}
	ws, _, err := websocket.Dial(t.Context(), "ws"+strings.TrimPrefix(srv.URL, "http"), opts)
	require.NoError(t, err)
	t.Cleanup(func() { ws.CloseNow() })

	ws.SetReadLimit(limit)
	_, _, err = ws.Read(t.Context())
	require.ErrorIs(t, err, websocket.ErrMessageTooBig)
	require.Less(t, wire.Load(), int64(limit), "the message was not compressed on the wire")
}
