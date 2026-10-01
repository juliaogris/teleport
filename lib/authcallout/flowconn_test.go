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
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

// dialAppStream opens an on-demand app stream and returns the edge's end
// and the callout's flowConn.
func dialAppStream(t *testing.T) (*websocket.Conn, net.Conn) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	p := newOnDemandPool(t, e.url(t), priv)
	got := make(chan net.Conn, 1)
	require.NoError(t, p.SetAppHandler(func(c net.Conn) { got <- c }))
	sendDial(t, e.control(t), "app", newStreamID(t))
	s := e.stream(t)
	// The edge accepts messages up to the runtime's limit, larger than the
	// library default.
	s.ws.SetReadLimit(1 << 20)
	select {
	case c := <-got:
		t.Cleanup(func() { c.Close() })
		return s.ws, c
	case <-time.After(5 * time.Second):
		t.Fatal("app handler not called within 5s")
		return nil, nil
	}
}

// readBytes reads binary messages from ws until it has n bytes.
func readBytes(t *testing.T, ws *websocket.Conn, n int) {
	for got := 0; got < n; {
		typ, msg, err := ws.Read(t.Context())
		require.NoError(t, err)
		require.Equal(t, websocket.MessageBinary, typ)
		got += len(msg)
	}
}

func TestFlowConnWritesStopAtTheWindow(t *testing.T) {
	edge, c := dialAppStream(t)
	wrote := make(chan int, 1)
	go func() {
		n, _ := c.Write(make([]byte, 3*streamWindow))
		wrote <- n
	}()

	readBytes(t, edge, streamWindow)
	select {
	case n := <-wrote:
		t.Fatalf("Write returned %d bytes without an ack", n)
	case <-time.After(300 * time.Millisecond):
	}

	// The edge acks only what it has read, as the hub does.
	require.NoError(t, edge.Write(t.Context(), websocket.MessageText, []byte("ack "+strconv.Itoa(streamWindow))))
	readBytes(t, edge, streamWindow)
	require.NoError(t, edge.Write(t.Context(), websocket.MessageText, []byte("ack "+strconv.Itoa(2*streamWindow))))
	readBytes(t, edge, streamWindow)
	select {
	case n := <-wrote:
		require.Equal(t, 3*streamWindow, n)
	case <-time.After(5 * time.Second):
		t.Fatal("Write did not finish after the acks")
	}
}

func TestFlowConnReadsBinaryAndSkipsAcks(t *testing.T) {
	edge, c := dialAppStream(t)
	require.NoError(t, edge.Write(t.Context(), websocket.MessageBinary, []byte("hel")))
	require.NoError(t, edge.Write(t.Context(), websocket.MessageText, []byte("ack 0")))
	require.NoError(t, edge.Write(t.Context(), websocket.MessageBinary, []byte("lo")))
	buf := make([]byte, 5)
	got := 0
	for got < 5 {
		n, err := c.Read(buf[got:])
		require.NoError(t, err)
		got += n
	}
	require.Equal(t, "hello", string(buf))
}

func TestFlowConnBadAckCloses(t *testing.T) {
	for _, ack := range []string{"ack 99", "ack -1", "ack x", "hello"} {
		t.Run(ack, func(t *testing.T) {
			edge, c := dialAppStream(t)
			require.NoError(t, edge.Write(t.Context(), websocket.MessageText, []byte(ack)))
			_, err := c.Read(make([]byte, 1))
			require.Error(t, err)
		})
	}
}

func TestFlowConnReadDeadline(t *testing.T) {
	_, c := dialAppStream(t)
	require.NoError(t, c.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	require.ErrorAs(t, err, &ne)
	require.True(t, ne.Timeout())
	// A write is not held by the read deadline.
	_, err = c.Write([]byte("x"))
	require.NoError(t, err)
}
