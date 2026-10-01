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
	"strconv"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

// appStream is an open on-demand app stream: the pool, the edge's end and
// the callout's flowConn.
type appStream struct {
	pool *Pool
	edge *websocket.Conn
	conn net.Conn
}

// dialAppStream opens an on-demand app stream.
func dialAppStream(t *testing.T, opts ...func(*Config)) appStream {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	p := newOnDemandPool(t, e.url(t), priv, opts...)
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
		return appStream{pool: p, edge: s.ws, conn: c}
	case <-time.After(5 * time.Second):
		t.Fatal("app handler not called within 5s")
		return appStream{}
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

// readUntilClosed reads ws until it fails and returns the error.
func readUntilClosed(t *testing.T, ws *websocket.Conn) error {
	for {
		if _, _, err := ws.Read(t.Context()); err != nil {
			return err
		}
	}
}

// drain reads and drops what the callout sends, without acking, so a
// writer blocks on the window and not on TCP.
func drain(t *testing.T, ws *websocket.Conn) {
	go readUntilClosed(t, ws)
}

func TestFlowConnReadsBinaryAndSkipsAcks(t *testing.T) {
	s := dialAppStream(t)
	require.NoError(t, s.edge.Write(t.Context(), websocket.MessageBinary, []byte("hel")))
	require.NoError(t, s.edge.Write(t.Context(), websocket.MessageText, []byte("ack 0")))
	require.NoError(t, s.edge.Write(t.Context(), websocket.MessageBinary, []byte("lo")))
	buf := make([]byte, 5)
	_, err := io.ReadFull(s.conn, buf)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buf))
}

func TestFlowConnAcksWhatReadHandsOn(t *testing.T) {
	s := dialAppStream(t)
	chunk := make([]byte, 64<<10)
	for range 5 {
		require.NoError(t, s.edge.Write(t.Context(), websocket.MessageBinary, chunk))
	}
	// Each Read takes at most one chunk, so the total crosses ackEvery
	// exactly at the fourth.
	for range 5 {
		_, err := io.ReadFull(s.conn, chunk)
		require.NoError(t, err)
	}
	typ, msg, err := s.edge.Read(t.Context())
	require.NoError(t, err)
	require.Equal(t, websocket.MessageText, typ)
	require.Equal(t, "ack "+strconv.Itoa(ackEvery), string(msg))
}

func TestFlowConnWritesStopAtTheWindow(t *testing.T) {
	s := dialAppStream(t)
	wrote := make(chan int, 1)
	go func() {
		n, _ := s.conn.Write(make([]byte, 3*streamWindow))
		wrote <- n
	}()

	readBytes(t, s.edge, streamWindow)
	select {
	case n := <-wrote:
		t.Fatalf("Write returned %d bytes without an ack", n)
	case <-time.After(300 * time.Millisecond):
	}

	// The edge acks only what it has read, as the hub does.
	require.NoError(t, s.edge.Write(t.Context(), websocket.MessageText, []byte("ack "+strconv.Itoa(streamWindow))))
	readBytes(t, s.edge, streamWindow)
	require.NoError(t, s.edge.Write(t.Context(), websocket.MessageText, []byte("ack "+strconv.Itoa(2*streamWindow))))
	readBytes(t, s.edge, streamWindow)
	select {
	case n := <-wrote:
		require.Equal(t, 3*streamWindow, n)
	case <-time.After(5 * time.Second):
		t.Fatal("Write did not finish after the acks")
	}
}

func TestFlowConnReadsEOFWhenProxyCloses(t *testing.T) {
	for _, status := range []websocket.StatusCode{websocket.StatusNormalClosure, websocket.StatusGoingAway} {
		t.Run(status.String(), func(t *testing.T) {
			s := dialAppStream(t)
			require.NoError(t, s.edge.Close(status, ""))
			_, err := s.conn.Read(make([]byte, 1))
			require.ErrorIs(t, err, io.EOF)
		})
	}
}

func TestFlowConnCloseSendsCloseFrame(t *testing.T) {
	s := dialAppStream(t)
	require.NoError(t, s.conn.Close())
	err := readUntilClosed(t, s.edge)
	require.Equal(t, websocket.StatusNormalClosure, websocket.CloseStatus(err))
}

func TestFlowConnPoolCloseSendsGoingAway(t *testing.T) {
	s := dialAppStream(t)
	require.NoError(t, s.pool.Close())
	err := readUntilClosed(t, s.edge)
	require.Equal(t, websocket.StatusGoingAway, websocket.CloseStatus(err))
}

func TestFlowConnIdleClosesWithPolicyViolation(t *testing.T) {
	s := dialAppStream(t, func(c *Config) { c.streamIdle = 100 * time.Millisecond })
	err := readUntilClosed(t, s.edge)
	require.Equal(t, websocket.StatusPolicyViolation, websocket.CloseStatus(err))
	_, err = s.conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestFlowConnCloseUnblocksWrite(t *testing.T) {
	s := dialAppStream(t)
	done := make(chan error, 1)
	go func() {
		_, err := s.conn.Write(make([]byte, 2*streamWindow))
		done <- err
	}()
	// The edge never acks, so the writer is parked on the window once the
	// edge has the first window.
	readBytes(t, s.edge, streamWindow)
	require.NoError(t, s.conn.Close())
	select {
	case err := <-done:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(10 * time.Second):
		t.Fatal("Write still blocked after Close")
	}
	err := readUntilClosed(t, s.edge)
	require.Equal(t, websocket.StatusNormalClosure, websocket.CloseStatus(err))
}

func TestFlowConnBadAckCloses(t *testing.T) {
	for _, ack := range []string{"ack 99", "ack -1", "ack x", "hello"} {
		t.Run(ack, func(t *testing.T) {
			s := dialAppStream(t)
			require.NoError(t, s.edge.Write(t.Context(), websocket.MessageText, []byte(ack)))
			_, err := s.conn.Read(make([]byte, 1))
			require.Error(t, err)
			err = readUntilClosed(t, s.edge)
			require.Equal(t, websocket.StatusPolicyViolation, websocket.CloseStatus(err))
		})
	}
}

func TestFlowConnReadDeadline(t *testing.T) {
	s := dialAppStream(t)
	require.NoError(t, s.conn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	_, err := s.conn.Read(make([]byte, 1))
	var ne net.Error
	require.ErrorAs(t, err, &ne)
	require.True(t, ne.Timeout())
	// A write is not held by the read deadline.
	_, err = s.conn.Write([]byte("x"))
	require.NoError(t, err)
}

func TestFlowConnWriteDeadlineWhileWindowFull(t *testing.T) {
	s := dialAppStream(t)
	drain(t, s.edge)
	_, err := s.conn.Write(make([]byte, streamWindow))
	require.NoError(t, err)
	require.NoError(t, s.conn.SetWriteDeadline(time.Now().Add(100*time.Millisecond)))
	_, err = s.conn.Write([]byte("x"))
	var ne net.Error
	require.ErrorAs(t, err, &ne)
	require.True(t, ne.Timeout())
}

func TestFlowConnTooMuchUnreadCloses(t *testing.T) {
	s := dialAppStream(t)
	// The hub sends at most 64 KiB per message.
	chunk := make([]byte, 64<<10)
	for range maxPendingRead/len(chunk) + 1 {
		if err := s.edge.Write(t.Context(), websocket.MessageBinary, chunk); err != nil {
			break
		}
	}
	// Nobody reads, so the bytes pile up past the limit.
	select {
	case <-s.conn.(*flowConn).done:
	case <-time.After(10 * time.Second):
		t.Fatal("the stream stayed open with more than maxPendingRead unread")
	}
	err := readUntilClosed(t, s.edge)
	require.Equal(t, websocket.StatusPolicyViolation, websocket.CloseStatus(err))
}
