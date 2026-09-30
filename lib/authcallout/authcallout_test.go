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
	"bytes"
	"compress/flate"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

// fakeHub is the proxy side of the callout. It sends a nonce, checks the
// signature against pub, and hands each verified WebSocket to verified.
type fakeHub struct {
	pub      ed25519.PublicKey
	dials    atomic.Int32
	verified chan *websocket.Conn
	srv      *httptest.Server
}

func newFakeHub(t *testing.T, pub ed25519.PublicKey) *fakeHub {
	h := &fakeHub{pub: pub, verified: make(chan *websocket.Conn, 64)}
	ctx := t.Context()
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.dials.Add(1)
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		nonce := make([]byte, NonceSize)
		rand.Read(nonce)
		if err := ws.Write(ctx, websocket.MessageBinary, nonce); err != nil {
			ws.CloseNow()
			return
		}
		_, reply, err := ws.Read(ctx)
		if err != nil || len(reply) != NonceSize+ed25519.SignatureSize {
			ws.CloseNow()
			return
		}
		msg := SignedMessage(r.Host, nonce, reply[:NonceSize])
		if !ed25519.Verify(h.pub, msg, reply[NonceSize:]) {
			ws.CloseNow()
			return
		}
		h.verified <- ws
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *fakeHub) url(t *testing.T) *url.URL {
	u, err := url.Parse("ws" + strings.TrimPrefix(h.srv.URL, "http") + "/tunnel/auth")
	require.NoError(t, err)
	return u
}

func (h *fakeHub) next(t *testing.T) *websocket.Conn {
	select {
	case ws := <-h.verified:
		t.Cleanup(func() { ws.CloseNow() })
		return ws
	case <-time.After(5 * time.Second):
		t.Fatal("no verified WebSocket within 5s")
		return nil
	}
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func newPool(t *testing.T, u *url.URL, key ed25519.PrivateKey, size int) *Pool {
	p, err := New(Config{URL: u, Key: key, Size: size, DialsPerMinute: 6000})
	require.NoError(t, err)
	p.Start()
	t.Cleanup(func() { p.Close() })
	return p
}

// acceptStream has the hub start a stream with first and returns the
// stream from p.Accept.
func acceptStream(t *testing.T, p *Pool, ws *websocket.Conn, first string) net.Conn {
	require.NoError(t, ws.Write(t.Context(), websocket.MessageBinary, []byte(first)))
	c, err := p.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	return c
}

func TestCheckURL(t *testing.T) {
	for _, tc := range []struct {
		url     string
		wantErr bool
	}{
		{url: "wss://teleport.example.com/tunnel/auth", wantErr: false},
		{url: "ws://localhost:8787/tunnel/auth", wantErr: false},
		{url: "ws://127.0.0.1:8787/tunnel/auth", wantErr: false},
		{url: "ws://192.168.1.10:8787/tunnel/auth", wantErr: false},
		{url: "ws://teleport.example.com/tunnel/auth", wantErr: true},
		{url: "ws://8.8.8.8/tunnel/auth", wantErr: true},
		{url: "https://teleport.example.com/tunnel/auth", wantErr: true},
	} {
		t.Run(tc.url, func(t *testing.T) {
			u, err := url.Parse(tc.url)
			require.NoError(t, err)
			err = CheckURL(u)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestPoolOpensSize(t *testing.T) {
	pub, priv := newKey(t)
	hub := newFakeHub(t, pub)
	newPool(t, hub.url(t), priv, 3)
	for range 3 {
		hub.next(t)
	}
	select {
	case <-hub.verified:
		t.Fatal("pool opened more WebSockets than its size")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestPoolFirstByteAndEcho(t *testing.T) {
	pub, priv := newKey(t)
	hub := newFakeHub(t, pub)
	p := newPool(t, hub.url(t), priv, 1)
	ws := hub.next(t)
	c := acceptStream(t, p, ws, "hello")
	require.NoError(t, ws.Write(t.Context(), websocket.MessageBinary, []byte("world")))

	var got []byte
	buf := make([]byte, 3)
	for len(got) < len("helloworld") {
		n, err := c.Read(buf)
		require.NoError(t, err)
		got = append(got, buf[:n]...)
	}
	require.Equal(t, "helloworld", string(got))

	_, err := c.Write([]byte("back"))
	require.NoError(t, err)
	_, reply, err := ws.Read(t.Context())
	require.NoError(t, err)
	require.Equal(t, "back", string(reply))

	require.IsType(t, &net.TCPAddr{}, c.RemoteAddr())
	require.IsType(t, &net.TCPAddr{}, c.LocalAddr())

	go ws.Close(websocket.StatusNormalClosure, "")
	_, err = c.Read(buf)
	require.ErrorIs(t, err, io.EOF)
}

func TestPoolReplacesStreamClosedBeforeFirstMessage(t *testing.T) {
	pub, priv := newKey(t)
	hub := newFakeHub(t, pub)
	newPool(t, hub.url(t), priv, 1)
	hub.next(t).CloseNow()
	hub.next(t)
}

func TestPoolReplacesAcceptedStream(t *testing.T) {
	pub, priv := newKey(t)
	hub := newFakeHub(t, pub)
	p := newPool(t, hub.url(t), priv, 1)
	ws := hub.next(t)
	c := acceptStream(t, p, ws, "x")
	// The hub reads so that it answers the close frame.
	go ws.Read(t.Context())
	require.NoError(t, c.Close())
	hub.next(t)
}

func TestPoolReplacesRejectedSignature(t *testing.T) {
	pub, _ := newKey(t)
	_, wrong := newKey(t)
	hub := newFakeHub(t, pub)
	newPool(t, hub.url(t), wrong, 1)
	require.Eventually(t, func() bool { return hub.dials.Load() >= 2 }, 5*time.Second, 10*time.Millisecond)
	require.Empty(t, hub.verified)
}

func TestPoolDoesNotFollowRedirects(t *testing.T) {
	pub, priv := newKey(t)
	hub := newFakeHub(t, pub)
	var redirects atomic.Int32
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirects.Add(1)
		http.Redirect(w, r, hub.srv.URL+"/tunnel/auth", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)
	u, err := url.Parse("ws" + strings.TrimPrefix(redirector.URL, "http") + "/tunnel/auth")
	require.NoError(t, err)

	newPool(t, u, priv, 1)
	require.Eventually(t, func() bool { return redirects.Load() >= 2 }, 5*time.Second, 10*time.Millisecond)
	require.Zero(t, hub.dials.Load())
}

func TestPoolDialTimesOut(t *testing.T) {
	_, priv := newKey(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	accepted := make(chan net.Conn, 64)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
			accepted <- c
		}
	}()
	u, err := url.Parse("ws://" + l.Addr().String() + "/tunnel/auth")
	require.NoError(t, err)

	p, err := New(Config{URL: u, Key: priv, Size: 1, DialsPerMinute: 6000, DialTimeout: 100 * time.Millisecond})
	require.NoError(t, err)
	p.Start()
	t.Cleanup(func() { p.Close() })
	require.Eventually(t, func() bool { return len(accepted) >= 2 }, 5*time.Second, 10*time.Millisecond)
}

func TestPoolRejectsServerChosenCompression(t *testing.T) {
	_, priv := newKey(t)
	// The hub sends the nonce right after the handshake. A client that
	// accepts the compression answers it. A rejected dial reads up to 1 KiB
	// of the body before it closes, so a padding frame keeps the test short.
	var tail bytes.Buffer
	writeFrame(t, &tail, false, opcodeBinary, make([]byte, NonceSize))
	writeFrame(t, &tail, false, opcodeBinary, make([]byte, 1024))
	extension := "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n"
	hub := newRawHub(t, extension, tail.Bytes())
	newPool(t, hub.url(t), priv, 1)

	c := hub.next(t)
	n, err := c.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF, "the pool sent bytes on a WebSocket with compression it did not offer")
	require.Zero(t, n)
	hub.next(t)
}

func TestPoolRejectsCompressedFrame(t *testing.T) {
	_, priv := newKey(t)
	hub := newRawHub(t, "", nil)
	p := newPool(t, hub.url(t), priv, 1)

	c := hub.next(t)
	writeFrame(t, c, false, opcodeBinary, make([]byte, NonceSize))
	opcode, reply := readFrame(t, c)
	require.Equal(t, byte(opcodeBinary), opcode)
	require.Len(t, reply, NonceSize+ed25519.SignatureSize)

	// One MiB of zeros deflates to about 1 KiB.
	var deflated bytes.Buffer
	zw, err := flate.NewWriter(&deflated, flate.BestCompression)
	require.NoError(t, err)
	_, err = zw.Write(make([]byte, 1<<20))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.Less(t, deflated.Len(), readLimit)
	writeFrame(t, c, true, opcodeBinary, deflated.Bytes())

	opcode, payload := readFrame(t, c)
	require.Equal(t, byte(opcodeClose), opcode)
	require.Equal(t, uint16(websocket.StatusProtocolError), binary.BigEndian.Uint16(payload))
	select {
	case <-p.conns:
		t.Fatal("pool accepted a stream whose first frame was compressed")
	default:
	}
	hub.next(t)
}

func TestConnCloseBreaksBlockedWrite(t *testing.T) {
	pub, priv := newKey(t)
	hub := newFakeHub(t, pub)
	p := newPool(t, hub.url(t), priv, 1)
	c := acceptStream(t, p, hub.next(t), "x")

	// The hub never reads, so writes stall once the socket buffers fill.
	var written atomic.Int64
	writeErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, err := c.Write(buf)
			written.Add(int64(n))
			if err != nil {
				writeErr <- err
				return
			}
		}
	}()
	stalled := func() bool {
		before := written.Load()
		time.Sleep(50 * time.Millisecond)
		return before > 0 && written.Load() == before
	}
	require.Eventually(t, stalled, 10*time.Second, 10*time.Millisecond)

	closed := make(chan struct{})
	go func() {
		c.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close waited behind the blocked Write")
	}
	select {
	case err := <-writeErr:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Write did not return after Close")
	}
}

func TestPoolStopKeepsAcceptedStreams(t *testing.T) {
	pub, priv := newKey(t)
	hub := newFakeHub(t, pub)
	p := newPool(t, hub.url(t), priv, 2)
	used, idle := hub.next(t), hub.next(t)
	c := acceptStream(t, p, used, "x")

	p.Stop()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, _, err := idle.Read(ctx)
	require.Error(t, err, "Stop left an idle WebSocket open")
	_, err = p.Accept()
	require.ErrorIs(t, err, net.ErrClosed)

	_, err = c.Write([]byte("still open"))
	require.NoError(t, err)
	_, got, err := used.Read(ctx)
	require.NoError(t, err)
	require.Equal(t, "still open", string(got))

	// The hub reads so that it answers the close frame.
	go used.Read(ctx)
	require.NoError(t, c.Close())
	select {
	case <-hub.verified:
		t.Fatal("pool dialed after Stop")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestPoolCloseClosesAll(t *testing.T) {
	pub, priv := newKey(t)
	hub := newFakeHub(t, pub)
	p := newPool(t, hub.url(t), priv, 2)
	a, b := hub.next(t), hub.next(t)

	require.NoError(t, p.Close())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for _, ws := range []*websocket.Conn{a, b} {
		_, _, err := ws.Read(ctx)
		require.Error(t, err)
	}
	_, err := p.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestListenerMergesPoolAndTCP(t *testing.T) {
	pub, priv := newKey(t)
	hub := newFakeHub(t, pub)
	p := newPool(t, hub.url(t), priv, 1)
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	l := NewListener(tcp, p)
	t.Cleanup(func() { l.Close() })

	require.NoError(t, hub.next(t).Write(t.Context(), websocket.MessageBinary, []byte("x")))
	c, err := l.Accept()
	require.NoError(t, err)
	require.IsType(t, &conn{}, c)

	d, err := net.Dial("tcp", tcp.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	c, err = l.Accept()
	require.NoError(t, err)
	require.IsType(t, &net.TCPConn{}, c)

	require.NoError(t, l.Close())
	_, err = l.Accept()
	require.ErrorIs(t, err, net.ErrClosed)
}

// scriptedListener returns the Accept results a test feeds it.
type scriptedListener struct {
	results chan acceptResult
	closed  chan struct{}
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	select {
	case r := <-l.results:
		return r.conn, r.err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *scriptedListener) Close() error {
	close(l.closed)
	return nil
}

func (l *scriptedListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestListenerKeepsAcceptingAfterTCPError(t *testing.T) {
	pub, priv := newKey(t)
	hub := newFakeHub(t, pub)
	p := newPool(t, hub.url(t), priv, 1)
	tcp := &scriptedListener{results: make(chan acceptResult, 2), closed: make(chan struct{})}
	l := NewListener(tcp, p)
	t.Cleanup(func() { l.Close() })

	accept := func() (net.Conn, error) {
		type result struct {
			conn net.Conn
			err  error
		}
		got := make(chan result, 1)
		go func() {
			c, err := l.Accept()
			got <- result{c, err}
		}()
		select {
		case r := <-got:
			return r.conn, r.err
		case <-time.After(2 * time.Second):
			t.Fatal("Accept did not return")
			return nil, nil
		}
	}

	tcp.results <- acceptResult{err: errors.New("accept tcp: too many open files")}
	_, err := accept()
	require.ErrorContains(t, err, "too many open files")

	client, server := net.Pipe()
	t.Cleanup(func() { client.Close() })
	tcp.results <- acceptResult{conn: server}
	c, err := accept()
	require.NoError(t, err)
	require.Same(t, server, c)
}
