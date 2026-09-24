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
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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
	upgrader := websocket.Upgrader{}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.dials.Add(1)
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		nonce := make([]byte, NonceSize)
		rand.Read(nonce)
		if err := ws.WriteMessage(websocket.BinaryMessage, nonce); err != nil {
			ws.Close()
			return
		}
		_, reply, err := ws.ReadMessage()
		if err != nil || len(reply) != NonceSize+ed25519.SignatureSize {
			ws.Close()
			return
		}
		msg := SignedMessage(r.Host, nonce, reply[:NonceSize])
		if !ed25519.Verify(h.pub, msg, reply[NonceSize:]) {
			ws.Close()
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
		t.Cleanup(func() { ws.Close() })
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

	require.NoError(t, ws.WriteMessage(websocket.BinaryMessage, []byte("hello")))
	c, err := p.Accept()
	require.NoError(t, err)
	buf := make([]byte, 5)
	_, err = c.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buf))

	_, err = c.Write([]byte("world"))
	require.NoError(t, err)
	_, got, err := ws.ReadMessage()
	require.NoError(t, err)
	require.Equal(t, "world", string(got))

	_, ok := c.RemoteAddr().(*net.TCPAddr)
	require.True(t, ok)
}

func TestPoolReplacesClosedStream(t *testing.T) {
	pub, priv := newKey(t)
	hub := newFakeHub(t, pub)
	newPool(t, hub.url(t), priv, 1)
	hub.next(t).Close()
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

func TestPoolCloseClosesAll(t *testing.T) {
	pub, priv := newKey(t)
	hub := newFakeHub(t, pub)
	p, err := New(Config{URL: hub.url(t), Key: priv, Size: 2})
	require.NoError(t, err)
	p.Start()
	a, b := hub.next(t), hub.next(t)

	require.NoError(t, p.Close())
	for _, ws := range []*websocket.Conn{a, b} {
		ws.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _, err := ws.ReadMessage()
		require.Error(t, err)
	}
	_, err = p.Accept()
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

	require.NoError(t, hub.next(t).WriteMessage(websocket.BinaryMessage, []byte("x")))
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
