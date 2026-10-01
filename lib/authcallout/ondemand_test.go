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
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

// lazyStream is a stream socket the fake edge accepted.
type lazyStream struct {
	id     string
	query  url.Values
	header http.Header
	ws     *websocket.Conn
}

// lazyEdge is the edge side of on-demand mode. Control sockets must pass
// the challenge. Stream sockets are handed over with their id header.
type lazyEdge struct {
	pub      ed25519.PublicKey
	controls chan *websocket.Conn
	streams  chan lazyStream
	srv      *httptest.Server
}

func newLazyEdge(t *testing.T, pub ed25519.PublicKey) *lazyEdge {
	e := &lazyEdge{pub: pub, controls: make(chan *websocket.Conn, 16), streams: make(chan lazyStream, 64)}
	ctx := t.Context()
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		switch r.URL.Query().Get("mode") {
		case "control":
			nonce := make([]byte, NonceSize)
			rand.Read(nonce)
			if err := ws.Write(ctx, websocket.MessageBinary, nonce); err != nil {
				ws.CloseNow()
				return
			}
			_, reply, err := ws.Read(ctx)
			if err != nil || len(reply) != NonceSize+ed25519.SignatureSize ||
				!ed25519.Verify(e.pub, SignedMessage(r.Host, nonce, reply[:NonceSize]), reply[NonceSize:]) {
				ws.CloseNow()
				return
			}
			e.controls <- ws
		case "stream":
			e.streams <- lazyStream{id: r.Header.Get(StreamIDHeader), query: r.URL.Query(), header: r.Header.Clone(), ws: ws}
		default:
			ws.CloseNow()
		}
	}))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *lazyEdge) url(t *testing.T) *url.URL {
	u, err := url.Parse("ws" + strings.TrimPrefix(e.srv.URL, "http") + "/tunnel/auth")
	require.NoError(t, err)
	return u
}

func (e *lazyEdge) control(t *testing.T) *websocket.Conn {
	select {
	case ws := <-e.controls:
		t.Cleanup(func() { ws.CloseNow() })
		return ws
	case <-time.After(5 * time.Second):
		t.Fatal("no verified control socket within 5s")
		return nil
	}
}

func (e *lazyEdge) stream(t *testing.T) lazyStream {
	select {
	case s := <-e.streams:
		t.Cleanup(func() { s.ws.CloseNow() })
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("no stream within 5s")
		return lazyStream{}
	}
}

func (e *lazyEdge) noStream(t *testing.T, within time.Duration) {
	select {
	case s := <-e.streams:
		s.ws.CloseNow()
		t.Fatalf("unexpected stream %q", s.id)
	case <-time.After(within):
	}
}

func newOnDemandPool(t *testing.T, u *url.URL, key ed25519.PrivateKey, opts ...func(*Config)) *Pool {
	cfg := Config{URL: u, Key: key, Mode: ModeOnDemand, DialsPerMinute: 6000}
	for _, o := range opts {
		o(&cfg)
	}
	p, err := New(cfg)
	require.NoError(t, err)
	p.Start()
	t.Cleanup(func() { p.Close() })
	return p
}

func newStreamID(t *testing.T) string {
	b := make([]byte, streamIDSize)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sendDial(t *testing.T, ws *websocket.Conn, kind, id string) {
	require.NoError(t, ws.Write(t.Context(), websocket.MessageText, []byte("dial "+kind+" "+id)))
}

// requireClosed reads from ws until it fails, within 5 s.
func requireClosed(t *testing.T, ws *websocket.Conn) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := ws.Read(t.Context()); err != nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("control socket still open after 5s")
	}
}

func TestOnDemandControlChallenge(t *testing.T) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	newOnDemandPool(t, e.url(t), priv)
	e.control(t)
	e.noStream(t, 200*time.Millisecond)
}

func TestOnDemandDialAuthReachesAccept(t *testing.T) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	p := newOnDemandPool(t, e.url(t), priv)
	ctl := e.control(t)

	id := newStreamID(t)
	sendDial(t, ctl, "auth", id)
	s := e.stream(t)
	require.Equal(t, id, s.id)

	c, err := p.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	require.NoError(t, s.ws.Write(t.Context(), websocket.MessageBinary, []byte("hello")))
	buf := make([]byte, 5)
	_, err = io.ReadFull(c, buf)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buf))

	_, err = c.Write([]byte("back"))
	require.NoError(t, err)
	_, msg, err := s.ws.Read(t.Context())
	require.NoError(t, err)
	require.Equal(t, "back", string(msg))
}

func TestOnDemandDialAppReachesHandler(t *testing.T) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	p := newOnDemandPool(t, e.url(t), priv)
	got := make(chan net.Conn, 1)
	require.NoError(t, p.SetAppHandler(func(c net.Conn) { got <- c }))
	ctl := e.control(t)

	id := newStreamID(t)
	sendDial(t, ctl, "app", id)
	s := e.stream(t)
	require.Equal(t, id, s.id)

	select {
	case c := <-got:
		t.Cleanup(func() { c.Close() })
		require.NoError(t, s.ws.Write(t.Context(), websocket.MessageBinary, []byte("app")))
		buf := make([]byte, 3)
		_, err := io.ReadFull(c, buf)
		require.NoError(t, err)
		require.Equal(t, "app", string(buf))
	case <-time.After(5 * time.Second):
		t.Fatal("app handler not called within 5s")
	}
}

func TestOnDemandDialAppNoHandler(t *testing.T) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	newOnDemandPool(t, e.url(t), priv)
	ctl := e.control(t)

	sendDial(t, ctl, "app", newStreamID(t))
	e.noStream(t, time.Second)
}

func TestOnDemandStreamIDHeader(t *testing.T) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	newOnDemandPool(t, e.url(t), priv)
	ctl := e.control(t)

	id := newStreamID(t)
	sendDial(t, ctl, "auth", id)
	s := e.stream(t)
	require.Equal(t, id, s.id)
	require.Equal(t, url.Values{"mode": {"stream"}}, s.query)
	require.Equal(t, StreamAcks, s.header.Get(StreamHeader))
}

func TestOnDemandBadMessageClosesControl(t *testing.T) {
	for _, msg := range []string{
		"dial auth short",
		"dial auth " + strings.Repeat("A", 43) + "=",
		"dial ssh " + strings.Repeat("A", 43),
		"dial auth",
		"hello",
	} {
		t.Run(msg, func(t *testing.T) {
			pub, priv := newKey(t)
			e := newLazyEdge(t, pub)
			newOnDemandPool(t, e.url(t), priv)
			ctl := e.control(t)

			require.NoError(t, ctl.Write(t.Context(), websocket.MessageText, []byte(msg)))
			requireClosed(t, ctl)
			e.noStream(t, 200*time.Millisecond)
			// The callout redials.
			e.control(t)
		})
	}
}

func TestOnDemandPing(t *testing.T) {
	fast := func(c *Config) { c.pingEvery, c.pongTimeout = 50*time.Millisecond, 200*time.Millisecond }

	t.Run("pong keeps the socket open", func(t *testing.T) {
		pub, priv := newKey(t)
		e := newLazyEdge(t, pub)
		newOnDemandPool(t, e.url(t), priv, fast)
		ctl := e.control(t)
		for range 3 {
			typ, msg, err := ctl.Read(t.Context())
			require.NoError(t, err)
			require.Equal(t, websocket.MessageText, typ)
			require.Equal(t, "ping", string(msg))
			require.NoError(t, ctl.Write(t.Context(), websocket.MessageText, []byte("pong")))
		}
	})

	t.Run("missing pong closes the socket", func(t *testing.T) {
		pub, priv := newKey(t)
		e := newLazyEdge(t, pub)
		newOnDemandPool(t, e.url(t), priv, fast)
		ctl := e.control(t)
		requireClosed(t, ctl)
		e.control(t)
	})
}

func TestOnDemandRedialsAfterClose(t *testing.T) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	newOnDemandPool(t, e.url(t), priv)
	ctl := e.control(t)
	ctl.Close(websocket.StatusNormalClosure, "")
	e.control(t)
}

func TestOnDemandDialRateLimited(t *testing.T) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	newOnDemandPool(t, e.url(t), priv)
	ctl := e.control(t)

	for range streamDialBurst + 8 {
		sendDial(t, ctl, "auth", newStreamID(t))
	}
	for range streamDialBurst {
		e.stream(t)
	}
	// One more stream may come from the refill during the test.
	extra := 0
	timeout := time.After(300 * time.Millisecond)
	for done := false; !done; {
		select {
		case s := <-e.streams:
			s.ws.CloseNow()
			extra++
		case <-timeout:
			done = true
		}
	}
	require.LessOrEqual(t, extra, 1)
}

func TestSetAppHandlerNeedsOnDemand(t *testing.T) {
	_, priv := newKey(t)
	u, err := url.Parse("ws://127.0.0.1:1/tunnel/auth")
	require.NoError(t, err)
	p, err := New(Config{URL: u, Key: priv})
	require.NoError(t, err)
	t.Cleanup(func() { p.Close() })
	require.Error(t, p.SetAppHandler(func(net.Conn) {}))
}
