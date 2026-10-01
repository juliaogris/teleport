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
	// refuses advertises "refuse" on control sockets. Set it before the
	// pool starts.
	refuses bool
}

func newLazyEdge(t *testing.T, pub ed25519.PublicKey) *lazyEdge {
	e := &lazyEdge{pub: pub, controls: make(chan *websocket.Conn, 16), streams: make(chan lazyStream, 64)}
	ctx := t.Context()
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e.refuses && r.URL.Query().Get("mode") == "control" {
			w.Header().Set(ControlHeader, ControlRefuse)
		}
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		switch r.URL.Query().Get("mode") {
		case "control":
			if !verifyChallenge(ctx, ws, e.pub, r.Host) {
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
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sendDial(t *testing.T, ws *websocket.Conn, kind, id string) {
	require.NoError(t, ws.Write(t.Context(), websocket.MessageText, []byte("dial "+kind+" "+id)))
}

// requireClosed reads ws until it fails, within 5 s, and returns the error.
func requireClosed(t *testing.T, ws *websocket.Conn) error {
	select {
	case err := <-awaitClose(t, ws):
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("control socket still open after 5s")
		return nil
	}
}

// requireRefuse reads the next control message and requires it to refuse
// id.
func requireRefuse(t *testing.T, ctl *websocket.Conn, id string) {
	typ, msg, err := ctl.Read(t.Context())
	require.NoError(t, err)
	require.Equal(t, websocket.MessageText, typ)
	require.Equal(t, "refuse "+id, string(msg))
}

func TestOnDemandControlChallenge(t *testing.T) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	newOnDemandPool(t, e.url(t), priv)
	e.control(t)
	e.noStream(t, 200*time.Millisecond)
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

func TestOnDemandDialAuthReachesAccept(t *testing.T) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	p := newOnDemandPool(t, e.url(t), priv)
	ctl := e.control(t)

	id := newStreamID(t)
	sendDial(t, ctl, "auth", id)
	s := e.stream(t)
	require.Equal(t, id, s.id)
	require.Equal(t, url.Values{"mode": {"stream"}}, s.query)
	require.Equal(t, StreamAcks, s.header.Get(StreamHeader))

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
	// An edge that did not advertise refuse hears nothing.
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	_, _, err := ctl.Read(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestOnDemandRefusesDroppedDial(t *testing.T) {
	t.Run("no app handler", func(t *testing.T) {
		pub, priv := newKey(t)
		e := newLazyEdge(t, pub)
		e.refuses = true
		newOnDemandPool(t, e.url(t), priv)
		ctl := e.control(t)

		id := newStreamID(t)
		sendDial(t, ctl, "app", id)
		requireRefuse(t, ctl, id)
		e.noStream(t, 200*time.Millisecond)
	})

	t.Run("too many streams", func(t *testing.T) {
		pub, priv := newKey(t)
		e := newLazyEdge(t, pub)
		e.refuses = true
		p := newOnDemandPool(t, e.url(t), priv)
		ctl := e.control(t)
		p.openStreams.Store(maxStreams)

		id := newStreamID(t)
		sendDial(t, ctl, "auth", id)
		requireRefuse(t, ctl, id)
		e.noStream(t, 200*time.Millisecond)
	})

	t.Run("over the dial budget", func(t *testing.T) {
		pub, priv := newKey(t)
		e := newLazyEdge(t, pub)
		e.refuses = true
		p := newOnDemandPool(t, e.url(t), priv)
		ctl := e.control(t)
		p.streamLimiters[streamAuth].SetBurst(0)

		id := newStreamID(t)
		sendDial(t, ctl, "auth", id)
		requireRefuse(t, ctl, id)
		e.noStream(t, 200*time.Millisecond)
	})
}

func TestOnDemandBadMessageClosesControl(t *testing.T) {
	for _, msg := range []string{
		"hello",
		"dial auth",
		"dial ssh " + strings.Repeat("A", 43),
		"dial auth short",
		"dial auth " + strings.Repeat("A", 43) + "=",
	} {
		t.Run(msg, func(t *testing.T) {
			pub, priv := newKey(t)
			e := newLazyEdge(t, pub)
			newOnDemandPool(t, e.url(t), priv)
			ctl := e.control(t)

			require.NoError(t, ctl.Write(t.Context(), websocket.MessageText, []byte(msg)))
			err := requireClosed(t, ctl)
			require.Equal(t, websocket.StatusPolicyViolation, websocket.CloseStatus(err))
			e.noStream(t, 200*time.Millisecond)
			// The callout redials.
			e.control(t)
		})
	}
}

func TestOnDemandRedialsAfterClose(t *testing.T) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	newOnDemandPool(t, e.url(t), priv)
	ctl := e.control(t)
	ctl.Close(websocket.StatusNormalClosure, "")
	e.control(t)
}

func TestOnDemandStopClosesControlGoingAway(t *testing.T) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	p := newOnDemandPool(t, e.url(t), priv)
	ctl := e.control(t)
	p.Stop()
	err := readUntilClosed(t, ctl)
	require.Equal(t, websocket.StatusGoingAway, websocket.CloseStatus(err))
}

func TestNextControlBackoff(t *testing.T) {
	const minBackoff, maxControlBackoff = 100 * time.Millisecond, 10 * time.Minute
	p := &Pool{cfg: Config{minBackoff: minBackoff, maxControlBackoff: maxControlBackoff}}
	closed := func(code websocket.StatusCode, reason string) error {
		return websocket.CloseError{Code: code, Reason: reason}
	}
	for _, tc := range []struct {
		name    string
		backoff time.Duration
		lasted  time.Duration
		err     error
		want    time.Duration
	}{
		{name: "normal close after a healthy socket", backoff: 8 * time.Second, lasted: time.Minute, err: closed(websocket.StatusNormalClosure, ""), want: minBackoff},
		{name: "network error after a healthy socket", backoff: 8 * time.Second, lasted: time.Minute, err: io.EOF, want: minBackoff},
		{name: "network error after a medium socket", backoff: minBackoff, lasted: 20 * time.Second, err: io.EOF, want: 2 * minBackoff},
		{name: "network error after a medium socket stops at maxBackoff", backoff: maxBackoff, lasted: 20 * time.Second, err: io.EOF, want: maxBackoff},
		{name: "short socket", backoff: 0, lasted: time.Second, err: closed(websocket.StatusNormalClosure, ""), want: minBackoff},
		{name: "short socket grows", backoff: minBackoff, lasted: time.Second, err: closed(websocket.StatusNormalClosure, ""), want: 2 * minBackoff},
		{name: "short socket grows past maxBackoff", backoff: maxBackoff, lasted: time.Second, err: io.EOF, want: 2 * maxBackoff},
		{name: "short socket stops at maxControlBackoff", backoff: maxControlBackoff, lasted: time.Second, err: io.EOF, want: maxControlBackoff},
		{name: "policy violation after a healthy socket grows", backoff: minBackoff, lasted: time.Minute, err: closed(websocket.StatusPolicyViolation, "bad signature"), want: 2 * minBackoff},
		{name: "replaced after a healthy socket grows", backoff: minBackoff, lasted: time.Minute, err: closed(websocket.StatusNormalClosure, replacedReason), want: 2 * minBackoff},
		{name: "try again later stays at minBackoff", backoff: 8 * time.Second, lasted: time.Second, err: closed(websocket.StatusTryAgainLater, "too many sockets in the challenge"), want: minBackoff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := p.nextControlBackoff(tc.backoff, tc.lasted, tc.err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestOnDemandBacksOffAfterPolicyViolation(t *testing.T) {
	const minBackoff = 100 * time.Millisecond
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	newOnDemandPool(t, e.url(t), priv, func(c *Config) { c.minBackoff = minBackoff })

	// The first 1008 sets the backoff to minBackoff, the second doubles
	// it, so the third dial waits at least minBackoff.
	e.control(t).Close(websocket.StatusPolicyViolation, "bad signature")
	second := e.control(t)
	closedAt := time.Now()
	second.Close(websocket.StatusPolicyViolation, "bad signature")
	e.control(t)
	require.GreaterOrEqual(t, time.Since(closedAt), minBackoff)
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
	// A few more streams may come from the refill during the test.
	window := 300 * time.Millisecond
	refills := int(window.Seconds()*streamDialsPerMinute/60) + 1
	extra := 0
	timeout := time.After(window)
	for done := false; !done; {
		select {
		case s := <-e.streams:
			s.ws.CloseNow()
			extra++
		case <-timeout:
			done = true
		}
	}
	require.LessOrEqual(t, extra, refills)
}

func TestOnDemandDialBudgetPerKind(t *testing.T) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	p := newOnDemandPool(t, e.url(t), priv)
	require.NoError(t, p.SetAppHandler(func(c net.Conn) { c.Close() }))
	ctl := e.control(t)
	p.streamLimiters[streamAuth].SetBurst(0)

	sendDial(t, ctl, "auth", newStreamID(t))
	id := newStreamID(t)
	sendDial(t, ctl, "app", id)
	s := e.stream(t)
	require.Equal(t, id, s.id)
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
