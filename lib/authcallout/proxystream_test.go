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
	"net/url"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
)

// proxyTarget is a TCP listener that stands in for the home proxy. It
// hands over each connection it accepts.
type proxyTarget struct {
	addr  string
	conns chan net.Conn
}

func newProxyTarget(t *testing.T) *proxyTarget {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	pt := &proxyTarget{addr: l.Addr().String(), conns: make(chan net.Conn, 64)}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			pt.conns <- c
		}
	}()
	return pt
}

func (pt *proxyTarget) conn(t *testing.T) net.Conn {
	select {
	case c := <-pt.conns:
		t.Cleanup(func() { c.Close() })
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no connection to the proxy address within 5s")
		return nil
	}
}

// unusedAddr returns a loopback address with nothing listening on it.
func unusedAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

func withProxyAddr(addr string) func(*Config) {
	return func(c *Config) { c.ProxyAddr = addr }
}

func TestOnDemandDialProxyReachesAddr(t *testing.T) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	target := newProxyTarget(t)
	newOnDemandPool(t, e.url(t), priv, withProxyAddr(target.addr))
	ctl := e.control(t)

	id := newStreamID(t)
	sendDial(t, ctl, "proxy", id)
	c := target.conn(t)
	s := e.stream(t)
	require.Equal(t, id, s.id)
	require.Equal(t, url.Values{"mode": {"stream"}}, s.query)
	require.Equal(t, StreamAcks, s.header.Get(StreamHeader))

	require.NoError(t, s.ws.Write(t.Context(), websocket.MessageBinary, []byte("hello")))
	buf := make([]byte, 5)
	_, err := io.ReadFull(c, buf)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buf))

	_, err = c.Write([]byte("back"))
	require.NoError(t, err)
	_, msg, err := s.ws.Read(t.Context())
	require.NoError(t, err)
	require.Equal(t, "back", string(msg))

	// The proxy address closing ends the stream.
	require.NoError(t, c.Close())
	_, _, err = s.ws.Read(t.Context())
	require.Equal(t, websocket.StatusNormalClosure, websocket.CloseStatus(err))
}

func TestOnDemandProxyStreamClosesTarget(t *testing.T) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	target := newProxyTarget(t)
	newOnDemandPool(t, e.url(t), priv, withProxyAddr(target.addr))
	ctl := e.control(t)

	sendDial(t, ctl, "proxy", newStreamID(t))
	c := target.conn(t)
	s := e.stream(t)
	require.NoError(t, s.ws.Close(websocket.StatusNormalClosure, ""))

	require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err := c.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}

func TestOnDemandRefusesProxyDial(t *testing.T) {
	tests := []struct {
		name  string
		addr  func(t *testing.T) string
		setup func(p *Pool)
	}{
		{name: "no proxy address", addr: func(*testing.T) string { return "" }},
		{name: "unreachable proxy address", addr: unusedAddr},
		{
			name:  "too many proxy streams",
			addr:  func(t *testing.T) string { return newProxyTarget(t).addr },
			setup: func(p *Pool) { p.openProxyStreams.Store(maxProxyStreams) },
		},
		{
			name:  "over the dial budget",
			addr:  func(t *testing.T) string { return newProxyTarget(t).addr },
			setup: func(p *Pool) { p.streamLimiters[streamProxy].SetBurst(0) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, priv := newKey(t)
			e := newLazyEdge(t, pub)
			e.refuses = true
			p := newOnDemandPool(t, e.url(t), priv, withProxyAddr(tt.addr(t)))
			ctl := e.control(t)
			if tt.setup != nil {
				tt.setup(p)
			}

			id := newStreamID(t)
			sendDial(t, ctl, "proxy", id)
			requireRefuse(t, ctl, id)
			e.noStream(t, 200*time.Millisecond)
		})
	}
}

func TestOnDemandProxyStreamsDoNotStarveAuth(t *testing.T) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	e.refuses = true
	target := newProxyTarget(t)
	p := newOnDemandPool(t, e.url(t), priv, withProxyAddr(target.addr))
	require.NoError(t, p.SetAppHandler(func(c net.Conn) { t.Cleanup(func() { c.Close() }) }))
	ctl := e.control(t)

	for range maxProxyStreams {
		sendDial(t, ctl, "proxy", newStreamID(t))
		target.conn(t)
		e.stream(t)
	}
	require.Eventually(t, func() bool { return p.openProxyStreams.Load() == maxProxyStreams }, 5*time.Second, 10*time.Millisecond)
	require.Zero(t, p.openStreams.Load())

	id := newStreamID(t)
	sendDial(t, ctl, "proxy", id)
	requireRefuse(t, ctl, id)

	for _, kind := range []string{"auth", "app"} {
		id := newStreamID(t)
		sendDial(t, ctl, kind, id)
		require.Equal(t, id, e.stream(t).id, kind)
	}
}

func TestOnDemandProxyBudgetIsSeparate(t *testing.T) {
	pub, priv := newKey(t)
	e := newLazyEdge(t, pub)
	target := newProxyTarget(t)
	p := newOnDemandPool(t, e.url(t), priv, withProxyAddr(target.addr))
	ctl := e.control(t)
	p.streamLimiters[streamAuth].SetBurst(0)
	p.streamLimiters[streamApp].SetBurst(0)

	id := newStreamID(t)
	sendDial(t, ctl, "proxy", id)
	target.conn(t)
	require.Equal(t, id, e.stream(t).id)
}

func TestConfigProxyAddr(t *testing.T) {
	_, priv := newKey(t)
	u, err := url.Parse("ws://127.0.0.1:1/tunnel/auth")
	require.NoError(t, err)
	tests := []struct {
		name    string
		mode    Mode
		addr    string
		wantErr bool
	}{
		{name: "on demand", mode: ModeOnDemand, addr: "127.0.0.1:3080"},
		{name: "host name", mode: ModeOnDemand, addr: "localhost:3080"},
		{name: "unset", mode: ModePool},
		{name: "pool mode", mode: ModePool, addr: "127.0.0.1:3080", wantErr: true},
		{name: "no port", mode: ModeOnDemand, addr: "127.0.0.1", wantErr: true},
		{name: "no host", mode: ModeOnDemand, addr: ":3080", wantErr: true},
		{name: "port zero", mode: ModeOnDemand, addr: "127.0.0.1:0", wantErr: true},
		{name: "port too large", mode: ModeOnDemand, addr: "127.0.0.1:65536", wantErr: true},
		{name: "named port", mode: ModeOnDemand, addr: "127.0.0.1:https", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{URL: u, Key: priv, Mode: tt.mode, ProxyAddr: tt.addr}
			err := cfg.CheckAndSetDefaults()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
