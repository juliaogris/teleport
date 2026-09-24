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

// Package authcallout lets the auth service open its own connections to a
// proxy that cannot dial it, such as one on a stateless edge.
//
// A [Pool] keeps a fixed number of outbound WebSockets to the proxy. Each
// WebSocket is one stream:
//
//  1. The proxy sends a 32-byte nonce as the first message.
//  2. Auth replies with its own 32-byte nonce and an Ed25519 signature over
//     "sallyport/authpipe/v1", the URL host, the proxy nonce and the auth
//     nonce, in that order.
//  3. The stream waits until the proxy sends its first data message. The
//     pool then yields the stream from [Pool.Accept] as a [net.Conn], with
//     that message in front of it.
//
// The pool opens a new WebSocket when a stream closes. The bytes on a stream
// are the proxy's TLS to auth. The pool does no TLS of its own on ws://
// URLs, and does not authenticate the proxy.
package authcallout

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	mathrand "math/rand/v2"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/gravitational/trace"
	"golang.org/x/time/rate"
)

const (
	// ChallengeDomain is the first part of every signed challenge. It stops
	// the key from signing anything the proxy chooses.
	ChallengeDomain = "sallyport/authpipe/v1"
	// NonceSize is the size of each nonce in the challenge.
	NonceSize = 32

	challengeTimeout      = 10 * time.Second
	defaultSize           = 8
	defaultDialsPerMinute = 60
	// readLimit is larger than any message the proxy writes. A message is
	// one or more TLS records.
	readLimit      = 128 * 1024
	minBackoff     = 250 * time.Millisecond
	maxBackoff     = 30 * time.Second
	closeWriteWait = time.Second
)

// Config is the configuration for a [Pool].
type Config struct {
	// URL is the proxy's WebSocket URL. It must pass [CheckURL].
	URL *url.URL
	// Key signs the challenge on every WebSocket.
	Key ed25519.PrivateKey
	// Size is the number of WebSockets the pool keeps open. The default is 8.
	Size int
	// DialsPerMinute caps new WebSockets across the pool. The default is 60.
	DialsPerMinute int
	// Dialer dials the WebSockets. The default is [websocket.DefaultDialer].
	Dialer *websocket.Dialer
	// Logger is the logger. If not set, the pool uses [slog.Default].
	Logger *slog.Logger
}

// CheckAndSetDefaults validates the config and sets default values.
func (c *Config) CheckAndSetDefaults() error {
	if c.URL == nil {
		return trace.BadParameter("missing callout URL")
	}
	if err := CheckURL(c.URL); err != nil {
		return trace.Wrap(err)
	}
	if len(c.Key) != ed25519.PrivateKeySize {
		return trace.BadParameter("missing or invalid callout key")
	}
	if c.Size <= 0 {
		c.Size = defaultSize
	}
	if c.DialsPerMinute <= 0 {
		c.DialsPerMinute = defaultDialsPerMinute
	}
	if c.Dialer == nil {
		c.Dialer = websocket.DefaultDialer
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return nil
}

// CheckURL returns an error unless u is a wss:// URL, or a ws:// URL whose
// host is localhost or a loopback or private IP address.
func CheckURL(u *url.URL) error {
	switch u.Scheme {
	case "wss":
		return nil
	case "ws":
	default:
		return trace.BadParameter("callout URL %q must use wss:// or ws://", u.Redacted())
	}
	host := u.Hostname()
	if host == "localhost" {
		return nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || (!addr.IsLoopback() && !addr.IsPrivate()) {
		return trace.BadParameter("callout URL %q uses ws:// with a host that is not a private address", u.Redacted())
	}
	return nil
}

// LoadKey reads an Ed25519 private key from a PEM file in PKCS #8 form,
// as written by `openssl genpkey -algorithm ed25519`.
func LoadKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, trace.BadParameter("%s: no PEM block", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, trace.Wrap(err, "%s", path)
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, trace.BadParameter("%s: key is %T, want Ed25519", path, key)
	}
	return ed, nil
}

// SignedMessage returns the bytes the challenge signature covers.
func SignedMessage(host string, proxyNonce, authNonce []byte) []byte {
	var b bytes.Buffer
	b.WriteString(ChallengeDomain)
	b.WriteString(host)
	b.Write(proxyNonce)
	b.Write(authNonce)
	return b.Bytes()
}

// Pool keeps outbound WebSockets to the proxy open and yields each one as a
// stream once the proxy starts using it.
type Pool struct {
	cfg     Config
	limiter *rate.Limiter
	conns   chan net.Conn

	ctx    context.Context
	cancel context.CancelFunc
	start  sync.Once
	wg     sync.WaitGroup
}

// New returns a pool that does not dial until [Pool.Start].
func New(cfg Config) (*Pool, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Pool{
		cfg:     cfg,
		limiter: rate.NewLimiter(rate.Limit(float64(cfg.DialsPerMinute)/60), cfg.Size),
		conns:   make(chan net.Conn),
		ctx:     ctx,
		cancel:  cancel,
	}, nil
}

// Start opens the WebSockets. Calls after the first do nothing.
func (p *Pool) Start() {
	p.start.Do(func() {
		for range p.cfg.Size {
			p.wg.Add(1)
			go p.run()
		}
	})
}

// Accept returns the next stream the proxy has started to use. It returns
// [net.ErrClosed] after [Pool.Close].
func (p *Pool) Accept() (net.Conn, error) {
	select {
	case c := <-p.conns:
		return c, nil
	case <-p.ctx.Done():
		return nil, net.ErrClosed
	}
}

// Close closes every WebSocket, including streams returned by Accept, and
// waits for the pool to stop.
func (p *Pool) Close() error {
	p.cancel()
	p.wg.Wait()
	return nil
}

// run keeps one WebSocket open until the pool closes.
func (p *Pool) run() {
	defer p.wg.Done()
	log := p.cfg.Logger.With("url", p.cfg.URL.Redacted())
	backoff := time.Duration(0)
	for {
		if !p.limiter.Allow() {
			log.WarnContext(p.ctx, "auth callout: dial rate limit reached", "dials_per_minute", p.cfg.DialsPerMinute)
			if err := p.limiter.Wait(p.ctx); err != nil {
				return
			}
		}
		err := p.serveOne(log)
		if p.ctx.Err() != nil {
			return
		}
		if err == nil {
			backoff = 0
			continue
		}
		backoff = min(max(2*backoff, minBackoff), maxBackoff)
		wait := backoff/2 + mathrand.N(backoff/2)
		log.DebugContext(p.ctx, "auth callout: stream failed", "error", err, "retry_in", wait)
		select {
		case <-time.After(wait):
		case <-p.ctx.Done():
			return
		}
	}
}

// serveOne dials one WebSocket, answers the challenge, and hands the stream
// to Accept after the proxy's first data message. It returns nil once a
// handed-over stream closes.
func (p *Pool) serveOne(log *slog.Logger) error {
	ws, resp, err := p.cfg.Dialer.DialContext(p.ctx, p.cfg.URL.String(), nil)
	if resp != nil {
		resp.Body.Close()
	}
	if err != nil {
		return trace.Wrap(err, "dialing")
	}
	stop := context.AfterFunc(p.ctx, func() { ws.Close() })
	defer stop()
	ws.SetReadLimit(readLimit)
	log.DebugContext(p.ctx, "auth callout: dialed")

	if err := p.answerChallenge(ws); err != nil {
		ws.Close()
		return trace.Wrap(err, "challenge")
	}
	log.DebugContext(p.ctx, "auth callout: challenge signed")

	typ, first, err := ws.ReadMessage()
	if err != nil {
		ws.Close()
		return trace.Wrap(err, "waiting for first message")
	}
	if typ != websocket.BinaryMessage {
		ws.Close()
		return trace.BadParameter("first message is not binary")
	}

	conn := newConn(ws, first)
	select {
	case p.conns <- conn:
	case <-p.ctx.Done():
		conn.Close()
		return nil
	}
	log.DebugContext(p.ctx, "auth callout: stream handed to listener")
	select {
	case <-conn.done:
	case <-p.ctx.Done():
		conn.Close()
	}
	return nil
}

// answerChallenge reads the proxy nonce and writes the auth nonce and the
// signature.
func (p *Pool) answerChallenge(ws *websocket.Conn) error {
	ws.SetReadDeadline(time.Now().Add(challengeTimeout))
	typ, proxyNonce, err := ws.ReadMessage()
	if err != nil {
		return trace.Wrap(err)
	}
	if typ != websocket.BinaryMessage || len(proxyNonce) != NonceSize {
		return trace.BadParameter("proxy nonce is not %d binary bytes", NonceSize)
	}
	authNonce := make([]byte, NonceSize)
	if _, err := rand.Read(authNonce); err != nil {
		return trace.Wrap(err)
	}
	sig := ed25519.Sign(p.cfg.Key, SignedMessage(p.cfg.URL.Host, proxyNonce, authNonce))
	ws.SetWriteDeadline(time.Now().Add(challengeTimeout))
	if err := ws.WriteMessage(websocket.BinaryMessage, append(authNonce, sig...)); err != nil {
		return trace.Wrap(err)
	}
	ws.SetReadDeadline(time.Time{})
	ws.SetWriteDeadline(time.Time{})
	return nil
}
