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
//     "sallyport/authpipe/v1", the URL's Host field (host and port), the
//     proxy nonce and the auth nonce, in that order.
//  3. The stream waits until the proxy sends its first data message. The
//     pool then yields the stream from [Pool.Accept] as a [net.Conn], with
//     that message in front of it.
//
// The pool opens a new WebSocket when a stream closes. The bytes on a
// stream are TLS to auth, from the proxy or from a client the proxy pipes
// through. On ws:// URLs the pool does no TLS of its own. On wss:// URLs
// the dialer checks the proxy's certificate against the system roots. The
// pool never checks the proxy's Teleport identity.
//
// The pool never offers WebSocket compression and rejects a proxy that
// switches it on. Every message is read through a size limit that counts
// the bytes after any inflation.
//
// In [ModeOnDemand] the pool keeps one control socket open instead of the
// streams, so that a proxy on an edge that bills idle time can sleep:
//
//  1. The pool dials the URL with the query parameter mode=control and
//     answers the same challenge as above.
//  2. The proxy sends text messages "dial auth <id>" or "dial app <id>",
//     where <id> is 32 random bytes in unpadded base64url. Any other
//     message closes the control socket. For a dial it opens no stream
//     for, the pool answers "refuse <id>" if the proxy's response to the
//     control request carried the header "Sallyport-Control: refuse".
//     Without that header the pool answers nothing, and the proxy learns
//     of the dropped dial from its own deadline.
//  3. The pool sends the text "ping" every 30 seconds and closes the socket
//     when no "pong" comes back within 10 seconds. A proxy can answer it
//     without waking up.
//  4. For each dial, the pool dials the URL with mode=stream and the id in
//     the Sallyport-Stream-Id header. There is no challenge on a stream:
//     the proxy accepts only an id it sent on the control socket, once.
//     An auth stream goes to [Pool.Accept]. An app stream goes to the
//     handler set with [Pool.SetAppHandler].
//  5. Binary messages on a stream carry its bytes. Each end sends the text
//     "ack <n>" after every 256 KiB it has passed on, where <n> is the
//     total so far, and keeps at most 1 MiB unacknowledged. The stream
//     request carries the header "Sallyport-Stream: ack" to say that the
//     pool acknowledges. A proxy that does not read the header applies no
//     window to what it sends.
//
// An app stream is TLS from the proxy to the app service, as a reverse
// tunnel connection would be. The pool authenticates the proxy only by the
// TLS certificate of the URL's host. The reverse tunnel also checks the
// proxy's host certificate against the cluster's host CA, so on this path
// the app service's own check of the user's client certificate is the
// only Teleport check.
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
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
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
	defaultDialTimeout    = 30 * time.Second
	defaultSize           = 8
	defaultDialsPerMinute = 60
	// readLimit is larger than any message the proxy writes. A message is
	// one or more TLS records.
	readLimit         = 128 * 1024
	defaultMinBackoff = 250 * time.Millisecond
	maxBackoff        = 30 * time.Second
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
	// DialTimeout bounds the WebSocket handshake. The default is 30 seconds.
	DialTimeout time.Duration
	// Logger is the logger. If not set, the pool uses [slog.Default].
	Logger *slog.Logger
	// Mode selects how the pool opens streams. The default is [ModePool].
	Mode Mode

	// pingEvery and pongTimeout time the control socket's ping in
	// on-demand mode. Tests shorten them.
	pingEvery, pongTimeout time.Duration
	// minBackoff is the shortest wait before a redial, and
	// maxControlBackoff the longest wait before redialing a control
	// socket in on-demand mode. Tests shorten them.
	minBackoff, maxControlBackoff time.Duration
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
	if c.DialTimeout <= 0 {
		c.DialTimeout = defaultDialTimeout
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.pingEvery <= 0 {
		c.pingEvery = defaultPingEvery
	}
	if c.pongTimeout <= 0 {
		c.pongTimeout = defaultPongTimeout
	}
	if c.minBackoff <= 0 {
		c.minBackoff = defaultMinBackoff
	}
	if c.maxControlBackoff <= 0 {
		c.maxControlBackoff = defaultMaxControlBackoff
	}
	if c.Mode != ModePool && c.Mode != ModeOnDemand {
		return trace.BadParameter("unknown callout mode %d", c.Mode)
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

// SignedMessage returns the bytes the challenge signature covers. host is
// the URL's Host field, with the port if the URL has one.
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

	// ctx ends on Close. dialCtx ends on Stop and Close.
	ctx     context.Context
	cancel  context.CancelFunc
	dialCtx context.Context
	stop    context.CancelFunc
	start   sync.Once
	wg      sync.WaitGroup

	// These fields are used in on-demand mode only.
	streamLimiters map[streamKind]*rate.Limiter
	openStreams    atomic.Int32
	appHandler     atomic.Pointer[func(net.Conn)]
	dropLogs       dropLogs
}

// New returns a pool that does not dial until [Pool.Start].
func New(cfg Config) (*Pool, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	dialCtx, stop := context.WithCancel(ctx)
	return &Pool{
		cfg: cfg,
		// A burst of Size lets the first fill dial without waiting.
		limiter: rate.NewLimiter(rate.Limit(float64(cfg.DialsPerMinute)/60), cfg.Size),
		conns:   make(chan net.Conn),
		ctx:     ctx,
		cancel:  cancel,
		dialCtx: dialCtx,
		stop:    stop,

		streamLimiters: newStreamLimiters(),
		dropLogs:       newDropLogs(),
	}, nil
}

// Start opens the WebSockets: the streams in pool mode, the control socket
// in on-demand mode. Calls after the first do nothing.
func (p *Pool) Start() {
	p.start.Do(func() {
		if p.cfg.Mode == ModeOnDemand {
			p.wg.Add(1)
			go p.runControl()
			return
		}
		for range p.cfg.Size {
			p.wg.Add(1)
			go p.run()
		}
	})
}

// Accept returns the next stream the proxy has started to use. It returns
// [net.ErrClosed] after [Pool.Stop] or [Pool.Close].
func (p *Pool) Accept() (net.Conn, error) {
	select {
	case c := <-p.conns:
		return c, nil
	case <-p.dialCtx.Done():
		return nil, net.ErrClosed
	}
}

// Stop stops dialing and closes every WebSocket not yet returned by Accept.
// Streams returned by Accept stay open until their owner closes them.
func (p *Pool) Stop() {
	p.stop()
}

// Close stops the pool, closes the streams returned by Accept, and waits
// for the pool's goroutines to exit.
func (p *Pool) Close() error {
	p.cancel()
	p.wg.Wait()
	return nil
}

// run keeps one WebSocket open until the pool stops.
func (p *Pool) run() {
	defer p.wg.Done()
	log := p.cfg.Logger.With("url", p.cfg.URL.Redacted())
	var backoff time.Duration
	for {
		if !p.limiter.Allow() {
			log.WarnContext(p.dialCtx, "auth callout: dial rate limit reached", "dials_per_minute", p.cfg.DialsPerMinute)
			if err := p.limiter.Wait(p.dialCtx); err != nil {
				return
			}
		}
		err := p.serveOne(log)
		if p.dialCtx.Err() != nil {
			return
		}
		if err == nil {
			backoff = 0
			continue
		}
		backoff = min(max(2*backoff, p.cfg.minBackoff), maxBackoff)
		// Jitter spreads the redials when the proxy drops every WebSocket.
		wait := backoff/2 + mathrand.N(backoff/2)
		log.DebugContext(p.dialCtx, "auth callout: stream failed", "error", err, "retry_in", wait)
		select {
		case <-time.After(wait):
		case <-p.dialCtx.Done():
			return
		}
	}
}

// noRedirectClient refuses redirects, so the URL that [CheckURL] accepted is
// the only one the pool dials.
var noRedirectClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// serveOne dials one WebSocket, answers the challenge, and hands the stream
// to Accept after the proxy's first data message. It returns nil once a
// handed-over stream closes.
func (p *Pool) serveOne(log *slog.Logger) error {
	ws, local, remote, err := p.dialWithAddrs(p.cfg.URL.String(), nil)
	if err != nil {
		return trace.Wrap(err, "dialing")
	}
	defer ws.CloseNow()
	ws.SetReadLimit(readLimit)
	log.DebugContext(p.dialCtx, "auth callout: dialed")

	if err := p.answerChallenge(ws); err != nil {
		return trace.Wrap(err, "challenge")
	}
	log.DebugContext(p.dialCtx, "auth callout: challenge signed")

	// The stream has no deadline here. It idles until the proxy uses it.
	typ, first, err := ws.Read(p.dialCtx)
	if err != nil {
		return trace.Wrap(err, "waiting for first message")
	}
	if typ != websocket.MessageBinary {
		return trace.BadParameter("first message is not binary")
	}

	// Accepted streams outlive Stop, so the conn takes ctx, not dialCtx.
	conn := newConn(p.ctx, ws, first, local, remote)
	select {
	case p.conns <- conn:
	case <-p.dialCtx.Done():
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

// dialWithAddrs dials a WebSocket to rawURL with extra request headers,
// and returns it with the local and remote addresses of its TCP
// connection.
func (p *Pool) dialWithAddrs(rawURL string, header http.Header) (*websocket.Conn, net.Addr, net.Addr, error) {
	var local, remote net.Addr = &net.TCPAddr{}, &net.TCPAddr{}
	clientTrace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		local, remote = info.Conn.LocalAddr(), info.Conn.RemoteAddr()
	}}
	ctx, cancel := context.WithTimeout(httptrace.WithClientTrace(p.dialCtx, clientTrace), p.cfg.DialTimeout)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, rawURL, &websocket.DialOptions{HTTPClient: noRedirectClient, HTTPHeader: header})
	if err != nil {
		return nil, nil, nil, trace.Wrap(err)
	}
	return ws, local, remote, nil
}

// answerChallenge reads the proxy nonce and writes the auth nonce and the
// signature.
func (p *Pool) answerChallenge(ws *websocket.Conn) error {
	ctx, cancel := context.WithTimeout(p.dialCtx, challengeTimeout)
	defer cancel()
	typ, proxyNonce, err := ws.Read(ctx)
	if err != nil {
		return trace.Wrap(err)
	}
	if typ != websocket.MessageBinary || len(proxyNonce) != NonceSize {
		return trace.BadParameter("proxy nonce is not %d binary bytes", NonceSize)
	}
	authNonce := make([]byte, NonceSize)
	if _, err := rand.Read(authNonce); err != nil {
		return trace.Wrap(err)
	}
	sig := ed25519.Sign(p.cfg.Key, SignedMessage(p.cfg.URL.Host, proxyNonce, authNonce))
	if err := ws.Write(ctx, websocket.MessageBinary, append(authNonce, sig...)); err != nil {
		return trace.Wrap(err)
	}
	return nil
}
