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
	"encoding/base64"
	"errors"
	"log/slog"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/gravitational/trace"
	"golang.org/x/time/rate"
)

// Mode selects how a [Pool] opens streams.
type Mode int

const (
	// ModePool keeps [Config.Size] streams open at all times.
	ModePool Mode = iota
	// ModeOnDemand keeps one control socket open and opens a stream each
	// time the proxy asks for one.
	ModeOnDemand
)

const (
	// StreamIDHeader carries the stream id on a stream request in
	// on-demand mode.
	StreamIDHeader = "Sallyport-Stream-Id"
	// StreamHeader on a stream request carries the stream features the
	// pool supports. Its one value is [StreamAcks].
	StreamHeader = "Sallyport-Stream"
	// StreamAcks says the pool acknowledges the bytes it receives on the
	// stream, so the proxy can apply a window to them.
	StreamAcks = "ack"
	// ControlHeader on the proxy's response to a control request carries
	// the control messages the proxy accepts. Its one value is
	// [ControlRefuse].
	ControlHeader = "Sallyport-Control"
	// ControlRefuse says the proxy accepts "refuse <id>" for a dial the
	// pool opens no stream for.
	ControlRefuse = "refuse"
	// controlReadLimit is larger than any control message.
	controlReadLimit = 256
	// controlWriteTimeout bounds each write on the control socket.
	controlWriteTimeout = 10 * time.Second
	// streamIDSize is the size of a stream id before base64url encoding.
	streamIDSize = 32
	// Stream dials in on-demand mode have their own budget per stream
	// kind, so that login traffic cannot use up the app budget. A cold
	// page load asks for one app stream per asset, all at once, and
	// maxStreams bounds a proxy that keeps asking.
	streamDialBurst      = 128
	streamDialsPerMinute = 480
	// maxStreams caps the streams open at once in on-demand mode.
	maxStreams = 256
	// defaultMaxControlBackoff is the longest wait before redialing a
	// control socket that the proxy refused or replaced, or that closed
	// within shortControl.
	defaultMaxControlBackoff = 10 * time.Minute
	shortControl             = 10 * time.Second
	// healthyControl is how long a control socket must stay open for the
	// next dial to wait only minBackoff.
	healthyControl = 30 * time.Second
	// replacedReason is the close reason the proxy gives a control socket
	// that a newer one replaced.
	replacedReason = "replaced"
)

const (
	// defaultPingEvery is how often the control socket sends "ping", and
	// defaultPongTimeout how long it then waits for "pong".
	defaultPingEvery   = 30 * time.Second
	defaultPongTimeout = 10 * time.Second
)

// streamKind is the kind of stream the proxy asks for.
type streamKind string

const (
	streamAuth streamKind = "auth"
	streamApp  streamKind = "app"
)

// SetAppHandler sets the function that serves app streams in on-demand
// mode. Each app stream is passed to h in its own goroutine. It returns an
// error unless the pool is in on-demand mode.
func (p *Pool) SetAppHandler(h func(net.Conn)) error {
	if p.cfg.Mode != ModeOnDemand {
		return trace.BadParameter("auth callout is not in on-demand mode")
	}
	if h == nil {
		return trace.BadParameter("missing app handler")
	}
	p.appHandler.Store(&h)
	return nil
}

// ClearAppHandler removes the app handler. Later app dials open no stream.
func (p *Pool) ClearAppHandler() { p.appHandler.Store(nil) }

// Mode returns the pool's mode.
func (p *Pool) Mode() Mode { return p.cfg.Mode }

// modeURL returns the callout URL with the mode query parameter set.
func (p *Pool) modeURL(mode string) string {
	u := *p.cfg.URL
	q := u.Query()
	q.Set("mode", mode)
	u.RawQuery = q.Encode()
	return u.String()
}

// runControl keeps the control socket open until the pool stops.
func (p *Pool) runControl() {
	defer p.wg.Done()
	log := p.cfg.Logger.With("url", p.cfg.URL.Redacted())
	var backoff time.Duration
	for {
		if !p.limiter.Allow() {
			warnSometimes(p.dialCtx, log, &p.controlLogs.limited, "auth callout: dial rate limit reached", "dials_per_minute", p.cfg.DialsPerMinute)
			if err := p.limiter.Wait(p.dialCtx); err != nil {
				return
			}
		}
		start := time.Now()
		err := p.serveControl(log)
		if p.dialCtx.Err() != nil {
			return
		}
		backoff = p.nextControlBackoff(backoff, time.Since(start), err)
		wait := backoff/2 + mathrand.N(backoff/2)
		warnSometimes(p.dialCtx, log, &p.controlLogs.closed, "auth callout: control socket closed", "error", err, "retry_in", wait)
		select {
		case <-time.After(wait):
		case <-p.dialCtx.Done():
			return
		}
	}
}

// controlLogs rate limits the warnings of the control redial loop. A proxy
// that evicts the socket with 1013 is redialed after Config.minBackoff
// each time, and would otherwise warn twice a second for as long as it is
// at its cap.
type controlLogs struct {
	limited, closed rate.Sometimes
}

// newControlLogs returns controlLogs that warn at most once a minute per
// line.
func newControlLogs() controlLogs {
	return controlLogs{
		limited: rate.Sometimes{Interval: time.Minute},
		closed:  rate.Sometimes{Interval: time.Minute},
	}
}

// warnSometimes logs msg at WARN when s allows it, and at DEBUG otherwise.
func warnSometimes(ctx context.Context, log *slog.Logger, s *rate.Sometimes, msg string, args ...any) {
	level := slog.LevelDebug
	s.Do(func() { level = slog.LevelWarn })
	log.Log(ctx, level, msg, args...)
}

// nextControlBackoff returns the backoff before the next control dial,
// given the previous backoff and how long the last socket lived before it
// closed with err.
//
// Each dial wakes a proxy that sleeps. A proxy that refuses the socket
// (1008) or replaces it with another auth process's socket, or a socket
// that closes within shortControl, would otherwise wake the proxy every
// maxBackoff for good, so those grow the backoff up to
// Config.maxControlBackoff. A proxy that evicted the socket to make room
// (1013) wants another try soon, so that backoff stays at Config.minBackoff.
func (p *Pool) nextControlBackoff(backoff, lasted time.Duration, err error) time.Duration {
	var closeErr websocket.CloseError
	errors.As(err, &closeErr)
	switch {
	case closeErr.Code == websocket.StatusTryAgainLater:
		return p.cfg.minBackoff
	case closeErr.Code == websocket.StatusPolicyViolation, closeErr.Reason == replacedReason, lasted < shortControl:
		return min(max(2*backoff, p.cfg.minBackoff), p.cfg.maxControlBackoff)
	case lasted >= healthyControl:
		return p.cfg.minBackoff
	}
	return min(max(2*backoff, p.cfg.minBackoff), maxBackoff)
}

// serveControl dials the control socket, answers the challenge, and serves
// the proxy's dial requests until the socket closes.
func (p *Pool) serveControl(log *slog.Logger) error {
	dialCtx, cancelDial := context.WithTimeout(p.dialCtx, p.cfg.DialTimeout)
	ws, resp, err := websocket.Dial(dialCtx, p.modeURL("control"), &websocket.DialOptions{HTTPClient: noRedirectClient})
	cancelDial()
	if err != nil {
		return trace.Wrap(err, "dialing control socket")
	}
	defer ws.CloseNow()
	refuses := slices.Contains(strings.Fields(resp.Header.Get(ControlHeader)), ControlRefuse)
	ws.SetReadLimit(controlReadLimit)
	if err := p.answerChallenge(ws); err != nil {
		return trace.Wrap(err, "control challenge")
	}
	log.DebugContext(p.dialCtx, "auth callout: control socket ready", "refuses", refuses)

	ctx, cancel := context.WithCancel(p.dialCtx)
	defer cancel()
	var lastPong atomic.Int64
	lastPong.Store(time.Now().UnixNano())
	pingErr := make(chan error, 1)
	go func() {
		pingErr <- p.ping(ctx, ws, &lastPong)
		cancel()
	}()
	// The read in serveDials is not bound to a context. A read that ends
	// with its context drops the connection with no close frame, so a stop
	// ends it through the close handshake instead.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-p.dialCtx.Done():
			closeGracefully(ws, websocket.StatusGoingAway)
		case <-done:
		}
	}()

	code, err := p.serveDials(ctx, ws, log, &lastPong, refuses)
	if code != 0 {
		closeGracefully(ws, code)
		return trace.Wrap(err)
	}
	select {
	case errPing := <-pingErr:
		return trace.Wrap(errPing)
	default:
	}
	return trace.Wrap(err)
}

// serveDials answers the proxy's dial requests on ws until the socket fails
// or the proxy breaks the protocol. It returns the close status to send,
// 1008 for a message the proxy must not send and 1011 for a failed write,
// or 0 when the socket already failed.
func (p *Pool) serveDials(ctx context.Context, ws *websocket.Conn, log *slog.Logger, lastPong *atomic.Int64, refuses bool) (websocket.StatusCode, error) {
	for {
		typ, msg, err := ws.Read(context.Background())
		if err != nil {
			return 0, trace.Wrap(err, "reading control socket")
		}
		if typ != websocket.MessageText {
			return websocket.StatusPolicyViolation, trace.BadParameter("control message is not text")
		}
		text := string(msg)
		if text == "pong" {
			lastPong.Store(time.Now().UnixNano())
			continue
		}
		kind, id, err := parseDial(text)
		if err != nil {
			return websocket.StatusPolicyViolation, trace.Wrap(err)
		}
		if p.dialStream(log, kind, id) || !refuses {
			continue
		}
		// The write outlives Stop, so a dial read during Stop is refused.
		if err := writeControl(p.ctx, ws, "refuse "+id); err != nil {
			return websocket.StatusInternalError, trace.Wrap(err, "writing refuse")
		}
	}
}

// writeControl writes one text message on the control socket within
// [controlWriteTimeout].
func writeControl(ctx context.Context, ws *websocket.Conn, text string) error {
	ctx, cancel := context.WithTimeout(ctx, controlWriteTimeout)
	defer cancel()
	return trace.Wrap(ws.Write(ctx, websocket.MessageText, []byte(text)))
}

// ping writes "ping" every Config.pingEvery and returns an error when a
// "pong" is more than Config.pongTimeout overdue.
func (p *Pool) ping(ctx context.Context, ws *websocket.Conn, lastPong *atomic.Int64) error {
	t := time.NewTicker(p.cfg.pingEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		sent := time.Now()
		if err := writeControl(ctx, ws, "ping"); err != nil {
			return trace.Wrap(err, "writing ping")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(p.cfg.pongTimeout):
		}
		if time.Unix(0, lastPong.Load()).Before(sent) {
			ws.CloseNow()
			return trace.ConnectionProblem(nil, "no pong within %v", p.cfg.pongTimeout)
		}
	}
}

// parseDial parses "dial auth <id>" or "dial app <id>". The id must be
// [streamIDSize] bytes in unpadded base64url.
func parseDial(text string) (streamKind, string, error) {
	parts := strings.Split(text, " ")
	if len(parts) != 3 || parts[0] != "dial" {
		return "", "", trace.BadParameter("unexpected control message")
	}
	kind := streamKind(parts[1])
	if kind != streamAuth && kind != streamApp {
		return "", "", trace.BadParameter("unexpected stream kind")
	}
	id := parts[2]
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(raw) != streamIDSize || base64.RawURLEncoding.EncodeToString(raw) != id {
		return "", "", trace.BadParameter("malformed stream id")
	}
	return kind, id, nil
}

// dialStream opens the stream the proxy asked for and returns true when it
// did. It opens none after [Pool.Stop], when no app handler is set for an
// app stream, when [maxStreams] are open, or when the stream dial budget
// is used up.
func (p *Pool) dialStream(log *slog.Logger, kind streamKind, id string) bool {
	if p.dialCtx.Err() != nil {
		return false
	}
	var handler func(net.Conn)
	if kind == streamApp {
		h := p.appHandler.Load()
		if h == nil {
			p.dropLogs.noHandler.Do(func() {
				log.WarnContext(p.dialCtx, "auth callout: app stream asked for, but no app service is registered")
			})
			return false
		}
		handler = *h
	}
	if p.openStreams.Load() >= maxStreams {
		p.dropLogs.tooMany.Do(func() {
			log.WarnContext(p.dialCtx, "auth callout: too many streams open, dropping dials", "max_streams", maxStreams)
		})
		return false
	}
	if !p.streamLimiters[kind].Allow() {
		p.dropLogs.overBudget.Do(func() {
			log.WarnContext(p.dialCtx, "auth callout: stream dial rate limit reached, dropping dials", "kind", kind, "dials_per_minute", streamDialsPerMinute)
		})
		return false
	}
	p.wg.Add(1)
	p.openStreams.Add(1)
	go func() {
		defer p.wg.Done()
		defer p.openStreams.Add(-1)
		if err := p.serveStream(kind, id, handler); err != nil {
			log.DebugContext(p.dialCtx, "auth callout: stream failed", "kind", kind, "error", err)
		}
	}()
	return true
}

// dropLogs rate limits the log line for each reason a dial is dropped, so
// that one reason cannot silence another.
type dropLogs struct {
	noHandler, tooMany, overBudget rate.Sometimes
}

// newDropLogs returns dropLogs that log each reason at most once a minute.
func newDropLogs() dropLogs {
	return dropLogs{
		noHandler:  rate.Sometimes{Interval: time.Minute},
		tooMany:    rate.Sometimes{Interval: time.Minute},
		overBudget: rate.Sometimes{Interval: time.Minute},
	}
}

// serveStream opens one stream and hands it to auth's listener or to the
// app handler. It returns once the stream closes.
func (p *Pool) serveStream(kind streamKind, id string, handler func(net.Conn)) error {
	header := http.Header{StreamIDHeader: {id}, StreamHeader: {StreamAcks}}
	ws, local, remote, err := p.dialWithAddrs(p.modeURL("stream"), header)
	if err != nil {
		return trace.Wrap(err, "dialing stream")
	}
	ws.SetReadLimit(readLimit)
	// Streams outlive Stop, so the conn takes ctx, not dialCtx.
	conn := newFlowConn(p.ctx, ws, local, remote, p.cfg.streamIdle)
	switch kind {
	case streamApp:
		go handler(conn)
	case streamAuth:
		select {
		case p.conns <- conn:
		case <-p.dialCtx.Done():
			conn.closeWith(websocket.StatusGoingAway)
			return nil
		}
	}
	select {
	case <-conn.done:
	case <-p.ctx.Done():
		conn.closeWith(websocket.StatusGoingAway)
	}
	return nil
}

// newStreamLimiters returns one stream dial limiter per stream kind.
func newStreamLimiters() map[streamKind]*rate.Limiter {
	limiters := map[streamKind]*rate.Limiter{}
	for _, kind := range []streamKind{streamAuth, streamApp} {
		limiters[kind] = rate.NewLimiter(rate.Limit(float64(streamDialsPerMinute)/60), streamDialBurst)
	}
	return limiters
}
