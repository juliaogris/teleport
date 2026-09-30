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
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	opcodeBinary = 0x2
	opcodeClose  = 0x8
)

// rawHub upgrades to WebSocket by hand, so a test can send handshake
// headers and frames a WebSocket library would refuse to send. Each
// upgraded connection is handed to conns.
type rawHub struct {
	conns chan net.Conn
	srv   *httptest.Server
}

// newRawHub returns a hub whose 101 response carries extraHeaders, each
// terminated by CRLF, and whose body starts with tail.
func newRawHub(t *testing.T, extraHeaders string, tail []byte) *rawHub {
	h := &rawHub{conns: make(chan net.Conn, 64)}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		key := r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
		sum := sha1.Sum([]byte(key))
		accept := base64.StdEncoding.EncodeToString(sum[:])
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n" + extraHeaders + "\r\n"
		if _, err := c.Write(append([]byte(resp), tail...)); err != nil {
			c.Close()
			return
		}
		h.conns <- c
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *rawHub) url(t *testing.T) *url.URL {
	u, err := url.Parse("ws" + strings.TrimPrefix(h.srv.URL, "http") + "/tunnel/auth")
	require.NoError(t, err)
	return u
}

func (h *rawHub) next(t *testing.T) net.Conn {
	select {
	case c := <-h.conns:
		t.Cleanup(func() { c.Close() })
		require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no upgraded connection within 5s")
		return nil
	}
}

// writeFrame writes one unmasked frame, as a server does.
func writeFrame(t *testing.T, w io.Writer, rsv1 bool, opcode byte, payload []byte) {
	header := []byte{0x80 | opcode}
	if rsv1 {
		header[0] |= 0x40
	}
	switch n := len(payload); {
	case n < 126:
		header = append(header, byte(n))
	case n < 1<<16:
		header = append(header, 126)
		header = binary.BigEndian.AppendUint16(header, uint16(n))
	default:
		header = append(header, 127)
		header = binary.BigEndian.AppendUint64(header, uint64(n))
	}
	_, err := w.Write(append(header, payload...))
	require.NoError(t, err)
}

// readFrame reads one masked frame, as a client sends, and returns its
// opcode and unmasked payload.
func readFrame(t *testing.T, r io.Reader) (byte, []byte) {
	var header [2]byte
	_, err := io.ReadFull(r, header[:])
	require.NoError(t, err)
	opcode := header[0] & 0x0f
	require.NotZero(t, header[1]&0x80, "client frame is not masked")
	n := uint64(header[1] & 0x7f)
	switch n {
	case 126:
		var ext [2]byte
		_, err = io.ReadFull(r, ext[:])
		require.NoError(t, err)
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		_, err = io.ReadFull(r, ext[:])
		require.NoError(t, err)
		n = binary.BigEndian.Uint64(ext[:])
	}
	var mask [4]byte
	_, err = io.ReadFull(r, mask[:])
	require.NoError(t, err)
	payload := make([]byte, n)
	_, err = io.ReadFull(r, payload)
	require.NoError(t, err)
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return opcode, payload
}
