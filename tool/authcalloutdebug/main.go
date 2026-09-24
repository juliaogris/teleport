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

// Command authcalloutdebug runs an auth callout pool outside the auth
// process and copies each stream to auth over TCP. It is for debugging the
// callout: if the proxy works with this command and not with the in-process
// callout, the fault is in the hand-over to the auth listener.
//
// Usage:
//
//	authcalloutdebug -url ws://localhost:8787/tunnel/auth -key callout.pem
package main

import (
	"flag"
	"io"
	"log"
	"log/slog"
	"net"
	"net/url"
	"os"

	"github.com/gravitational/teleport/lib/authcallout"
)

func main() {
	rawURL := flag.String("url", "", "proxy WebSocket URL")
	keyPath := flag.String("key", "", "Ed25519 key file")
	authAddr := flag.String("auth", "127.0.0.1:3025", "auth server address")
	size := flag.Int("size", 0, "number of WebSockets, 0 for the default")
	flag.Parse()
	if *rawURL == "" || *keyPath == "" {
		flag.Usage()
		os.Exit(2)
	}
	u, err := url.Parse(*rawURL)
	if err != nil {
		log.Fatal(err)
	}
	key, err := authcallout.LoadKey(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	pool, err := authcallout.New(authcallout.Config{URL: u, Key: key, Size: *size, Logger: logger})
	if err != nil {
		log.Fatal(err)
	}
	pool.Start()
	for {
		c, err := pool.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go forward(c, *authAddr)
	}
}

func forward(c net.Conn, authAddr string) {
	defer c.Close()
	a, err := net.Dial("tcp", authAddr)
	if err != nil {
		log.Printf("dialing auth: %v", err)
		return
	}
	defer a.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, c); done <- struct{}{} }()
	go func() { io.Copy(c, a); done <- struct{}{} }()
	<-done
}
