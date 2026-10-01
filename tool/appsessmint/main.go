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

// Command appsessmint creates an app session for a user and writes the
// session's TLS certificate and key to a directory. It makes the same two
// calls a proxy makes for web app access, without a browser or a passkey.
//
// Usage:
//
//	tctl auth sign --user=alice --format=tls --out=alice --ttl=1h
//	appsessmint -user-identity alice -proxy-identity ./identity \
//	  -user alice -app octoprint -public-addr octo.example.com \
//	  -cluster example -out ./appsession
//
// -user-identity is the prefix of the files `tctl auth sign --format=tls`
// writes. -proxy-identity is a directory written by proxymint. The output
// directory receives app.crt, app.key, session-id and bearer-token.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
)

func main() {
	authAddr := flag.String("auth", "127.0.0.1:3025", "auth server address")
	userIdentity := flag.String("user-identity", "", "prefix of the user's .crt, .key and .cas files")
	proxyIdentity := flag.String("proxy-identity", "", "directory written by proxymint")
	user := flag.String("user", "", "user the session is for")
	app := flag.String("app", "", "app name")
	publicAddr := flag.String("public-addr", "", "app public address")
	cluster := flag.String("cluster", "", "cluster name")
	out := flag.String("out", "appsession", "output directory")
	flag.Parse()
	if *userIdentity == "" || *proxyIdentity == "" || *user == "" || *app == "" || *publicAddr == "" || *cluster == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*authAddr, *userIdentity, *proxyIdentity, *user, *app, *publicAddr, *cluster, *out); err != nil {
		log.Fatal(err)
	}
}

func run(authAddr, userIdentity, proxyIdentity, user, app, publicAddr, cluster, out string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	asUser, err := client.New(ctx, client.Config{
		Addrs:       []string{authAddr},
		Credentials: []client.Credentials{client.LoadKeyPair(userIdentity+".crt", userIdentity+".key", userIdentity+".cas")},
	})
	if err != nil {
		return fmt.Errorf("connecting as %s: %w", user, err)
	}
	defer asUser.Close()

	// The response carries no private key, so the proxy reads the session
	// back.
	created, err := asUser.CreateAppSession(ctx, &proto.CreateAppSessionRequest{
		Username:    user,
		PublicAddr:  publicAddr,
		ClusterName: cluster,
		AppName:     app,
	})
	if err != nil {
		return fmt.Errorf("creating app session: %w", err)
	}

	asProxy, err := client.New(ctx, client.Config{
		Addrs: []string{authAddr},
		Credentials: []client.Credentials{client.LoadKeyPair(
			filepath.Join(proxyIdentity, "tls.crt"),
			filepath.Join(proxyIdentity, "key.pem"),
			filepath.Join(proxyIdentity, "tls-ca.crt"),
		)},
	})
	if err != nil {
		return fmt.Errorf("connecting as proxy: %w", err)
	}
	defer asProxy.Close()

	session, err := asProxy.GetAppSession(ctx, types.GetAppSessionRequest{SessionID: created.GetName()})
	if err != nil {
		return fmt.Errorf("reading app session: %w", err)
	}

	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	files := map[string][]byte{
		"app.crt":      session.GetTLSCert(),
		"app.key":      session.GetTLSPriv(),
		"session-id":   []byte(session.GetName() + "\n"),
		"bearer-token": []byte(session.GetBearerToken() + "\n"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(out, name), data, 0o600); err != nil {
			return err
		}
	}
	fmt.Printf("wrote app session for %s to %s, expires %s\n", user, out, session.Expiry().Format(time.RFC3339))
	return nil
}
