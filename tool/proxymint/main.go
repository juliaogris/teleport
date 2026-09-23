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

// Command proxymint joins a cluster once with a proxy token and writes a
// proxy identity to a directory. The identity is for a proxy that is not a
// Teleport process, so it can present certificates that agents and auth
// accept for the proxy role.
//
// Usage:
//
//	proxymint -auth 127.0.0.1:3025 -token <proxy-token> \
//	  -host-uuid <uuid> -principal teleport.example.com -out ./identity
//
// The directory receives key.pem (PKCS#8), key (OpenSSH), ssh-cert.pub,
// tls.crt, tls-ca.crt and ssh-ca.pub. The token must allow the proxy role.
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/join"
	"github.com/gravitational/teleport/lib/auth/state"
	"github.com/gravitational/teleport/lib/utils"
)

func main() {
	authAddr := flag.String("auth", "127.0.0.1:3025", "auth server address")
	token := flag.String("token", "", "join token that allows the proxy role")
	hostUUID := flag.String("host-uuid", "", "host UUID for the proxy identity")
	principal := flag.String("principal", "", "public hostname of the proxy")
	caPath := flag.String("ca-path", "", "path to the cluster CA file; empty skips CA verification")
	out := flag.String("out", "identity", "output directory")
	flag.Parse()
	if *token == "" || *hostUUID == "" || *principal == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*authAddr, *token, *hostUUID, *principal, *caPath, *out); err != nil {
		log.Fatal(err)
	}
}

func run(authAddr, token, hostUUID, principal, caPath, out string) error {
	addr, err := utils.ParseAddr(authAddr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := join.Register(ctx, join.RegisterParams{
		Token: token,
		ID: state.IdentityID{
			Role:     types.RoleProxy,
			HostUUID: hostUUID,
			NodeName: principal,
		},
		AuthServers:          []utils.NetAddr{*addr},
		AdditionalPrincipals: []string{principal},
		DNSNames:             []string{principal},
		CAPath:               caPath,
	})
	if err != nil {
		return fmt.Errorf("registering: %w", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(res.PrivateKey)
	if err != nil {
		return fmt.Errorf("marshaling private key: %w", err)
	}
	openssh, err := ssh.MarshalPrivateKey(res.PrivateKey, "")
	if err != nil {
		return fmt.Errorf("marshaling OpenSSH private key: %w", err)
	}

	var tlsCA, sshCA []byte
	for _, c := range res.Certs.TLSCACerts {
		tlsCA = append(tlsCA, c...)
	}
	for _, c := range res.Certs.SSHCACerts {
		sshCA = append(sshCA, c...)
	}

	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	files := map[string][]byte{
		"key.pem":      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		"key":          pem.EncodeToMemory(openssh),
		"ssh-cert.pub": res.Certs.SSH,
		"tls.crt":      res.Certs.TLS,
		"tls-ca.crt":   tlsCA,
		"ssh-ca.pub":   sshCA,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(out, name), data, 0o600); err != nil {
			return err
		}
	}
	fmt.Printf("wrote proxy identity for %s (%s) to %s\n", principal, hostUUID, out)
	return nil
}
