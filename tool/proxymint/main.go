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
//	proxymint -auth 127.0.0.1:3025 -token-file ./proxy.token \
//	  -ca-pin sha256:<pin> -host-uuid <uuid> \
//	  -principal teleport.example.com -out ./identity
//
// The token file holds the join token, which must allow the proxy role.
// Auth is verified with -ca-pin or -ca-path. -insecure joins without
// verifying auth, for a loopback auth only.
//
// The directory receives key.pem (PKCS#8), key (OpenSSH), ssh-cert.pub,
// tls.crt, tls-ca.crt and ssh-ca.pub.
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/join"
	"github.com/gravitational/teleport/lib/auth/state"
	"github.com/gravitational/teleport/lib/utils"
)

// flags are the command line flags.
type flags struct {
	authAddr  string
	tokenFile string
	hostUUID  string
	principal string
	caPath    string
	caPins    string
	insecure  bool
	out       string
}

func main() {
	var f flags
	flag.StringVar(&f.authAddr, "auth", "127.0.0.1:3025", "auth server address")
	flag.StringVar(&f.tokenFile, "token-file", "", "file holding a join token that allows the proxy role")
	flag.StringVar(&f.hostUUID, "host-uuid", "", "host UUID for the proxy identity")
	flag.StringVar(&f.principal, "principal", "", "public hostname of the proxy")
	flag.StringVar(&f.caPath, "ca-path", "", "path to the cluster CA file that verifies auth")
	flag.StringVar(&f.caPins, "ca-pin", "", "comma-separated CA pins that verify auth; takes precedence over -ca-path")
	flag.BoolVar(&f.insecure, "insecure", false, "join without verifying auth")
	flag.StringVar(&f.out, "out", "identity", "output directory")
	flag.Parse()
	if f.tokenFile == "" || f.hostUUID == "" || f.principal == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := f.checkVerification(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		flag.Usage()
		os.Exit(2)
	}
	if err := run(f); err != nil {
		log.Fatal(err)
	}
}

// checkVerification returns an error unless the flags name a way to verify
// auth, or say not to.
//
// A -ca-path that does not exist is an error here, because the join
// library joins without verification when the file is missing.
func (f flags) checkVerification() error {
	switch {
	case f.insecure:
		return nil
	case f.caPins != "":
		return nil
	case f.caPath != "":
		_, err := os.Stat(f.caPath)
		if err != nil {
			return fmt.Errorf("-ca-path: %w", err)
		}
		return nil
	}
	return errors.New("one of -ca-pin, -ca-path or -insecure is required")
}

func run(f flags) error {
	addr, err := utils.ParseAddr(f.authAddr)
	if err != nil {
		return err
	}
	tokenBytes, err := os.ReadFile(f.tokenFile)
	if err != nil {
		return fmt.Errorf("reading token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return fmt.Errorf("token file %s is empty", f.tokenFile)
	}
	var caPins []string
	if f.caPins != "" {
		caPins = strings.Split(f.caPins, ",")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := join.Register(ctx, join.RegisterParams{
		Token: token,
		ID: state.IdentityID{
			Role:     types.RoleProxy,
			HostUUID: f.hostUUID,
			NodeName: f.principal,
		},
		AuthServers:          []utils.NetAddr{*addr},
		AdditionalPrincipals: []string{f.principal},
		DNSNames:             []string{f.principal},
		CAPins:               caPins,
		CAPath:               f.caPath,
		Insecure:             f.insecure,
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

	if err := os.MkdirAll(f.out, 0o700); err != nil {
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
		if err := os.WriteFile(filepath.Join(f.out, name), data, 0o600); err != nil {
			return err
		}
	}
	fmt.Printf("wrote proxy identity for %s (%s) to %s\n", f.principal, f.hostUUID, f.out)
	return nil
}
