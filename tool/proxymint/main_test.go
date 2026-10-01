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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckVerification(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath, []byte("not checked here"), 0o600))
	for _, tc := range []struct {
		name    string
		flags   flags
		wantErr bool
	}{
		{name: "ca pin", flags: flags{caPins: "sha256:abc"}, wantErr: false},
		{name: "ca path", flags: flags{caPath: caPath}, wantErr: false},
		{name: "insecure", flags: flags{insecure: true}, wantErr: false},
		{name: "ca path that does not exist", flags: flags{caPath: filepath.Join(t.TempDir(), "missing.pem")}, wantErr: true},
		{name: "nothing", flags: flags{}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.flags.checkVerification()
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
