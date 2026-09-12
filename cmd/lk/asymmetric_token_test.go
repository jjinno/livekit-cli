// Copyright 2024 LiveKit, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenCreateHasPrivateKeyFlag(t *testing.T) {
	tokenCmd := findCommandByName(TokenCommands, "token")
	require.NotNil(t, tokenCmd)
	createCmd := findCommandByName(tokenCmd.Commands, "create")
	require.NotNil(t, createCmd)
	assert.True(t, commandHasFlag(createCmd, "private-key"),
		"'token create' must have --private-key for asymmetric signing")
}

func TestLoadSigningKeyPEM(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	dir := t.TempDir()
	good := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(good, pemBytes, 0o600))

	t.Run("valid PKCS8 EC key loads", func(t *testing.T) {
		key, err := loadSigningKeyPEM(good)
		require.NoError(t, err)
		_, ok := key.(*ecdsa.PrivateKey)
		require.True(t, ok, "expected an *ecdsa.PrivateKey")
	})

	t.Run("garbage is rejected", func(t *testing.T) {
		bad := filepath.Join(dir, "bad.pem")
		require.NoError(t, os.WriteFile(bad, []byte("not a pem"), 0o600))
		_, err := loadSigningKeyPEM(bad)
		require.Error(t, err)
	})

	t.Run("missing file is rejected", func(t *testing.T) {
		_, err := loadSigningKeyPEM(filepath.Join(dir, "nope.pem"))
		require.Error(t, err)
	})
}
