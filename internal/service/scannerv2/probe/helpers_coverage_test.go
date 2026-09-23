// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probe

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// --- helpers.go ---

func TestTimeMsString(t *testing.T) {
	require.Equal(t, "0", timeMsString(0))
	require.Equal(t, "42", timeMsString(42))
	require.Equal(t, "-3", timeMsString(-3))
}

// --- q_bridge_mib.go ---

func TestGosnmpToString(t *testing.T) {
	require.Equal(t, "VLAN 10", gosnmpToString("VLAN 10"))
	require.Equal(t, "port1", gosnmpToString([]byte("port1")))
	// Non-string PDU value types (int, bool) render as "", callers omit them.
	require.Empty(t, gosnmpToString(10))
	require.Empty(t, gosnmpToString(nil))
	require.Empty(t, gosnmpToString(true))
}

// --- cert_collector.go pure helpers ---

func TestTLSVersionString(t *testing.T) {
	cases := []struct {
		v    uint16
		want string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0300, ""}, // SSLv3: unrecognized post-handshake
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, tlsVersionString(tc.v), "version 0x%04X", tc.v)
	}
}

func TestLooksLikeHostname(t *testing.T) {
	require.True(t, looksLikeHostname("nas.lan.example.com"))
	require.True(t, looksLikeHostname("host.example"))
	require.False(t, looksLikeHostname("John Smith"))  // space → person name
	require.False(t, looksLikeHostname("Example Inc")) // org name
	require.False(t, looksLikeHostname("plainlabel"))  // no dot
	require.False(t, looksLikeHostname("a.b,c"))       // comma
}

// --- cert_keys.go ---

// selfSignedCertWithKey builds a minimal self-signed certificate around the
// given key so publicKeyBits can be exercised for each key family.
func selfSignedCertWithKey(t *testing.T, pub, priv any, sigAlg x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "test.local"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		SignatureAlgorithm: sigAlg,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestPublicKeyBits_KeyFamilies(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaCert := selfSignedCertWithKey(t, &rsaKey.PublicKey, rsaKey, x509.SHA256WithRSA)
	require.Equal(t, 2048, publicKeyBits(rsaCert))

	ecKey := mustECDSAKey(t)
	ecdsaCert := selfSignedCertWithKey(t, &ecKey.PublicKey, ecKey, x509.ECDSAWithSHA256)
	require.Equal(t, 256, publicKeyBits(ecdsaCert))

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edCert := selfSignedCertWithKey(t, edPub, edPriv, x509.PureEd25519)
	require.Equal(t, 256, publicKeyBits(edCert))

	// Unknown key family → 0 (field omitted rather than misleading).
	require.Equal(t, 0, publicKeyBits(&x509.Certificate{PublicKey: "not-a-key"}))
}

func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

// --- cdp_mib.go nil guards ---

func TestResolveIfNames_NilGuards(t *testing.T) {
	require.Nil(t, resolveIfNames(nil, []int{1}, nil))
	require.Nil(t, resolveIfNames(nil, nil, nil))
}
