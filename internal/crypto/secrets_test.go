// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package crypto

import (
	"encoding/base64"
	"strings"
	"testing"
)

// testKey is a fixed 32-byte key for deterministic tests. It is NOT secret —
// it never leaves the test binary.
var testKey = []byte("01234567890123456789012345678901") // exactly 32 ASCII bytes

func TestNewCipher_RejectsWrongKeyLength(t *testing.T) {
	cases := []struct {
		name string
		n    int
	}{
		{"empty", 0},
		{"too short", 16},
		{"too long", 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewCipher(make([]byte, tc.n)); err == nil {
				t.Fatalf("NewCipher(%d bytes) succeeded; want error", tc.n)
			}
		})
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	c, err := NewCipher(testKey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	cases := []string{
		"mySecretAuthPassphrase!",
		"",                          // empty must round-trip (noAuth credential convention)
		strings.Repeat("x", 10_000), // large payload exercises multi-block
		"unicode: 密码 🔑 пароль",      // UTF-8
	}
	for _, want := range cases {
		blob, err := c.Encrypt(want)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", want, err)
		}
		got, err := c.Decrypt(blob)
		if err != nil {
			t.Fatalf("Decrypt(%q): %v", want, err)
		}
		if got != want {
			t.Errorf("round-trip mismatch: got %q, want %q", got, want)
		}
	}
}

func TestEncrypt_RandomNonce_DifferentBlobs(t *testing.T) {
	// Same plaintext must yield different ciphertexts (random nonce per call).
	// If this fails, the implementation is reusing a nonce, which breaks GCM's
	// confidentiality (and is a known catastrophic GCM footgun).
	c, err := NewCipher(testKey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	const plaintext = "same passphrase"
	b1, _ := c.Encrypt(plaintext)
	b2, _ := c.Encrypt(plaintext)
	if b1 == b2 {
		t.Fatalf("two Encrypt calls produced identical blobs — nonce reuse?")
	}
	// Both must still decrypt back to the same plaintext.
	if got, _ := c.Decrypt(b1); got != plaintext {
		t.Errorf("b1 decrypted to %q, want %q", got, plaintext)
	}
	if got, _ := c.Decrypt(b2); got != plaintext {
		t.Errorf("b2 decrypted to %q, want %q", got, plaintext)
	}
}

func TestDecrypt_WrongKey_Fails(t *testing.T) {
	c1, _ := NewCipher(testKey)
	otherKey := []byte("abcdefghijklmnopqrstuvwxyz012345") // different 32-byte key
	c2, _ := NewCipher(otherKey)
	blob, _ := c1.Encrypt("secret")
	if _, err := c2.Decrypt(blob); err == nil {
		t.Fatalf("Decrypt with wrong key succeeded; want GCM auth failure")
	}
}

func TestDecrypt_TamperedBlob_Fails(t *testing.T) {
	c, _ := NewCipher(testKey)
	blob, _ := c.Encrypt("secret")

	// Flip the last char of the base64 blob — any authenticated change must
	// break the GCM tag.
	tampered := blob[:len(blob)-2] + "XX"
	// Ensure the tampered string is still valid-length base64-ish; if our
	// replacement made it un-decodable at the base64 layer that's also an
	// acceptable "fails" outcome (Decode error path). Either way no plaintext.
	if _, err := c.Decrypt(tampered); err == nil {
		t.Fatalf("Decrypt of tampered blob succeeded; want error")
	}
}

func TestDecrypt_EmptyInput_ReturnsEmpty(t *testing.T) {
	// Empty DB column = "no secret stored", must NOT error (noAuth convention).
	c, _ := NewCipher(testKey)
	got, err := c.Decrypt("")
	if err != nil {
		t.Fatalf("Decrypt(\"\"): %v", err)
	}
	if got != "" {
		t.Errorf("Decrypt(\"\") = %q, want \"\"", got)
	}
}

func TestDecrypt_MalformedBase64_Fails(t *testing.T) {
	c, _ := NewCipher(testKey)
	if _, err := c.Decrypt("!!! not base64 !!!"); err == nil {
		t.Fatalf("Decrypt of non-base64 succeeded; want error")
	}
}

func TestDecrypt_BadVersionByte_Fails(t *testing.T) {
	// Build a blob whose version byte is NOT EnvelopeVersion and confirm Decrypt
	// rejects it before touching GCM (so a future v2 blob can't be silently
	// mis-decoded by v1 code).
	c, _ := NewCipher(testKey)
	// Encrypt a real blob, then mutate the version byte via a re-encode.
	genuine, _ := c.Encrypt("x")
	// Decode → flip first byte → re-encode. If the GCM AAD were not bound to
	// the version, the flip would slip through; with AAD binding it must fail.
	raw, err := base64.StdEncoding.DecodeString(genuine)
	if err != nil {
		t.Fatalf("setup base64 decode: %v", err)
	}
	if len(raw) == 0 {
		t.Fatalf("setup: empty decoded blob")
	}
	raw[0] = 99 // impossible version
	tampered := base64.StdEncoding.EncodeToString(raw)
	if _, err := c.Decrypt(tampered); err == nil {
		t.Fatalf("Decrypt with wrong version byte succeeded; want error")
	}
}

func TestKeyFingerprint_StableAndShort(t *testing.T) {
	// Same key → same fingerprint; different key → different fingerprint; and
	// the output is always 8 hex chars (no key material leaked beyond prefix).
	fp1 := (&Cipher{}).KeyFingerprint(testKey)
	fp2 := (&Cipher{}).KeyFingerprint(testKey)
	if fp1 != fp2 {
		t.Errorf("fingerprint not stable: %q vs %q", fp1, fp2)
	}
	if len(fp1) != 8 {
		t.Errorf("fingerprint len = %d, want 8", len(fp1))
	}
	otherKey := []byte("abcdefghijklmnopqrstuvwxyz012345")
	fpOther := (&Cipher{}).KeyFingerprint(otherKey)
	if fp1 == fpOther {
		t.Errorf("different keys produced same fingerprint %q", fp1)
	}
}
