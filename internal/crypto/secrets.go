// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Package crypto provides symmetric encryption-at-rest for secrets stored in
// SQLite (SNMPv3 USM passphrases today; potentially TOTP secrets and others
// later). It uses AES-256-GCM from the standard library — no third-party
// dependency.
//
// The master key is sourced from configuration (security.master_key, overridable
// via MIBEE_SECURITY_MASTER_KEY) and held in memory only. Ciphertexts are
// self-describing blobs: a versioned envelope that carries the random
// per-message nonce inline, so a row may be migrated (re-encrypted under a new
// key) without a schema change.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// EnvelopeVersion is the version byte stamped at the start of every ciphertext
// blob. Versioning the format up front means a future key-rotation / algorithm
// change can ship without a schema migration: new writes bump the version,
// Decrypt dispatches on it, and old rows keep decrypting until rewritten.
const EnvelopeVersion byte = 1

// MasterKeyLen is the required length, in bytes, of the master key. AES-256
// needs a 32-byte key; we refuse shorter keys rather than padding, because a
// padded key is weaker than the user intended and the failure is silent.
const MasterKeyLen = 32

// Cipher wraps an AES-256-GCM cipher keyed by the master key. The zero value is
// NOT usable — construct with NewCipher.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher builds a Cipher from a master key. The key must be exactly
// MasterKeyLen (32) bytes; shorter keys are rejected (see MasterKeyLen doc for
// why). Callers pass the raw bytes — a human-typed passphrase should be run
// through a KDF first (we keep the API at the key layer to avoid hiding the
// KDF choice behind a stringly-typed convenience).
func NewCipher(masterKey []byte) (*Cipher, error) {
	if len(masterKey) != MasterKeyLen {
		return nil, fmt.Errorf("crypto: master key must be exactly %d bytes (got %d)", MasterKeyLen, len(masterKey))
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: cipher.NewGCM: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt seals plaintext under the master key and returns a self-describing
// base64 blob. The blob layout is:
//
//	[ version:1 ][ nonce:12 ][ ciphertext+tag ]
//
// The nonce is cryptographically random per call, so encrypting the same
// passphrase twice yields different blobs (the test asserts this). The empty
// string is a valid plaintext and round-trips; it is NOT special-cased, so an
// empty passphrase is still confidentiality-protected (relevant for v3
// noAuth/noPriv rows where the field is intentionally empty).
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("crypto: read nonce: %w", err)
	}
	// Pre-allocate the full blob so Seal can write into it in place: version +
	// nonce (plain) then ciphertext+tag (sealed). One allocation, no copies.
	blob := make([]byte, 0, 1+len(nonce)+len(plaintext)+c.aead.Overhead())
	blob = append(blob, EnvelopeVersion)
	blob = append(blob, nonce...)
	// The version byte is ALSO bound as AAD so Decrypt can detect a flipped
	// version even before GCM verifies the rest — see the matching Open below.
	blob = c.aead.Seal(blob, nonce, []byte(plaintext), []byte{EnvelopeVersion})
	return base64.StdEncoding.EncodeToString(blob), nil
}

// Decrypt reverses Encrypt. It fails (non-nil error) if the blob is malformed,
// was sealed under a different key, or was tampered with — GCM authenticates
// the ciphertext and the version byte, so any modification is detected.
//
// An empty input string returns ("", nil) — the caller convention is that an
// empty DB column means "no secret stored" (e.g. a noAuth v3 credential has no
// passphrase), distinct from a corrupt blob. This keeps inserts of partial v3
// credentials simple.
func (c *Cipher) Decrypt(blob string) (string, error) {
	if blob == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return "", fmt.Errorf("crypto: base64 decode: %w", err)
	}
	if len(raw) < 1 {
		return "", errors.New("crypto: blob too short for version byte")
	}
	if raw[0] != EnvelopeVersion {
		return "", fmt.Errorf("crypto: unsupported envelope version %d (want %d)", raw[0], EnvelopeVersion)
	}
	raw = raw[1:]
	ns := c.aead.NonceSize()
	if len(raw) < ns+c.aead.Overhead() {
		return "", errors.New("crypto: blob too short for nonce+ciphertext")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := c.aead.Open(nil, nonce, ct, []byte{EnvelopeVersion})
	if err != nil {
		return "", fmt.Errorf("crypto: gcm open: %w", err)
	}
	return string(pt), nil
}

// Stamping the version byte as AAD (via the {EnvelopeVersion} slice above) ties
// the on-wire version to the authenticated data: an attacker can't flip the
// version byte to bypass a future decrypt path without invalidating the GCM
// tag. Keep this in sync with Encrypt's Sealed AAD.

// KeyFingerprint returns a short, non-reversible hex prefix of the master key.
// It exists so startup logs and tests can confirm two processes share a key
// WITHOUT exposing the key itself — useful when verifying a deployment picked
// up MIBEE_SECURITY_MASTER_KEY. Only the first 4 bytes (8 hex chars) are
// surfaced: enough to spot a mismatch, far too little to aid an attack.
func (c *Cipher) KeyFingerprint(masterKey []byte) string {
	if len(masterKey) < 4 {
		return "????????"
	}
	// uint32 avoids the binary.Read/Write dance for one integer.
	v := binary.BigEndian.Uint32(masterKey[:4])
	return fmt.Sprintf("%08x", v)
}
