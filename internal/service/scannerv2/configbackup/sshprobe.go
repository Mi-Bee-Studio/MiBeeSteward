// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

// Package configbackup implements the Oxidized/RANCID-style device config-
// backup feature (#137): a periodic background job fetches each managed
// network device's running-config over SSH, versions + diffs it (via
// internal/configdiff + the device_configs table), and emits a change event.
//
// This file is the SSH probe engine: a pure, testable FetchConfig that connects
// to one device with a decrypted sshcred.Credential, runs the vendor-specific
// "show running-config" command, and returns the captured text. The scheduling,
// device selection, storage, and change-detection wiring live in service.go
// (a later PR) and consume this engine.
package configbackup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"mibee-steward/internal/service/scannerv2/sshcred"
)

// ErrHostKeyMismatch is returned when the device's SSH host key does not match
// the pinned fingerprint on the credential (a possible MITM). The first connect
// (no pinned fp) always succeeds and returns the actual fingerprint for the
// caller to pin (TOFU — trust on first use).
var ErrHostKeyMismatch = errors.New("configbackup: SSH host key fingerprint mismatch (possible MITM)")

// FetchConfig connects to host:port with the decrypted credential, runs the
// vendor-specific config command, and returns the captured running-config text.
// It returns the device's actual host-key fingerprint so the caller can TOFU-
// pin it (the credential's HostKeyFP may be "" on first connect).
//
// brand selects the command via CommandForBrand. timeout bounds the connect +
// command; ctx cancels a hung connection. The credential's plaintext is read
// once here and discarded when FetchConfig returns (it lives only in the
// resolver's returned *Credential for the call duration).
func FetchConfig(ctx context.Context, host string, port int, cred *sshcred.Credential, brand string, timeout time.Duration) (config string, hostKeyFP string, err error) {
	if cred == nil {
		return "", "", errors.New("configbackup: nil credential")
	}
	if port <= 0 {
		port = 22
	}
	auth, err := authMethod(cred)
	if err != nil {
		return "", "", fmt.Errorf("ssh auth: %w", err)
	}

	var actualFP string
	hostKeyCallback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		actualFP = ssh.FingerprintSHA256(key)
		if cred.HostKeyFP != "" && actualFP != cred.HostKeyFP {
			return fmt.Errorf("%w: expected %s, got %s", ErrHostKeyMismatch, cred.HostKeyFP, actualFP)
		}
		return nil // TOFU: first connect (no pin) accepts; later connects verify.
	}

	cfg := &ssh.ClientConfig{
		User:            cred.Username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// ctx-aware dial: ssh.Dial has no context, so dial the TCP connection with
	// the context, then hand it to ssh.NewClientConn. A cancelled context closes
	// the dial (and any in-flight handshake via the conn close in the defer).
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", actualFP, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()
	go func() {
		<-ctx.Done()
		_ = conn.SetDeadline(time.Now()) // unblock a hung handshake on cancellation
	}()

	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		// A host-key mismatch surfaces here; actualFP was captured by the callback.
		return "", actualFP, err
	}
	defer sc.Close()
	client := ssh.NewClient(sc, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", actualFP, fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	out, err := session.CombinedOutput(CommandForBrand(brand))
	if err != nil {
		return "", actualFP, fmt.Errorf("ssh command %q: %w", CommandForBrand(brand), err)
	}
	return string(out), actualFP, nil
}

// authMethod builds the ssh.AuthMethod for the credential's auth_method:
// "password" → ssh.Password; "key" → ssh.PublicKeys (PEM, optionally with a
// passphrase). Returns an error for an unknown method or an unparseable key.
func authMethod(cred *sshcred.Credential) (ssh.AuthMethod, error) {
	switch cred.AuthMethod {
	case "password":
		return ssh.Password(cred.Secret), nil
	case "key":
		var (
			signer ssh.Signer
			err    error
		)
		if cred.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(cred.Secret), []byte(cred.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(cred.Secret))
		}
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		return ssh.PublicKeys(signer), nil
	default:
		return nil, fmt.Errorf("unsupported auth_method %q", cred.AuthMethod)
	}
}

// CommandForBrand returns the config-fetch command for the device's vendor
// brand (read from devices.brand). The matrix covers the SSH-management matrix
// vendors (#137 decision 1); the default is the Cisco/IOS form ("show running-
// config") which is the most common + the fallback Arista/Huawei use too.
func CommandForBrand(brand string) string {
	b := strings.ToLower(brand)
	switch {
	case strings.Contains(b, "juniper"):
		return "show configuration | display set | no-more"
	case strings.Contains(b, "hp"), strings.Contains(b, "aruba"), strings.Contains(b, "h3c"), strings.Contains(b, "comware"):
		return "display current-configuration"
	default:
		// Cisco IOS / NX-OS, Arista, Huawei VRP (many), Mikrotik (show config),
		// and unknown vendors: the widely-understood "show running-config".
		return "show running-config"
	}
}
