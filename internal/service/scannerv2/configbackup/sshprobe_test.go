// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package configbackup

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"mibee-steward/internal/service/scannerv2/sshcred"
)

// startTestSSHServer stands up an in-process SSH server that accepts the given
// user/password and, on any "exec" request, returns the canned config text.
// Returns its address + its host-key fingerprint (for TOFU assertions).
func startTestSSHServer(t *testing.T, wantUser, wantPW, canned string) (addr, hostKeyFP string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	_ = pub
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	hostKeyFP = ssh.FingerprintSHA256(signer.PublicKey())

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == wantUser && string(pass) == wantPW {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return // listener closed (test cleanup)
			}
			go serveSSHSession(nConn, cfg, canned)
		}
	}()
	return ln.Addr().String(), hostKeyFP
}

// serveSSHSession handles one connection: completes the SSH handshake, then for
// each "session" channel answers "exec" with the canned config + exit-status 0.
func serveSSHSession(nConn net.Conn, cfg *ssh.ServerConfig, canned string) {
	sconn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go func(in <-chan *ssh.Request) {
			defer ch.Close()
			for req := range in {
				if req.Type == "exec" {
					req.Reply(true, nil)
					_, _ = ch.Write([]byte(canned))
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{0}))
					return
				}
				req.Reply(false, nil)
			}
		}(chReqs)
	}
}

func TestFetchConfig_PasswordAuth_CapturesConfig(t *testing.T) {
	const canned = "hostname r1\ninterface eth0\n ip address 10.0.0.1/24\nend\n"
	addr, fp := startTestSSHServer(t, "admin", "pw", canned)

	cred := &sshcred.Credential{AuthMethod: "password", Username: "admin", Secret: "pw", HostKeyFP: ""}
	host, portS, _ := net.SplitHostPort(addr)
	var portI int
	fmt.Sscanf(portS, "%d", &portI)

	out, gotFP, err := FetchConfig(context.Background(), host, portI, cred, "Cisco", 5*time.Second)
	require.NoError(t, err)
	require.Equal(t, canned, out, "captured running-config text")
	require.Equal(t, fp, gotFP, "returned the actual host-key fp for TOFU pinning")
}

func TestFetchConfig_HostKeyMismatchRejected(t *testing.T) {
	addr, _ := startTestSSHServer(t, "admin", "pw", "x")
	// Pin a WRONG fingerprint → the device's key must not match.
	cred := &sshcred.Credential{AuthMethod: "password", Username: "admin", Secret: "pw",
		HostKeyFP: "SHA256:0000000000000000000000000000000000000000000000000000000000000000"}
	host, portS, _ := net.SplitHostPort(addr)
	var portI int
	fmt.Sscanf(portS, "%d", &portI)

	_, _, err := FetchConfig(context.Background(), host, portI, cred, "Cisco", 5*time.Second)
	require.ErrorIs(t, err, ErrHostKeyMismatch, "a pinned-fp mismatch must be rejected (MITM guard)")
}

func TestFetchConfig_BadPasswordRejected(t *testing.T) {
	addr, _ := startTestSSHServer(t, "admin", "pw", "x")
	cred := &sshcred.Credential{AuthMethod: "password", Username: "admin", Secret: "WRONG", HostKeyFP: ""}
	host, portS, _ := net.SplitHostPort(addr)
	var portI int
	fmt.Sscanf(portS, "%d", &portI)

	_, _, err := FetchConfig(context.Background(), host, portI, cred, "Cisco", 5*time.Second)
	require.Error(t, err, "bad credentials must fail to connect")
}

// TestFetchConfig_NilCredential is the fail-closed guard.
func TestFetchConfig_NilCredential(t *testing.T) {
	_, _, err := FetchConfig(context.Background(), "10.0.0.1", 22, nil, "Cisco", time.Second)
	require.Error(t, err)
}

func TestCommandForBrand(t *testing.T) {
	require.Equal(t, "show running-config", CommandForBrand("Cisco"))
	require.Equal(t, "show running-config", CommandForBrand("Arista"))
	require.Equal(t, "show running-config", CommandForBrand("")) // default fallback
	require.Equal(t, "show configuration | display set | no-more", CommandForBrand("Juniper"))
	require.Equal(t, "show configuration | display set | no-more", CommandForBrand("juniper networks"))
	require.Equal(t, "display current-configuration", CommandForBrand("HP"))
	require.Equal(t, "display current-configuration", CommandForBrand("Aruba"))
	require.Equal(t, "display current-configuration", CommandForBrand("H3C"))
	// Case-insensitive.
	require.True(t, strings.Contains(CommandForBrand("CISCO"), "running-config"))
}
