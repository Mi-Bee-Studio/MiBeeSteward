// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

func httpTarget(url string, opts *domain.ProbeOptions) db.ProbeTarget {
	t := db.ProbeTarget{
		ID: 1, Name: "t", Module: "http", Target: url,
		IntervalSeconds: 60, TimeoutSeconds: 5,
	}
	if opts != nil {
		t.Options = mustOptionsJSON(opts)
	}
	return t
}

func mustOptionsJSON(o *domain.ProbeOptions) string {
	s, err := marshalProbeOptions(o)
	if err != nil {
		panic(err)
	}
	return s
}

// TestExecuteHTTPOptions pins the option-aware http verdicts against a local
// responder: expected-status sets, keyword modes, and the HEAD shortcut.
func TestExecuteHTTPOptions(t *testing.T) {
	exec := defaultTargetExecutor
	ctx := context.Background()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("healthy: all systems nominal"))
	}))
	defer srv.Close()

	t.Run("plain legacy status rule still applies", func(t *testing.T) {
		out := exec.execute(ctx, httpTarget(srv.URL, &domain.ProbeOptions{IgnoreTLSErrors: false}))
		require.Equal(t, "success", out.Status)
	})
	t.Run("expected status accepts", func(t *testing.T) {
		out := exec.execute(ctx, httpTarget(srv.URL, &domain.ProbeOptions{ExpectedStatus: []int{200, 204}}))
		require.Equal(t, "success", out.Status)
	})
	t.Run("expected status rejects", func(t *testing.T) {
		out := exec.execute(ctx, httpTarget(srv.URL, &domain.ProbeOptions{ExpectedStatus: []int{204}}))
		require.Equal(t, "fail", out.Status)
		require.Contains(t, out.ErrMsg, "not in expected set")
		require.Equal(t, 200, out.StatusCode)
	})
	t.Run("keyword contains", func(t *testing.T) {
		out := exec.execute(ctx, httpTarget(srv.URL, &domain.ProbeOptions{Keyword: "nominal"}))
		require.Equal(t, "success", out.Status)
	})
	t.Run("keyword contains misses", func(t *testing.T) {
		out := exec.execute(ctx, httpTarget(srv.URL, &domain.ProbeOptions{Keyword: "unhealthy"}))
		require.Equal(t, "fail", out.Status)
		require.Contains(t, out.ErrMsg, "does not contain")
	})
	t.Run("keyword not_contains trips on presence", func(t *testing.T) {
		out := exec.execute(ctx, httpTarget(srv.URL, &domain.ProbeOptions{Keyword: "healthy", KeywordMode: domain.ProbeKeywordNotContains}))
		require.Equal(t, "fail", out.Status)
		require.Contains(t, out.ErrMsg, "forbidden keyword")
	})
	t.Run("keyword regex", func(t *testing.T) {
		out := exec.execute(ctx, httpTarget(srv.URL, &domain.ProbeOptions{Keyword: `healthy: .*nominal`, KeywordMode: domain.ProbeKeywordRegex}))
		require.Equal(t, "success", out.Status)
	})
	t.Run("HEAD with 204 and expected set", func(t *testing.T) {
		out := exec.execute(ctx, httpTarget(srv.URL, &domain.ProbeOptions{Method: "HEAD", ExpectedStatus: []int{204}}))
		require.Equal(t, "success", out.Status)
	})
	t.Run("status failure beats keyword check", func(t *testing.T) {
		out := exec.execute(ctx, httpTarget(srv.URL, &domain.ProbeOptions{ExpectedStatus: []int{204}, Keyword: "healthy"}))
		require.Equal(t, "fail", out.Status)
		require.Contains(t, out.ErrMsg, "not in expected set")
	})
}

// TestExecuteHTTPOptions_TimeoutClassification pins that a transport error
// burning the whole budget reads timeout, matching the legacy classifier.
func TestExecuteHTTPOptions_TimeoutClassification(t *testing.T) {
	exec := defaultTargetExecutor
	ctx := context.Background()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	// Black-hole the connection: accept, hold open, never answer - the only
	// shape that reliably burns the whole budget into a timeout (an immediate
	// close would RST and read as fail). Connections live in the accept
	// goroutine only, so the race detector has nothing to say.
	go func() {
		for {
			c, aerr := l.Accept()
			if aerr != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		}
	}()
	defer l.Close()

	out := exec.execute(ctx, httpTarget("http://"+addr+"/", nil))
	require.Equal(t, "timeout", out.Status)
}

// TestExecuteTCPOptions pins the banner-flow tcp semantics: send→expect over
// a local line server, plus plain connect-success without expectations.
func TestExecuteTCPOptions(t *testing.T) {
	exec := defaultTargetExecutor
	ctx := context.Background()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	go func() {
		for {
			c, aerr := l.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, _ := c.Read(buf)
				if string(buf[:n]) == "HELLO" {
					_, _ = c.Write([]byte("SSH-2.0-mibee-test\r\n"))
				}
			}(c)
		}
	}()
	target := func(opts *domain.ProbeOptions) db.ProbeTarget {
		return db.ProbeTarget{
			ID: 2, Name: "tcp", Module: "tcp", Target: l.Addr().String(),
			IntervalSeconds: 60, TimeoutSeconds: 3,
			Options: mustOptionsJSON(opts),
		}
	}

	t.Run("send and expect banner", func(t *testing.T) {
		out := exec.execute(ctx, target(&domain.ProbeOptions{Send: "HELLO", Expect: "SSH-2.0"}))
		require.Equal(t, "success", out.Status)
	})
	t.Run("expect regex", func(t *testing.T) {
		out := exec.execute(ctx, target(&domain.ProbeOptions{Send: "HELLO", Expect: `^SSH-\d\.\d`, ExpectMode: domain.ProbeKeywordRegex}))
		require.Equal(t, "success", out.Status)
	})
	t.Run("banner mismatch fails", func(t *testing.T) {
		out := exec.execute(ctx, target(&domain.ProbeOptions{Send: "HELLO", Expect: "FTP"}))
		require.Equal(t, "fail", out.Status)
	})
	t.Run("no options falls back to connect-only", func(t *testing.T) {
		out := exec.execute(ctx, db.ProbeTarget{
			ID: 3, Name: "tcp", Module: "tcp", Target: l.Addr().String(),
			IntervalSeconds: 60, TimeoutSeconds: 3,
		})
		require.Equal(t, "success", out.Status)
	})
}
