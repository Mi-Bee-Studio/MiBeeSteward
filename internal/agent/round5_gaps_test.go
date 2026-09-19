// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/probetarget"
)

// capturePoster records everything Post receives.
type capturePoster struct {
	mu    sync.Mutex
	got   []probetarget.AgentResultReport
	ch    chan struct{}
	once  sync.Once
	close func() <-chan struct{}
}

func newCapturePoster() *capturePoster {
	ch := make(chan struct{})
	p := &capturePoster{ch: ch}
	p.close = func() <-chan struct{} { return ch }
	return p
}

func (p *capturePoster) Post(_ context.Context, results []probetarget.AgentResultReport) {
	p.mu.Lock()
	p.got = append(p.got, results...)
	p.mu.Unlock()
	p.once.Do(func() { close(p.ch) })
}

func (p *capturePoster) results() []probetarget.AgentResultReport {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]probetarget.AgentResultReport(nil), p.got...)
}

// TestProber_StartStopEndToEnd covers the full lifecycle: a started prober
// probes a target queued by probeOne, and Stop flushes the batch to the
// poster via the reportLoop's ctx.Done flush.
func TestProber_StartStopEndToEnd(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)

	poster := newCapturePoster()
	p := NewProber(poster, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()
	p.Start(ctx)
	t.Cleanup(p.Stop)

	// A real http-module probe against the local test server (loopback).
	p.probeOne(ctx, probetarget.Spec{
		ID: 42, Name: "upstream", Module: "http", Target: up.URL,
		IntervalSeconds: 60, TimeoutSeconds: 5, Vantage: "agent:t",
	})

	p.Stop()

	select {
	case <-poster.close():
		res := poster.results()
		require.NotEmpty(t, res)
		require.Equal(t, int64(42), res[0].TargetID)
		require.Equal(t, "agent:t", res[0].Vantage)
		require.Equal(t, "success", res[0].Status, "loopback http probe must succeed (got %+v)", res[0])
		require.Equal(t, 200, res[0].StatusCode)
	case <-time.After(3 * time.Second):
		t.Fatal("poster never received the flushed batch after Stop")
	}
}

// TestProber_ProbeOnePanicContained: a module prober panic must be recovered,
// not wedge or crash the loop goroutine.
func TestProber_ProbeOnePanicContained(t *testing.T) {
	p := NewProber(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan struct{})
	go func() {
		defer close(done)
		// An invalid module name keeps RunTarget's dispatch table lookup
		// failing fast (no panic expected) — the recover() path itself is what
		// keeps a hypothetical panic from escaping; assert the call returns.
		p.probeOne(context.Background(), probetarget.Spec{ID: 1, Module: "no-such-module", Target: "x", TimeoutSeconds: 1})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("probeOne did not return")
	}
}

// TestHTTPResultPoster_Covers real POST semantics: auth header, payload shape,
// non-200 drop, and transport failure — none of them panic.
func TestHTTPResultPoster_Post(t *testing.T) {
	var gotAuth, gotBody string
	var gotPath string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)

	results := []probetarget.AgentResultReport{{TargetID: 7, Status: "ok"}}
	poster := NewHTTPResultPoster(up.URL, "tok-1", slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Empty batch is a no-op (no request).
	poster.Post(context.Background(), nil)

	poster.Post(context.Background(), results)
	require.Equal(t, "/api/v1/agents/probe-report", gotPath)
	require.Equal(t, "Bearer tok-1", gotAuth)
	require.Contains(t, gotBody, `"target_id":7`)

	// Non-200: logged + dropped, no panic.
	rejected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(rejected.Close)
	poster2 := NewHTTPResultPoster(rejected.URL, "t", slog.New(slog.NewTextHandler(io.Discard, nil)))
	poster2.Post(context.Background(), results)

	// Transport failure (dead server): logged + dropped, no panic.
	dead := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	_ = deadURL
	poster3 := NewHTTPResultPoster(deadURL, "t", slog.New(slog.NewTextHandler(io.Discard, nil)))
	poster3.Post(context.Background(), results)

	// Unbuildable request (control chars in URL): logged + dropped.
	poster4 := NewHTTPResultPoster("http://bad\x00url", "t", slog.New(slog.NewTextHandler(io.Discard, nil)))
	poster4.Post(context.Background(), results)
}

// TestLogRing_HandlerSemantics pins the slog.Handler surface: Enabled gates on
// the wrapped handler, WithAttrs/WithGroup share/derive rings, lines record.
func TestLogRing_HandlerSemantics(t *testing.T) {
	// nil next: everything enabled, With* return self, Lines record.
	r := NewLogRing(nil, 2)
	require.True(t, r.Enabled(context.Background(), slog.LevelDebug))
	require.Same(t, r, r.WithAttrs(nil))
	require.Same(t, r, r.WithGroup("g"))

	logger := slog.New(r)
	logger.Info("first")
	logger.Warn("second")
	logger.Error("third") // capacity 2 → "first" evicted
	lines := r.Lines()
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], "second")
	require.Contains(t, lines[1], "third")

	// Wrapped next: Enabled follows the wrapped level gate.
	inner := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn})
	r2 := NewLogRing(inner, 5)
	require.False(t, r2.Enabled(context.Background(), slog.LevelInfo))
	require.True(t, r2.Enabled(context.Background(), slog.LevelError))

	derived := r2.WithAttrs([]slog.Attr{slog.String("k", "v")})
	require.NotNil(t, derived)
	grouped := r2.WithGroup("grp")
	require.NotNil(t, grouped)
}

// TestReporterSetVersion: the setter feeds Meta's version field.
func TestReporterSetVersion(t *testing.T) {
	r := NewReporter("http://center.invalid", "tok", "agent-x", "192.168.0.0/16", 30*time.Second, 100, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.SetVersion("1.2.3-test")
	require.Equal(t, "1.2.3-test", r.Meta().Version)
}

// TestCommandPollerSetProber: wiring the prober must not panic and must be
// readable back through a plan round-trip (ApplyConfig → PlanFingerprint).
func TestCommandPollerSetProber(t *testing.T) {
	poller := NewCommandPoller("http://center.invalid", "tok", time.Minute, "192.168.0.0/16",
		func(context.Context, ScanCommand) (string, error) { return "", nil },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	pr := NewProber(nil, nil)
	poller.SetProber(pr)
	pr.ApplyConfig(ProbePlanCommand{Fingerprint: "fp-x"})
	require.Equal(t, "fp-x", pr.PlanFingerprint())
}

// TestCommandPoller_ExecuteMatrix drives the executor against a stub center
// that records every /complete POST: bad scan payload, missing targets,
// out-of-network rejection (Layer 2-agent), scan success/failure, probe plan
// without a prober, and unknown commands.
func TestCommandPoller_ExecuteMatrix(t *testing.T) {
	var mu sync.Mutex
	completions := map[int64][2]string{}
	center := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/complete") {
			id, _ := strconv.ParseInt(strings.Split(r.URL.Path, "/")[5], 10, 64)
			var body struct {
				Status string `json:"status"`
				Result string `json:"result"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			completions[id] = [2]string{body.Status, body.Result}
			mu.Unlock()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(center.Close)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	newP := func(cidr string, runScan func(context.Context, ScanCommand) (string, error)) *CommandPoller {
		return NewCommandPoller(center.URL, "tok", time.Minute, cidr, runScan, logger)
	}
	ctx := context.Background()
	run := func(p *CommandPoller, id int64, cmd, payload string) (string, string) {
		p.execute(ctx, pendingCommand{ID: id, Command: cmd, Payload: payload})
		mu.Lock()
		defer mu.Unlock()
		c := completions[id]
		return c[0], c[1]
	}

	st, res := run(newP("", nil), 1, "scan", `{nope`)
	require.Equal(t, "failed", st)
	require.Contains(t, res, "bad payload")

	st, res = run(newP("", nil), 2, "scan", `{}`)
	require.Equal(t, "failed", st)
	require.Contains(t, res, "missing targets")

	p := newP("192.168.77.0/24", nil)
	st, res = run(p, 3, "scan", `{"targets":"10.99.0.0/29"}`)
	require.Equal(t, "failed", st)
	require.Contains(t, res, "outside agent network")

	p = newP("192.168.77.0/24", func(context.Context, ScanCommand) (string, error) {
		return `{"alive":3}`, nil
	})
	st, res = run(p, 4, "scan", `{"targets":"192.168.77.0/30"}`)
	require.Equal(t, "done", st)
	require.Contains(t, res, `"alive":3`)

	p = newP("192.168.77.0/24", func(context.Context, ScanCommand) (string, error) {
		return "", errors.New("engine exploded")
	})
	st, res = run(p, 5, "scan", `{"targets":"192.168.77.1"}`)
	require.Equal(t, "failed", st)
	require.Contains(t, res, "engine exploded")

	st, res = run(newP("", nil), 6, "probe", `{"targets":[]}`)
	require.Equal(t, "failed", st)
	require.Contains(t, res, "no prober")

	st, res = run(newP("", nil), 7, "reboot-now", `{}`)
	require.Equal(t, "failed", st)
	require.Contains(t, res, "unknown command")

	// Remote ops disabled (the default) → refused with the opt-in hint.
	st, res = run(newP("", nil), 8, "restart", `{}`)
	require.Equal(t, "failed", st)
	require.Contains(t, res, "remote ops")
}
