// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/probe"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/testutil"
)

// fakeProber stands in for every module prober. fn decides the outcome per
// call; calls counts invocations (mutex: the engine probes concurrently).
type fakeProber struct {
	mu    sync.Mutex
	calls int
	fn    func(call int) (*probe.Result, error)
}

func (f *fakeProber) Probe(_ context.Context, _ string, _ time.Duration) (*probe.Result, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.mu.Unlock()
	if f.fn == nil {
		return &probe.Result{Success: true, StatusCode: 200}, nil
	}
	return f.fn(n)
}

func (f *fakeProber) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newTestEngine(t *testing.T, queries *db.Queries, fp *fakeProber, cc certCollector) *Engine {
	t.Helper()
	e := NewEngine(queries, slog.New(slog.NewTextHandler(io.Discard, nil)), nil /* no metrics */)
	e.probers = map[string]probe.Prober{"http": fp, "tcp": fp, "icmp": fp}
	if cc == nil {
		// Never touch the network from tests; modules that don't collect certs
		// never invoke this anyway.
		cc = func(_ context.Context, _ string, _ int, _ time.Duration) []scannerv2.TLSCertRecord {
			return []scannerv2.TLSCertRecord{{Error: "stub: no cert collection in tests"}}
		}
	}
	e.certCollect = cc
	return e
}

func setupEngine(t *testing.T) (*db.Queries, *Service, *fakeProber) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	fp := &fakeProber{}
	engine := newTestEngine(t, queries, fp, nil)
	return queries, New(queries, engine), fp
}

func mustCreate(t *testing.T, svc *Service, req domain.ProbeTargetRequest) domain.ProbeTargetResponse {
	t.Helper()
	resp, err := svc.Create(context.Background(), req)
	require.NoError(t, err)
	return resp
}

func TestEngine_TriggerNowHTTP(t *testing.T) {
	queries, svc, _ := setupEngine(t)
	ctx := context.Background()
	tgt := mustCreate(t, svc, validCreate("http", "http://example.com/healthz"))

	fp := &fakeProber{fn: func(int) (*probe.Result, error) {
		return &probe.Result{Success: true, Latency: 150 * time.Millisecond, StatusCode: 200}, nil
	}}
	engine := newTestEngine(t, queries, fp, nil)

	resp, err := engine.TriggerNow(ctx, tgt.ID)
	require.NoError(t, err)
	require.Equal(t, "success", resp.Status)
	require.Equal(t, 200, resp.StatusCode)
	require.InDelta(t, 150.0, resp.LatencyMs, 1.0)

	// Persisted: one history row + denormalized last_* on the target.
	results, total, err := svc.Results(ctx, tgt.ID, 10, 0)
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Equal(t, "success", results[0].Status)

	after, err := queries.GetProbeTarget(ctx, tgt.ID)
	require.NoError(t, err)
	require.Equal(t, "success", after.LastStatus)
	require.NotEmpty(t, after.LastRunAt)
}

func TestEngine_TriggerNowDisabled(t *testing.T) {
	queries, svc, _ := setupEngine(t)
	ctx := context.Background()
	tgt := mustCreate(t, svc, validCreate("tcp", "example.com:80"))
	off := false
	_, err := svc.Update(ctx, tgt.ID, domain.UpdateProbeTargetRequest{Enabled: &off})
	require.NoError(t, err)

	engine := newTestEngine(t, queries, &fakeProber{}, nil)
	_, err = engine.TriggerNow(ctx, tgt.ID)
	require.ErrorIs(t, err, ErrProbeTargetDisabled)
}

func TestEngine_TriggerNowTLSCollectsChain(t *testing.T) {
	queries, svc, _ := setupEngine(t)
	ctx := context.Background()
	tgt := mustCreate(t, svc, validCreate("tls", "example.com:443"))

	cc := func(_ context.Context, _ string, _ int, _ time.Duration) []scannerv2.TLSCertRecord {
		return []scannerv2.TLSCertRecord{
			{IP: "example.com", Port: 443, CertIndex: 0, SubjectCN: "example.com",
				NotAfter: "2026-12-01T00:00:00Z", TLSVersion: "TLS 1.3", Trusted: true},
			{IP: "example.com", Port: 443, CertIndex: 1, SubjectCN: "Sectigo", IsCA: true},
		}
	}
	engine := newTestEngine(t, queries, &fakeProber{}, cc)

	resp, err := engine.TriggerNow(ctx, tgt.ID)
	require.NoError(t, err)
	require.Equal(t, "success", resp.Status)
	require.Equal(t, "TLS 1.3", resp.TLSVersion)
	require.Equal(t, "2026-12-01T00:00:00Z", resp.CertNotAfter)
	require.NotNil(t, resp.CertTrusted)
	require.True(t, *resp.CertTrusted)

	certs, err := queries.ListProbeTLSCertsByTarget(ctx, tgt.ID)
	require.NoError(t, err)
	require.Len(t, certs, 2, "full chain persisted (leaf + issuer)")
	require.Equal(t, "example.com", certs[0].SubjectCn)
	require.EqualValues(t, 443, certs[0].Port)
}

func TestEngine_TLSCollectionFailureKeepsLastGoodChain(t *testing.T) {
	queries, svc, _ := setupEngine(t)
	ctx := context.Background()
	tgt := mustCreate(t, svc, validCreate("tls", "example.com:443"))

	good := func(_ context.Context, _ string, _ int, _ time.Duration) []scannerv2.TLSCertRecord {
		return []scannerv2.TLSCertRecord{{IP: "example.com", Port: 443, NotAfter: "2026-12-01T00:00:00Z", TLSVersion: "TLS 1.3", Trusted: true}}
	}
	engine := newTestEngine(t, queries, &fakeProber{}, good)
	_, err := engine.TriggerNow(ctx, tgt.ID)
	require.NoError(t, err)

	// Handshake now fails (e.g. transient network) — the stored chain must
	// survive so the UI keeps showing the last known-good certificate.
	engine.certCollect = func(_ context.Context, _ string, _ int, _ time.Duration) []scannerv2.TLSCertRecord {
		return []scannerv2.TLSCertRecord{{IP: "example.com", Port: 443, Error: "dial tcp: i/o timeout"}}
	}
	resp, err := engine.TriggerNow(ctx, tgt.ID)
	require.NoError(t, err)
	require.Equal(t, "timeout", resp.Status)
	require.NotEmpty(t, resp.ErrorMessage)

	certs, err := queries.ListProbeTLSCertsByTarget(ctx, tgt.ID)
	require.NoError(t, err)
	require.Len(t, certs, 1, "last-known-good chain preserved on collection failure")
}

func TestEngine_HTTPSAttachesCertSummary(t *testing.T) {
	queries, svc, _ := setupEngine(t)
	ctx := context.Background()
	tgt := mustCreate(t, svc, validCreate("http", "https://example.com"))

	cc := func(_ context.Context, host string, port int, _ time.Duration) []scannerv2.TLSCertRecord {
		require.Equal(t, "example.com", host)
		require.Equal(t, 443, port)
		return []scannerv2.TLSCertRecord{{NotAfter: "2026-12-01T00:00:00Z", TLSVersion: "TLS 1.3", Trusted: false}}
	}
	engine := newTestEngine(t, queries, &fakeProber{}, cc)

	resp, err := engine.TriggerNow(ctx, tgt.ID)
	require.NoError(t, err)
	require.Equal(t, "success", resp.Status, "cert collection failure never flips an OK http probe")
	require.Equal(t, "TLS 1.3", resp.TLSVersion)
	require.NotNil(t, resp.CertTrusted)
	require.False(t, *resp.CertTrusted)
}

func TestEngine_TimeoutClassification(t *testing.T) {
	queries, svc, _ := setupEngine(t)
	ctx := context.Background()
	tgt := mustCreate(t, svc, validCreate("tcp", "example.com:80"))

	fp := &fakeProber{fn: func(int) (*probe.Result, error) {
		return &probe.Result{Success: false, ErrorMessage: "context deadline exceeded"}, nil
	}}
	engine := newTestEngine(t, queries, fp, nil)

	resp, err := engine.TriggerNow(ctx, tgt.ID)
	require.NoError(t, err)
	require.Equal(t, "timeout", resp.Status)
}

func TestEngine_TickSchedulesByInterval(t *testing.T) {
	queries, svc, fp := setupEngine(t)
	ctx := context.Background()
	r := validCreate("tcp", "example.com:80")
	r.IntervalSeconds = 3600
	tgt := mustCreate(t, svc, r)

	engine := newTestEngine(t, queries, fp, nil)
	engine.tick(ctx)
	require.Equal(t, 1, fp.count(), "due immediately on first sight (never run)")

	engine.tick(ctx)
	require.Equal(t, 1, fp.count(), "interval not elapsed — no re-probe")

	after, err := queries.GetProbeTarget(ctx, tgt.ID)
	require.NoError(t, err)
	require.Equal(t, "success", after.LastStatus)
}

func TestEngine_TickResumesCadenceAfterRestart(t *testing.T) {
	queries, svc, fp := setupEngine(t)
	ctx := context.Background()
	r := validCreate("tcp", "example.com:80")
	r.IntervalSeconds = 3600
	tgt := mustCreate(t, svc, r)

	// Simulate a pre-restart probe one minute ago: due again in 59 minutes.
	lastRun := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	require.NoError(t, queries.SetProbeTargetLastResult(ctx, db.SetProbeTargetLastResultParams{
		LastRunAt: lastRun, LastStatus: "success", ID: tgt.ID,
	}))

	engine := newTestEngine(t, queries, fp, nil)
	engine.tick(ctx)
	require.Zero(t, fp.count(), "fresh engine must resume the stored cadence, not probe everything at startup")
}

func TestEngine_TickSkipsDisabled(t *testing.T) {
	queries, svc, fp := setupEngine(t)
	ctx := context.Background()
	tgt := mustCreate(t, svc, validCreate("tcp", "example.com:80"))
	off := false
	_, err := svc.Update(ctx, tgt.ID, domain.UpdateProbeTargetRequest{Enabled: &off})
	require.NoError(t, err)

	engine := newTestEngine(t, queries, fp, nil)
	engine.tick(ctx)
	require.Zero(t, fp.count(), "disabled targets never probed")
}

func TestEngine_InFlightGuard(t *testing.T) {
	queries, svc, _ := setupEngine(t)
	ctx := context.Background()
	tgt := mustCreate(t, svc, validCreate("tcp", "example.com:80"))

	release := make(chan struct{})
	fp := &fakeProber{fn: func(int) (*probe.Result, error) {
		<-release
		return &probe.Result{Success: true}, nil
	}}
	engine := newTestEngine(t, queries, fp, nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := engine.TriggerNow(ctx, tgt.ID)
		require.NoError(t, err)
	}()

	// Wait until the manual trigger holds the in-flight slot, then run a tick:
	// the scheduler's attempt must skip (ErrProbeBusy), not double-probe.
	require.Eventually(t, func() bool {
		_, busy := engine.inFlight.Load(tgt.ID)
		return busy
	}, 2*time.Second, 5*time.Millisecond, "trigger should hold the in-flight slot")

	engine.tick(ctx)
	close(release)
	<-done

	require.Equal(t, 1, fp.count(), "tick during an in-flight manual trigger must not double-probe")
}

func TestEngine_TriggerNotFound(t *testing.T) {
	queries, _, _ := setupEngine(t)
	engine := newTestEngine(t, queries, &fakeProber{}, nil)
	_, err := engine.TriggerNow(context.Background(), 999)
	require.ErrorIs(t, err, ErrProbeTargetNotFound)
}
