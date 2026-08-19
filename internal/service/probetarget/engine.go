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
	"database/sql"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/probe"
	"mibee-steward/internal/service/scannerv2"
	scannerv2probe "mibee-steward/internal/service/scannerv2/probe"
)

// Sentinel errors surfaced to the handler for status-code mapping.
var (
	ErrProbeTargetNotFound = errors.New("probe target not found")
	ErrProbeTargetDisabled = errors.New("probe target is disabled")
	ErrProbeBusy           = errors.New("probe already running for this target")
	ErrEngineNotAvailable  = errors.New("probe engine not available")
)

const (
	// tickInterval is how often the engine re-reads enabled targets. A tick is
	// NOT a probe: per-target due times come from each target's interval and
	// last_run_at, so a 10s tick schedules anything ≥10s faithfully while
	// keeping CRUD changes effective within 10s without any notify wiring.
	tickInterval = 10 * time.Second
	// maxConcurrency bounds simultaneous probes (semaphore). External targets
	// are few; 8 keeps a burst of due targets from hogging connections.
	maxConcurrency = 8
)

// Engine is the interval scheduler + probe executor. The DB is the source of
// truth: every tick re-lists enabled targets (adds/edits/deletes apply within
// one tick — no restart, no in-memory registry to desync), while an in-memory
// nextDue map (seeded from last_run_at on first sight) prevents re-probing a
// target the process just probed before a restart.
type Engine struct {
	queries     *db.Queries
	logger      *slog.Logger
	metrics     *metrics
	probers     map[string]probe.Prober // http/tcp/icmp modules
	certCollect certCollector

	nextDue  map[int64]time.Time
	mu       sync.Mutex // guards nextDue
	inFlight sync.Map   // target ID → struct{}; guards against tick/trigger overlap
	sem      chan struct{}

	cancel  context.CancelFunc
	done    chan struct{}
	startMu sync.Mutex
	started bool
}

// NewEngine constructs an Engine. reg may be nil (tests) to skip metrics.
func NewEngine(queries *db.Queries, logger *slog.Logger, reg prometheus.Registerer) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		queries: queries,
		logger:  logger,
		metrics: newMetrics(reg),
		probers: map[string]probe.Prober{
			"http": &probe.HTTPProber{},
			"tcp":  &probe.TCPProber{},
			"icmp": &probe.ICMPProber{},
		},
		certCollect: scannerv2probe.CollectCertChain,
		nextDue:     make(map[int64]time.Time),
		sem:         make(chan struct{}, maxConcurrency),
		done:        make(chan struct{}),
	}
}

// Start launches the tick loop (one immediate sweep, then every tickInterval).
// Idempotent: a second call is a no-op.
func (e *Engine) Start(ctx context.Context) {
	e.startMu.Lock()
	defer e.startMu.Unlock()
	if e.started {
		return
	}
	e.started = true
	ctx, e.cancel = context.WithCancel(ctx)
	go e.run(ctx)
}

// Stop cancels the loop and waits for the in-flight tick (including its
// probes) to settle. Safe to call even if Start was never called.
func (e *Engine) Stop() {
	e.startMu.Lock()
	cancel := e.cancel
	started := e.started
	e.startMu.Unlock()
	if !started {
		return
	}
	if cancel != nil {
		cancel()
	}
	<-e.done
}

func (e *Engine) run(ctx context.Context) {
	defer close(e.done)
	e.tick(ctx)
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.tick(ctx)
		}
	}
}

// tick lists enabled targets, launches those that are due (bounded), and
// prunes state for targets that disappeared.
func (e *Engine) tick(ctx context.Context) {
	targets, err := e.queries.ListEnabledProbeTargets(ctx)
	if err != nil {
		e.logger.Error("probe engine: list targets failed", "error", err)
		return
	}

	now := time.Now()
	current := make(map[string]bool, len(targets))

	var wg sync.WaitGroup
	e.mu.Lock()
	present := make(map[int64]bool, len(targets))
	for _, t := range targets {
		present[t.ID] = true
	}
	for id := range e.nextDue {
		if !present[id] {
			delete(e.nextDue, id) // deleted/disabled since last tick
		}
	}
	for i := range targets {
		t := targets[i]
		current[t.Name+"/"+t.Module] = true

		due, ok := e.nextDue[t.ID]
		if !ok {
			// First sight this process: resume the target's own cadence instead
			// of probing everything at once on startup. Never-run targets are
			// due immediately.
			due = now
			if t.LastRunAt != "" {
				if lr, perr := time.Parse(time.RFC3339, t.LastRunAt); perr == nil {
					due = lr.Add(time.Duration(t.IntervalSeconds) * time.Second)
				}
			}
			e.nextDue[t.ID] = due
		}
		if now.Before(due) {
			continue
		}
		// Reserve the slot BEFORE probing (heartbeat's lastProbe trick): a slow
		// probe must not cause a second launch on the next tick. The next due
		// lands a full interval after this tick, absorbing the probe duration.
		e.nextDue[t.ID] = now.Add(time.Duration(t.IntervalSeconds) * time.Second)

		wg.Add(1)
		go func() {
			defer wg.Done()
			e.sem <- struct{}{}
			defer func() { <-e.sem }()
			if _, err := e.probeTarget(ctx, t); err != nil && !errors.Is(err, ErrProbeBusy) {
				e.logger.Warn("probe engine: probe failed", "target_id", t.ID, "name", t.Name, "error", err)
			}
		}()
	}
	e.mu.Unlock()

	wg.Wait()
	e.metrics.retain(current)
}

// TriggerNow probes one target synchronously and returns the recorded result
// (bounded by the target's timeout — the handler responds with real data, not
// a "triggered" acknowledgment). Disabled targets are rejected like scan
// tasks; a target already mid-probe returns ErrProbeBusy.
func (e *Engine) TriggerNow(ctx context.Context, targetID int64) (domain.ProbeResultResponse, error) {
	t, err := e.queries.GetProbeTarget(ctx, targetID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ProbeResultResponse{}, ErrProbeTargetNotFound
		}
		return domain.ProbeResultResponse{}, err
	}
	if t.Enabled == 0 {
		return domain.ProbeResultResponse{}, ErrProbeTargetDisabled
	}
	resp, err := e.probeTarget(ctx, t)
	if errors.Is(err, ErrProbeBusy) {
		// Manual trigger raced the scheduler's run of the same target — the
		// outcome is already being written; report it as busy rather than block.
		return domain.ProbeResultResponse{}, ErrProbeBusy
	}
	return resp, err
}

// probeTarget runs one probe and persists everything: the probe_results series
// row, the denormalized last_* on the target, the certificate chain (upsert),
// and the Prometheus gauges. The in-flight guard makes tick-launched and
// trigger-launched runs of the same target mutually exclusive.
func (e *Engine) probeTarget(ctx context.Context, t db.ProbeTarget) (domain.ProbeResultResponse, error) {
	if _, busy := e.inFlight.LoadOrStore(t.ID, struct{}{}); busy {
		return domain.ProbeResultResponse{}, ErrProbeBusy
	}
	defer e.inFlight.Delete(t.ID)

	checkedAt := time.Now().UTC().Format(time.RFC3339)
	out := e.execute(ctx, t)

	if err := e.queries.CreateProbeResult(ctx, db.CreateProbeResultParams{
		TargetID:     t.ID,
		Status:       out.status,
		LatencyMs:    float64(out.latency.Microseconds()) / 1000.0,
		StatusCode:   int64(out.statusCode),
		ErrorMessage: out.errMsg,
		TlsVersion:   out.tlsVersion,
		CertNotAfter: out.certNotAfter,
		CertTrusted:  certTrustedDB(out.certTrusted),
		CheckedAt:    checkedAt,
	}); err != nil {
		e.logger.Error("probe engine: persist result failed", "target_id", t.ID, "error", err)
	}

	if err := e.queries.SetProbeTargetLastResult(ctx, db.SetProbeTargetLastResultParams{
		LastRunAt:     checkedAt,
		LastStatus:    out.status,
		LastLatencyMs: float64(out.latency.Microseconds()) / 1000.0,
		LastError:     out.errMsg,
		ID:            t.ID,
	}); err != nil {
		e.logger.Error("probe engine: update target last-result failed", "target_id", t.ID, "error", err)
	}

	// Upsert only on successful collection: a transient handshake failure must
	// not wipe the last known-good chain (deliberately unlike host_tls_certs,
	// whose "current state" semantics serve a different UI).
	if len(out.certs) > 0 {
		if err := e.upsertCerts(ctx, t.ID, out.certs); err != nil {
			e.logger.Error("probe engine: upsert certs failed", "target_id", t.ID, "error", err)
		}
	}

	e.metrics.record(t.Name, t.Module, out.status, out.latency.Seconds(), certExpiryUnix(out.certNotAfter))

	return domain.ProbeResultResponse{
		TargetID:     t.ID,
		Status:       out.status,
		LatencyMs:    float64(out.latency.Microseconds()) / 1000.0,
		StatusCode:   out.statusCode,
		ErrorMessage: out.errMsg,
		TLSVersion:   out.tlsVersion,
		CertNotAfter: out.certNotAfter,
		CertTrusted:  out.certTrusted,
		CheckedAt:    checkedAt,
	}, nil
}

// upsertCerts replaces the target's stored chain (delete-then-insert in one
// sequence — sqlc can't express the upsert; mirrors store.RecordTLSCerts).
func (e *Engine) upsertCerts(ctx context.Context, targetID int64, certs []scannerv2.TLSCertRecord) error {
	if _, err := e.queries.DeleteProbeTLSCertsByTarget(ctx, targetID); err != nil {
		return err
	}
	for _, c := range certs {
		params := db.CreateProbeTLSCertParams{
			TargetID:          targetID,
			Port:              int64(c.Port),
			CertIndex:         int64(c.CertIndex),
			SubjectCn:         c.SubjectCN,
			SubjectOrg:        c.SubjectOrg,
			Subject:           c.Subject,
			IssuerCn:          c.IssuerCN,
			IssuerOrg:         c.IssuerOrg,
			Issuer:            c.Issuer,
			SanDns:            c.SanDNS,
			SanIp:             c.SanIP,
			SanEmail:          c.SanEmail,
			Serial:            c.Serial,
			NotBefore:         c.NotBefore,
			NotAfter:          c.NotAfter,
			SigAlgorithm:      c.SigAlgorithm,
			KeyAlgorithm:      c.KeyAlgorithm,
			KeyBits:           int64(c.KeyBits),
			IsCa:              boolToInt64(c.IsCA),
			SelfSigned:        boolToInt64(c.SelfSigned),
			FingerprintSha256: c.FingerprintSHA256,
			Pem:               c.PEM,
			TlsVersion:        c.TLSVersion,
			CipherSuite:       c.CipherSuite,
			Trusted:           boolToInt64(c.Trusted),
			Error:             c.Error,
		}
		if err := e.queries.CreateProbeTLSCert(ctx, params); err != nil {
			return err
		}
	}
	return nil
}

// certTrustedDB maps the nullable trust verdict to the sentinel-int column
// (-1 = no cert this run, 0/1 = verdict).
func certTrustedDB(v *bool) int64 {
	if v == nil {
		return -1
	}
	return boolToInt64(*v)
}

func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// certExpiryUnix parses the leaf NotAfter into a Unix timestamp for the
// expiry gauge; nil when no cert was collected.
func certExpiryUnix(notAfter string) *float64 {
	if notAfter == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, notAfter)
	if err != nil {
		return nil
	}
	v := float64(t.Unix())
	return &v
}
