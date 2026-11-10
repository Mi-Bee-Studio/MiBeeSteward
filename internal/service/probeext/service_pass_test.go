package probeext

// Service-level pass-through coverage for the two API-facing readers the
// store tests do not reach through the service constructors: the coverage
// ratchet flagged the merged stack at 85.1% vs the 85.2% floor — these two
// one-line service methods were the uncovered straws on the new code.

import (
	"context"
	"testing"

	"mibee-steward/internal/config"
	"mibee-steward/internal/service/probe"
)

func TestService_ListTargetPhases_PassThrough(t *testing.T) {
	store := openTestStore(t)
	queries, _ := openTestQueries(t)
	svc := NewService(config.ProbeConfig{}, store, queries, nil)
	ctx := context.Background()

	// Empty history: no rows, no error.
	rows, err := svc.ListTargetPhases(ctx, 7, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("empty history returned %d rows", len(rows))
	}

	// StorePhase with nil or empty phases writes no row (the no-op
	// contract, pinned by TestStorePhasesRoundTrip); seed a data-bearing
	// one instead.
	if err := store.StorePhase(ctx, 7, "http", "center", "2026-11-09T01:00:00Z", 75.5,
		&probe.Phases{ResolvedIP: "203.0.113.9", DNSMs: 8, ConnectMs: 20, TLSMs: 31, TTFBMs: 12}); err != nil {
		t.Fatal(err)
	}
	rows, err = svc.ListTargetPhases(ctx, 7, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].DNSMs != 8 {
		t.Fatalf("rows=%+v, want one phase row with dns_ms=8", rows)
	}
}

func TestEpisodeService_ListEpisodesSince_PassThrough(t *testing.T) {
	store := openTestStore(t)
	queries, _ := openTestQueries(t)
	svc := NewEpisodeService(store, queries, nil, config.QualityEpisodeConfig{}, nil, nil)
	ctx := context.Background()

	if _, err := store.InsertEpisode(ctx, QualityEpisode{
		Kind: EpisodeKindNetwork, VantageGroup: "center", TargetGroup: "",
		StartedAt: "2026-11-08T08:00:00Z", LastSeenAt: "2026-11-08T08:30:00Z", Windows: 3,
		MetricDegraded: []EpisodeMetric{{TargetID: 1, Name: "a", Vantage: "center", P50Ms: 400, BaseP50Ms: 100, Reason: "latency"}},
	}); err != nil {
		t.Fatal(err)
	}

	eps, err := svc.ListEpisodesSince(ctx, "2026-11-08T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].Kind != EpisodeKindNetwork {
		t.Fatalf("episodes=%+v, want the seeded network episode", eps)
	}
}
