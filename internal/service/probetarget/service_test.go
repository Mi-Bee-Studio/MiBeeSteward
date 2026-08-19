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
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

func setupService(t *testing.T) (*Service, *db.Queries) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	return New(queries, nil), queries
}

func validCreate(module, target string) domain.ProbeTargetRequest {
	return domain.ProbeTargetRequest{
		Name: "site-tls", Module: module, Target: target,
		IntervalSeconds: 60, TimeoutSeconds: 10,
	}
}

func TestService_CreateDefaultsAndRoundtrip(t *testing.T) {
	svc, _ := setupService(t)
	ctx := context.Background()

	created, err := svc.Create(ctx, domain.ProbeTargetRequest{
		Name:   "github",
		Module: "tls",
		Target: "github.com:443",
		// interval/timeout zero → schema defaults (60/10), not validation errors.
	})
	require.NoError(t, err)
	require.EqualValues(t, 60, created.IntervalSeconds)
	require.EqualValues(t, 10, created.TimeoutSeconds)
	require.True(t, created.Enabled)
	require.Empty(t, created.LastStatus, "never probed")

	got, err := svc.Get(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "github", got.Name)
	require.Equal(t, "tls", got.Module)
}

func TestService_CreateValidation(t *testing.T) {
	svc, _ := setupService(t)
	ctx := context.Background()

	cases := []struct {
		name string
		req  domain.ProbeTargetRequest
	}{
		{"missing name", domain.ProbeTargetRequest{Module: "tcp", Target: "a.com:80", IntervalSeconds: 60, TimeoutSeconds: 5}},
		{"bad module", validCreate("gopher", "a.com:443")},
		{"http target not a URL", validCreate("http", "github.com")},
		{"http target bad scheme", validCreate("http", "ftp://example.com/")},
		{"tls target missing port", validCreate("tls", "example.com")},
		{"tcp target port out of range", validCreate("tcp", "example.com:70000")},
		{"icmp target with port", validCreate("icmp", "example.com:443")},
		{"interval too small", func() domain.ProbeTargetRequest {
			r := validCreate("tcp", "a.com:80")
			r.IntervalSeconds = 5
			return r
		}()},
		{"timeout >= interval", func() domain.ProbeTargetRequest {
			r := validCreate("tcp", "a.com:80")
			r.IntervalSeconds = 30
			r.TimeoutSeconds = 30
			return r
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.Create(ctx, tc.req)
			require.Error(t, err)
		})
	}
}

func TestService_CreateDuplicateName(t *testing.T) {
	svc, _ := setupService(t)
	ctx := context.Background()

	_, err := svc.Create(ctx, validCreate("tls", "a.com:443"))
	require.NoError(t, err)
	_, err = svc.Create(ctx, validCreate("tls", "b.com:443")) // same name "site-tls"
	require.ErrorIs(t, err, ErrDuplicateName)
}

func TestService_UpdatePartialAndMergedValidation(t *testing.T) {
	svc, _ := setupService(t)
	ctx := context.Background()

	created, err := svc.Create(ctx, validCreate("tcp", "example.com:80"))
	require.NoError(t, err)

	// Partial update: only the target moves.
	newTarget := "example.org:443"
	updated, err := svc.Update(ctx, created.ID, domain.UpdateProbeTargetRequest{Target: &newTarget})
	require.NoError(t, err)
	require.Equal(t, "example.org:443", updated.Target)
	require.Equal(t, "site-tls", updated.Name, "untouched fields preserved")

	// Switching module re-validates the merged grammar: http needs a URL.
	badModule := "http"
	_, err = svc.Update(ctx, created.ID, domain.UpdateProbeTargetRequest{Module: &badModule})
	require.Error(t, err, "host:port target must fail http grammar after module switch")

	// Rename to a taken name → duplicate; rename to itself is fine.
	_, err = svc.Create(ctx, func() domain.ProbeTargetRequest {
		r := validCreate("tcp", "x.com:80")
		r.Name = "other"
		return r
	}())
	require.NoError(t, err)
	taken := "other"
	_, err = svc.Update(ctx, created.ID, domain.UpdateProbeTargetRequest{Name: &taken})
	require.ErrorIs(t, err, ErrDuplicateName)
	selfName := "site-tls"
	_, err = svc.Update(ctx, created.ID, domain.UpdateProbeTargetRequest{Name: &selfName})
	require.NoError(t, err, "keeping one's own name is not a duplicate")
}

func TestService_UpdateEnabledToggle(t *testing.T) {
	svc, _ := setupService(t)
	ctx := context.Background()

	created, err := svc.Create(ctx, validCreate("icmp", "example.com"))
	require.NoError(t, err)

	off := false
	updated, err := svc.Update(ctx, created.ID, domain.UpdateProbeTargetRequest{Enabled: &off})
	require.NoError(t, err)
	require.False(t, updated.Enabled)

	got, err := svc.Get(ctx, created.ID)
	require.NoError(t, err)
	require.False(t, got.Enabled)
}

func TestService_DeleteCascadesResultsAndCerts(t *testing.T) {
	svc, queries := setupService(t)
	ctx := context.Background()

	created, err := svc.Create(ctx, validCreate("tls", "example.com:443"))
	require.NoError(t, err)

	// Seed one result + one cert row directly (the engine normally writes these).
	require.NoError(t, queries.CreateProbeResult(ctx, db.CreateProbeResultParams{
		TargetID: created.ID, Status: "success", CheckedAt: "2026-08-19T00:00:00Z",
	}))
	require.NoError(t, queries.CreateProbeTLSCert(ctx, db.CreateProbeTLSCertParams{
		TargetID: created.ID, Port: 443, SubjectCn: "example.com",
	}))

	require.NoError(t, svc.Delete(ctx, created.ID))

	results, err := queries.ListProbeResultsByTarget(ctx, db.ListProbeResultsByTargetParams{TargetID: created.ID, Limit: 10, Offset: 0})
	require.NoError(t, err)
	require.Empty(t, results, "result series removed with the target")

	certs, err := queries.ListProbeTLSCertsByTarget(ctx, created.ID)
	require.NoError(t, err)
	require.Empty(t, certs, "cert chain removed with the target")

	_, err = svc.Get(ctx, created.ID)
	require.ErrorIs(t, err, ErrProbeTargetNotFound)
}

func TestService_DeleteNotFound(t *testing.T) {
	svc, _ := setupService(t)
	require.ErrorIs(t, svc.Delete(context.Background(), 999), ErrProbeTargetNotFound)
}

func TestService_ListSearchAndPagination(t *testing.T) {
	svc, _ := setupService(t)
	ctx := context.Background()

	for i, tgt := range []string{"a.com:443", "b.com:443", "c.com:8080"} {
		r := validCreate("tls", tgt)
		r.Name = "target-" + string(rune('a'+i))
		_, err := svc.Create(ctx, r)
		require.NoError(t, err)
	}

	all, total, err := svc.List(ctx, "", 20, 0)
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Len(t, all, 3)

	hits, total, err := svc.List(ctx, "b.com", 20, 0)
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Len(t, hits, 1)
	require.Equal(t, "b.com:443", hits[0].Target)
}

func TestService_ResultsNewestFirst(t *testing.T) {
	svc, queries := setupService(t)
	ctx := context.Background()

	created, err := svc.Create(ctx, validCreate("http", "https://example.com"))
	require.NoError(t, err)
	for _, ts := range []string{"2026-08-19T01:00:00Z", "2026-08-19T03:00:00Z", "2026-08-19T02:00:00Z"} {
		require.NoError(t, queries.CreateProbeResult(ctx, db.CreateProbeResultParams{
			TargetID: created.ID, Status: "success", CheckedAt: ts,
		}))
	}

	results, total, err := svc.Results(ctx, created.ID, 10, 0)
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Len(t, results, 3)
	require.Equal(t, "2026-08-19T03:00:00Z", results[0].CheckedAt, "newest first")
	require.Equal(t, "2026-08-19T01:00:00Z", results[2].CheckedAt)

	_, _, err = svc.Results(ctx, 999, 10, 0)
	require.ErrorIs(t, err, ErrProbeTargetNotFound)
}

func TestService_TriggerWithoutEngine(t *testing.T) {
	svc, _ := setupService(t)
	_, err := svc.Trigger(context.Background(), 1)
	require.ErrorIs(t, err, ErrEngineNotAvailable)
}
