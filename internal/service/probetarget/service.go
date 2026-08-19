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
	"strings"
	"time"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// Sentinel errors (CRUD side; engine.go holds the trigger-side ones).
var (
	ErrDuplicateName = errors.New("probe target name already exists")
)

// Service is the CRUD facade over probe_targets (+ result history reads).
// There is deliberately NO create/update/delete notification to the Engine:
// the engine re-reads enabled targets every tick, so writes take effect on
// their own within one tick interval.
type Service struct {
	queries *db.Queries
	engine  *Engine // may be nil (tests / engine-less embedding); Trigger errors then
}

// New constructs a Service.
func New(queries *db.Queries, engine *Engine) *Service {
	return &Service{queries: queries, engine: engine}
}

// Create validates and inserts a probe target. interval/timeout zero-values
// fall back to the schema defaults (60s/10s) rather than tripping validation.
func (s *Service) Create(ctx context.Context, req domain.ProbeTargetRequest) (domain.ProbeTargetResponse, error) {
	if err := domain.ValidateProbeTargetRequest(req); err != nil {
		return domain.ProbeTargetResponse{}, err
	}
	name := strings.TrimSpace(req.Name)
	if err := s.checkNameFree(ctx, name, 0); err != nil {
		return domain.ProbeTargetResponse{}, err
	}

	enabled := int64(1)
	if req.Enabled != nil && !*req.Enabled {
		enabled = 0
	}
	target := strings.TrimSpace(req.Target)
	t, err := s.queries.CreateProbeTarget(ctx, db.CreateProbeTargetParams{
		Name:            name,
		Module:          req.Module,
		Target:          target,
		IntervalSeconds: defaultIfZero(int64(req.IntervalSeconds), 60),
		TimeoutSeconds:  defaultIfZero(int64(req.TimeoutSeconds), 10),
		Enabled:         enabled,
		Notes:           req.Notes,
	})
	if err != nil {
		return domain.ProbeTargetResponse{}, err
	}
	return toTargetResponse(t), nil
}

// Get returns one target by ID.
func (s *Service) Get(ctx context.Context, id int64) (domain.ProbeTargetResponse, error) {
	t, err := s.queries.GetProbeTarget(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ProbeTargetResponse{}, ErrProbeTargetNotFound
		}
		return domain.ProbeTargetResponse{}, err
	}
	return toTargetResponse(t), nil
}

// List returns a page of targets + total, optionally filtered by a substring
// over name + target (same idiom as scan tasks).
func (s *Service) List(ctx context.Context, search string, limit, offset int) ([]domain.ProbeTargetResponse, int64, error) {
	if limit < 20 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	search = strings.TrimSpace(search)
	targets, err := s.queries.ListProbeTargetsSearch(ctx, db.ListProbeTargetsSearchParams{
		Column1: search, LOWER: search, LOWER_2: search,
		Limit: int64(limit), Offset: int64(offset),
	})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.queries.CountProbeTargetsSearch(ctx, db.CountProbeTargetsSearchParams{
		Column1: search, LOWER: search, LOWER_2: search,
	})
	if err != nil {
		return nil, 0, err
	}
	out := make([]domain.ProbeTargetResponse, 0, len(targets))
	for _, t := range targets {
		out = append(out, toTargetResponse(t))
	}
	return out, total, nil
}

// Update applies a partial update. The merged result must pass full create
// validation (module grammar + bounds), so an edit can't smuggle in a target
// shape the executor can't handle.
func (s *Service) Update(ctx context.Context, id int64, req domain.UpdateProbeTargetRequest) (domain.ProbeTargetResponse, error) {
	existing, err := s.queries.GetProbeTarget(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ProbeTargetResponse{}, ErrProbeTargetNotFound
		}
		return domain.ProbeTargetResponse{}, err
	}

	name := existing.Name
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	module := existing.Module
	if req.Module != nil {
		module = *req.Module
	}
	target := existing.Target
	if req.Target != nil {
		target = strings.TrimSpace(*req.Target)
	}
	notes := existing.Notes
	if req.Notes != nil {
		notes = *req.Notes
	}
	interval := existing.IntervalSeconds
	if req.IntervalSeconds != nil {
		interval = int64(*req.IntervalSeconds)
	}
	timeout := existing.TimeoutSeconds
	if req.TimeoutSeconds != nil {
		timeout = int64(*req.TimeoutSeconds)
	}
	enabled := existing.Enabled == 1
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	if err := domain.ValidateProbeTargetRequest(domain.ProbeTargetRequest{
		Name: name, Module: module, Target: target,
		IntervalSeconds: int(interval), TimeoutSeconds: int(timeout),
		Enabled: &enabled, Notes: notes,
	}); err != nil {
		return domain.ProbeTargetResponse{}, err
	}
	if name != existing.Name {
		if err := s.checkNameFree(ctx, name, id); err != nil {
			return domain.ProbeTargetResponse{}, err
		}
	}

	t, err := s.queries.UpdateProbeTarget(ctx, db.UpdateProbeTargetParams{
		Name:            name,
		Module:          module,
		Target:          target,
		IntervalSeconds: interval,
		TimeoutSeconds:  timeout,
		Enabled:         existing.Enabled, // toggled separately below (same split as scan tasks)
		Notes:           notes,
		ID:              id,
	})
	if err != nil {
		return domain.ProbeTargetResponse{}, err
	}
	if enabled != (existing.Enabled == 1) {
		want := int64(0)
		if enabled {
			want = 1
		}
		if err := s.queries.ToggleProbeTargetEnabled(ctx, db.ToggleProbeTargetEnabledParams{
			Enabled: want, ID: id,
		}); err != nil {
			return domain.ProbeTargetResponse{}, err
		}
		t.Enabled = want
	}
	return toTargetResponse(t), nil
}

// Delete removes the target plus its result series and stored certificate
// chain. Explicit cascade: the main DB does not enable SQLite's
// foreign_keys pragma, so ON DELETE CASCADE never fires.
func (s *Service) Delete(ctx context.Context, id int64) error {
	if _, err := s.queries.GetProbeTarget(ctx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrProbeTargetNotFound
		}
		return err
	}
	if _, err := s.queries.DeleteProbeResultsByTarget(ctx, id); err != nil {
		return err
	}
	if _, err := s.queries.DeleteProbeTLSCertsByTarget(ctx, id); err != nil {
		return err
	}
	rows, err := s.queries.DeleteProbeTarget(ctx, id)
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrProbeTargetNotFound
	}
	return nil
}

// Trigger probes one target now (synchronous — returns the recorded result).
func (s *Service) Trigger(ctx context.Context, id int64) (domain.ProbeResultResponse, error) {
	if s.engine == nil {
		return domain.ProbeResultResponse{}, ErrEngineNotAvailable
	}
	return s.engine.TriggerNow(ctx, id)
}

// Results returns a target's history (newest first) + total.
func (s *Service) Results(ctx context.Context, targetID int64, limit, offset int) ([]domain.ProbeResultResponse, int64, error) {
	if _, err := s.queries.GetProbeTarget(ctx, targetID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, ErrProbeTargetNotFound
		}
		return nil, 0, err
	}
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.queries.ListProbeResultsByTarget(ctx, db.ListProbeResultsByTargetParams{
		TargetID: targetID, Limit: int64(limit), Offset: int64(offset),
	})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.queries.CountProbeResultsByTarget(ctx, targetID)
	if err != nil {
		return nil, 0, err
	}
	out := make([]domain.ProbeResultResponse, 0, len(rows))
	for _, r := range rows {
		out = append(out, toResultResponse(r))
	}
	return out, total, nil
}

// checkNameFree enforces the UNIQUE(name) constraint ahead of INSERT/UPDATE
// so violations surface as 409-style sentinels, not opaque SQLite errors.
// selfID excludes the row itself on update (0 = create).
func (s *Service) checkNameFree(ctx context.Context, name string, selfID int64) error {
	existing, err := s.queries.GetProbeTargetByName(ctx, name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if existing.ID != selfID {
		return ErrDuplicateName
	}
	return nil
}

func toTargetResponse(t db.ProbeTarget) domain.ProbeTargetResponse {
	return domain.ProbeTargetResponse{
		ID:              t.ID,
		Name:            t.Name,
		Module:          t.Module,
		Target:          t.Target,
		IntervalSeconds: int(t.IntervalSeconds),
		TimeoutSeconds:  int(t.TimeoutSeconds),
		Enabled:         t.Enabled == 1,
		Notes:           t.Notes,
		LastRunAt:       t.LastRunAt,
		LastStatus:      t.LastStatus,
		LastLatencyMs:   t.LastLatencyMs,
		LastError:       t.LastError,
		CreatedAt:       t.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:       t.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func toResultResponse(r db.ProbeResult) domain.ProbeResultResponse {
	resp := domain.ProbeResultResponse{
		ID:           r.ID,
		TargetID:     r.TargetID,
		Status:       r.Status,
		LatencyMs:    r.LatencyMs,
		StatusCode:   int(r.StatusCode),
		ErrorMessage: r.ErrorMessage,
		TLSVersion:   r.TlsVersion,
		CertNotAfter: r.CertNotAfter,
		CheckedAt:    r.CheckedAt,
	}
	if r.CertTrusted >= 0 {
		v := r.CertTrusted == 1
		resp.CertTrusted = &v
	}
	return resp
}

func defaultIfZero(v, def int64) int64 {
	if v == 0 {
		return def
	}
	return v
}
