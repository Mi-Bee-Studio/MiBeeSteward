// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package archive

import (
	"context"
	"fmt"
	"sort"
	"time"

	"mibee-steward/internal/db"
)

// ArchiveListItem is one row of the archive list view (#667).
type ArchiveListItem struct {
	ID                int64      `json:"id"`
	Name              string     `json:"name"`
	Type              string     `json:"type"`
	Brand             string     `json:"brand"`
	Model             string     `json:"model"`
	IPAddress         string     `json:"ip_address"`
	MACAddress        string     `json:"mac_address"`
	Status            string     `json:"status"`
	ArchivedAt        time.Time  `json:"archived_at"`
	ArchivePin        string     `json:"archive_pin"`
	OnlineSince       *time.Time `json:"online_since,omitempty"`
	OfflineSince      *time.Time `json:"offline_since,omitempty"`
	Periodic          bool       `json:"periodic"`
	PeriodicCycleDays float64    `json:"periodic_cycle_days,omitempty"`
	ScanSource        string     `json:"scan_source"`
	NetworkID         *int64     `json:"network_id,omitempty"`
	NetworkName       string     `json:"network_name,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

// ListArchived returns the archived-device page (newest first) plus total.
func (s *Service) ListArchived(ctx context.Context, limit, offset int64) ([]ArchiveListItem, int64, error) {
	rows, err := s.queries.ListArchivedDevices(ctx, db.ListArchivedDevicesParams{
		Limit: limit, Offset: offset,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("list archived: %w", err)
	}
	total, err := s.queries.CountArchivedDevices(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count archived: %w", err)
	}
	out := make([]ArchiveListItem, 0, len(rows))
	for _, r := range rows {
		out = append(out, ArchiveListItem{
			ID:                r.ID,
			Name:              r.Name,
			Type:              r.Type,
			Brand:             r.Brand,
			Model:             r.Model,
			IPAddress:         r.IpAddress,
			MACAddress:        r.MacAddress,
			Status:            r.Status,
			ArchivedAt:        derefTime(r.ArchivedAt),
			ArchivePin:        r.ArchivePin,
			OnlineSince:       r.OnlineSince,
			OfflineSince:      r.OfflineSince,
			Periodic:          r.Periodic == 1,
			PeriodicCycleDays: r.PeriodicCycleDays,
			ScanSource:        r.ScanSource,
			NetworkID:         r.NetworkID,
			NetworkName:       derefString(r.NetworkName),
			CreatedAt:         r.CreatedAt,
		})
	}
	return out, total, nil
}

// SetThresholdOverride sets/clears the per-device archive threshold (days).
// days <= 0 clears the override (follow the global threshold).
func (s *Service) SetThresholdOverride(ctx context.Context, id int64, days int64) error {
	var override *int64
	if days > 0 {
		override = &days
	}
	if _, err := s.queries.UpdateArchiveThresholdOverride(ctx, db.UpdateArchiveThresholdOverrideParams{
		ArchiveOfflineDaysOverride: override, UpdatedAt: time.Now(), ID: id,
	}); err != nil {
		return fmt.Errorf("set archive threshold override: %w", err)
	}
	return nil
}

// DossierEntry is one merged timeline row of a device's dossier (#666). Kind
// selects the summary shape; Data carries the kind-specific payload.
type DossierEntry struct {
	Kind       string         `json:"kind"` // archive_event|change|config|cert|document|sighting
	OccurredAt time.Time      `json:"occurred_at"`
	Summary    string         `json:"summary"`
	Data       map[string]any `json:"data,omitempty"`
}

// Dossier aggregates the device's whole recorded life into one timeline:
// archive lifecycle events, change_log history, config-backup versions, TLS
// certificates, attached documents, and address sightings — merged,
// newest-first, capped.
func (s *Service) Dossier(ctx context.Context, deviceID int64, limit int) ([]DossierEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var entries []DossierEntry

	events, err := s.queries.ListDeviceArchiveEvents(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("dossier archive events: %w", err)
	}
	for _, e := range events {
		entries = append(entries, DossierEntry{
			Kind: "archive_event", OccurredAt: e.OccurredAt,
			Summary: e.Event + " (" + e.TriggeredBy + ")",
			Data:    map[string]any{"event": e.Event, "triggered_by": e.TriggeredBy, "id": e.ID},
		})
	}

	changes, err := s.queries.ListDeviceChangeEvents(ctx, db.ListDeviceChangeEventsParams{
		EntityID: &deviceID, Limit: 100,
	})
	if err != nil {
		return nil, fmt.Errorf("dossier change events: %w", err)
	}
	for _, c := range changes {
		entries = append(entries, DossierEntry{
			Kind: "change", OccurredAt: c.DetectedAt,
			Summary: c.ChangeType,
			Data:    map[string]any{"change_type": c.ChangeType, "before": c.BeforeData, "after": c.AfterData},
		})
	}

	configs, err := s.queries.ListDeviceConfigs(ctx, db.ListDeviceConfigsParams{
		DeviceID: deviceID, Limit: 50,
	})
	if err != nil {
		return nil, fmt.Errorf("dossier configs: %w", err)
	}
	for _, c := range configs {
		entries = append(entries, DossierEntry{
			Kind: "config", OccurredAt: c.FetchedAt,
			Summary: "running-config " + c.ConfigHash[:min(10, len(c.ConfigHash))],
			Data:    map[string]any{"config_id": c.ID, "config_hash": c.ConfigHash, "protocol": c.Protocol},
		})
	}

	certs, err := s.queries.ListTLSCertsByDeviceID(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("dossier certs: %w", err)
	}
	for _, c := range certs {
		if c.CertIndex != 0 {
			continue // chain issuers: one entry per port, leaf only
		}
		entries = append(entries, DossierEntry{
			Kind: "cert", OccurredAt: c.UpdatedAt,
			Summary: fmt.Sprintf("TLS cert %s:%d", c.Ip, c.Port),
			Data:    map[string]any{"subject_cn": c.SubjectCn, "not_after": c.NotAfter, "self_signed": c.SelfSigned == 1},
		})
	}

	docs, err := s.queries.GetDeviceDocuments(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("dossier documents: %w", err)
	}
	for _, d := range docs {
		entries = append(entries, DossierEntry{
			Kind: "document", OccurredAt: d.CreatedAt,
			Summary: d.Title,
			Data:    map[string]any{"document_id": d.ID, "type": d.Type, "url": d.Url},
		})
	}

	sightings, err := s.queries.ListDeviceSightings(ctx, db.ListDeviceSightingsParams{
		DeviceID: deviceID, Limit: 50,
	})
	if err != nil {
		return nil, fmt.Errorf("dossier sightings: %w", err)
	}
	for _, sg := range sightings {
		entries = append(entries, DossierEntry{
			Kind: "sighting", OccurredAt: sg.LastSeen,
			Summary: fmt.Sprintf("seen %s via %s", sg.IpAddress, sg.Source),
			Data:    map[string]any{"ip": sg.IpAddress, "source": sg.Source, "vantage": sg.Vantage, "see_count": sg.SeeCount},
		})
	}

	// Merge newest-first, cap.
	sort.Slice(entries, func(i, j int) bool { return entries[i].OccurredAt.After(entries[j].OccurredAt) })
	if len(entries) > limit {
		entries = entries[:limit]
	}
	return entries, nil
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
