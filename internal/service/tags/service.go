// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

// Package tags owns the tag dictionary (#665): the built-in seeds
// (internal / external / temporary / pending) plus user-defined tags, and the
// device-tag assignments. Its primary audience is distinguishing internal
// assets from outsiders' devices that were recorded because they temporarily
// used the network.
package tags

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// Built-in seed keys (stable slugs; the frontend localizes by key, `name` is
// the editable default label). Order fixes their display order.
var builtinSeeds = []struct {
	Key       string
	Name      string
	SortOrder int64
}{
	{"internal", "Internal asset", 1},
	{"external", "External device", 2},
	{"temporary", "Temporary use", 3},
	{"pending", "Ownership pending", 4},
}

var (
	// ErrTagNotFound: id/key does not exist.
	ErrTagNotFound = errors.New("tag not found")
	// ErrBuiltinProtected: delete/rename attempted on a seeded built-in.
	ErrBuiltinProtected = errors.New("built-in tag cannot be deleted")
	// ErrDuplicateKey: create with a key that already exists.
	ErrDuplicateKey = errors.New("tag key already exists")
	// ErrInvalidKey: key failed the slug validation.
	ErrInvalidKey = errors.New("invalid tag key")
)

// keyPattern: lowercase slug, 1-40 chars (a-z, 0-9, _-). Keys are the API
// identity + i18n hook for built-ins, so they stay machine-friendly.
var keyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)

// Service is the tag dictionary + assignment service. All mutating entry
// points; reads are thin enough that handlers use *db.Queries directly
// (house layering rule).
type Service struct {
	queries *db.Queries
}

func New(queries *db.Queries) *Service {
	return &Service{queries: queries}
}

// SeedBuiltins plants the four built-in tags. Idempotent (key-guarded
// insert); safe on every startup.
func (s *Service) SeedBuiltins(ctx context.Context) error {
	for _, b := range builtinSeeds {
		if _, err := s.queries.SeedBuiltinTag(ctx, db.SeedBuiltinTagParams{
			Key: b.Key, Name: b.Name, SortOrder: b.SortOrder, Key_2: b.Key,
		}); err != nil {
			return fmt.Errorf("seed builtin tag %q: %w", b.Key, err)
		}
	}
	return nil
}

// List returns the whole dictionary (built-ins first, then sort_order).
func (s *Service) List(ctx context.Context) ([]db.Tag, error) {
	return s.queries.ListTags(ctx)
}

// Get returns one tag by id.
func (s *Service) Get(ctx context.Context, id int64) (db.Tag, error) {
	return s.queries.GetTag(ctx, id)
}

// GetTagByKey resolves a dictionary tag by its stable slug (built-in lookups).
func (s *Service) GetTagByKey(ctx context.Context, key string) (db.Tag, error) {
	return s.queries.GetTagByKey(ctx, key)
}

// Create adds a user-defined tag.
func (s *Service) Create(ctx context.Context, key, name, color, description string, sortOrder int64) (db.Tag, error) {
	key = strings.ToLower(strings.TrimSpace(key))
	if !keyPattern.MatchString(key) {
		return db.Tag{}, ErrInvalidKey
	}
	if strings.TrimSpace(name) == "" {
		name = key
	}
	tag, err := s.queries.CreateTag(ctx, db.CreateTagParams{
		Key: key, Name: name, Color: color, Description: description, SortOrder: sortOrder,
	})
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return db.Tag{}, ErrDuplicateKey
		}
		return db.Tag{}, fmt.Errorf("create tag: %w", err)
	}
	return tag, nil
}

// Update edits display fields. The key and the builtin flag are immutable.
func (s *Service) Update(ctx context.Context, id int64, name, color, description string, sortOrder int64) (db.Tag, error) {
	if strings.TrimSpace(name) == "" {
		return db.Tag{}, fmt.Errorf("tag name cannot be empty")
	}
	tag, err := s.queries.UpdateTag(ctx, db.UpdateTagParams{
		Name: name, Color: color, Description: description, SortOrder: sortOrder, ID: id,
	})
	if err != nil {
		return db.Tag{}, fmt.Errorf("update tag: %w", err)
	}
	return tag, nil
}

// Delete removes a user-defined tag and ALL its device assignments.
// Built-ins are rejected (guarded here AND in the SQL).
func (s *Service) Delete(ctx context.Context, id int64) error {
	tag, err := s.queries.GetTag(ctx, id)
	if err != nil {
		return ErrTagNotFound
	}
	if tag.Builtin == 1 {
		return ErrBuiltinProtected
	}
	n, err := s.queries.DeleteTag(ctx, id)
	if err != nil {
		return fmt.Errorf("delete tag: %w", err)
	}
	if n == 0 {
		return ErrBuiltinProtected
	}
	return nil
}

// ReplaceDeviceTags sets the device's tag set atomically (PUT semantics:
// the body's tag_ids ARE the new set).
func (s *Service) ReplaceDeviceTags(ctx context.Context, deviceID int64, tagIDs []int64) error {
	if err := s.queries.ClearDeviceTags(ctx, deviceID); err != nil {
		return fmt.Errorf("clear device tags: %w", err)
	}
	for _, tid := range tagIDs {
		if _, err := s.queries.AddDeviceTag(ctx, db.AddDeviceTagParams{
			DeviceID: deviceID, TagID: tid,
		}); err != nil {
			return fmt.Errorf("assign tag %d: %w", tid, err)
		}
	}
	return nil
}

// AddToDevices bulk-assigns one tag to many devices (the "tag the visitor
// phones in one go" path). Non-existent device ids are ignored (no partial
// failure for the batch).
func (s *Service) AddToDevices(ctx context.Context, tagID int64, deviceIDs []int64) (int, error) {
	applied := 0
	for _, did := range deviceIDs {
		n, err := s.queries.AddDeviceTag(ctx, db.AddDeviceTagParams{
			DeviceID: did, TagID: tagID,
		})
		if err != nil {
			return applied, fmt.Errorf("assign tag %d to device %d: %w", tagID, did, err)
		}
		applied += int(n)
	}
	return applied, nil
}

// RemoveFromDevice removes one tag from one device.
func (s *Service) RemoveFromDevice(ctx context.Context, deviceID, tagID int64) error {
	_, err := s.queries.RemoveDeviceTag(ctx, db.RemoveDeviceTagParams{
		DeviceID: deviceID, TagID: tagID,
	})
	return err
}

// ListForDevice returns the device's tags (detail view).
func (s *Service) ListForDevice(ctx context.Context, deviceID int64) ([]db.ListDeviceTagsRow, error) {
	return s.queries.ListDeviceTags(ctx, deviceID)
}

// FillForDevices batch-loads tags for a page of devices and returns
// deviceID -> tags (list view; absent ids get no entry).
func (s *Service) FillForDevices(ctx context.Context, deviceIDs []int64) (map[int64][]domain.TagBrief, error) {
	out := make(map[int64][]domain.TagBrief)
	if len(deviceIDs) == 0 {
		return out, nil
	}
	rows, err := s.queries.ListTagAssignments(ctx, deviceIDs)
	if err != nil {
		return nil, fmt.Errorf("batch tag assignments: %w", err)
	}
	for _, r := range rows {
		out[r.DeviceID] = append(out[r.DeviceID], domain.TagBrief{
			ID: r.ID, Key: r.Key, Name: r.Name, Color: r.Color, Builtin: r.Builtin == 1,
		})
	}
	return out, nil
}
