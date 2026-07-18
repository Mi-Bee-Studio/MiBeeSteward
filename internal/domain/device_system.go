// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package domain

import "time"

// DeviceSystemCategory represents the type of a system.
type DeviceSystemCategory string

const (
	CategoryWebApp     DeviceSystemCategory = "web_app"
	CategoryDatabase   DeviceSystemCategory = "database"
	CategoryMiddleware DeviceSystemCategory = "middleware"
	CategoryCustom     DeviceSystemCategory = "custom"
)

// Request types

type CreateDeviceSystemRequest struct {
	Name           string `json:"name"`
	EntryURL       string `json:"entry_url"`
	Description    string `json:"description"`
	Category       string `json:"category"`
	MetricsURL     string `json:"metrics_url"`
	MetricsEnabled bool   `json:"metrics_enabled"`
	Tags           string `json:"tags"`
}

type UpdateDeviceSystemRequest struct {
	Name           *string `json:"name,omitempty"`
	EntryURL       *string `json:"entry_url,omitempty"`
	Description    *string `json:"description,omitempty"`
	Category       *string `json:"category,omitempty"`
	MetricsURL     *string `json:"metrics_url,omitempty"`
	MetricsEnabled *bool   `json:"metrics_enabled,omitempty"`
	Tags           *string `json:"tags,omitempty"`
}

type DeviceSystemFilter struct {
	Category string `json:"category,omitempty"`
	Limit    int64  `json:"limit,omitempty"`
	Offset   int64  `json:"offset,omitempty"`
}

// Response types

type DeviceSystemResponse struct {
	ID             int64     `json:"id"`
	DeviceID       int64     `json:"device_id"`
	Name           string    `json:"name"`
	EntryURL       string    `json:"entry_url"`
	Description    string    `json:"description"`
	Category       string    `json:"category"`
	MetricsURL     string    `json:"metrics_url"`
	MetricsEnabled bool      `json:"metrics_enabled"`
	Tags           string    `json:"tags"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type DeviceSystemListResponse struct {
	Systems []DeviceSystemResponse `json:"systems"`
	Total   int                    `json:"total"`
}
