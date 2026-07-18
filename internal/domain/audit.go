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

// AuditLogResponse represents a single audit log entry in API responses.
type AuditLogResponse struct {
	ID           int64     `json:"id"`
	UserID       *int64    `json:"user_id"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   *string   `json:"resource_id"`
	IPAddress    *string   `json:"ip_address"`
	UserAgent    *string   `json:"user_agent"`
	Details      *string   `json:"details"`
	CreatedAt    time.Time `json:"created_at"`
}

// AuditLogListResponse wraps a list of audit logs with a total count.
type AuditLogListResponse struct {
	AuditLogs []AuditLogResponse `json:"audit_logs"`
	Total     int                `json:"total"`
}

// AuditLogFilter represents filtering parameters for audit log queries.
type AuditLogFilter struct {
	UserID       *int64
	Action       *string
	ResourceType *string
	DateFrom     *time.Time
	DateTo       *time.Time
	Limit        int32
	Offset       int32
}
