// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"

	"mibee-steward/internal/version"
)

func HealthHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var dbStatus string
		if err := db.PingContext(r.Context()); err != nil {
			dbStatus = "error"
			slog.Error("health check: db ping failed", "error", err)
		} else {
			dbStatus = "ok"
		}

		status := "ok"
		if dbStatus != "ok" {
			status = "degraded"
		}

		resp := map[string]string{
			"status":  status,
			"db":      dbStatus,
			"version": version.Version,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			slog.Debug("health response encode failed", "error", err)
		}
	}
}
