package handler

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
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
			"version": "0.1.0",
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			slog.Debug("health response encode failed", "error", err)
		}
	}
}
