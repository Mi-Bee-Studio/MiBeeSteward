package repository

import (
	"context"
	"log/slog"

	"mibee-steward/internal/db"
)

// AuditRepository writes audit log entries to the database.
type AuditRepository struct {
	db db.DBTX
}

// NewAuditRepository creates a new AuditRepository.
func NewAuditRepository(dbConn db.DBTX) *AuditRepository {
	return &AuditRepository{db: dbConn}
}

// AuditLog represents a single audit log entry.
type AuditLog struct {
	ID           int64  `json:"id"`
	UserID       *int64 `json:"user_id"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	IPAddress    string `json:"ip_address"`
	UserAgent    string `json:"user_agent"`
	Details      string `json:"details"`
}

// Log writes an audit log entry. Errors are logged but not propagated
// to avoid disrupting the main request flow.
func (r *AuditRepository) Log(ctx context.Context, entry AuditLog) {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO audit_logs (user_id, action, resource_type, resource_id, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		entry.UserID, entry.Action, entry.ResourceType, entry.ResourceID, entry.IPAddress, entry.UserAgent, entry.Details,
	)
	if err != nil {
		slog.Error("failed to write audit log", "error", err)
	}
}
