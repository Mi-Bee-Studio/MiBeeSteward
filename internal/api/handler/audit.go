package handler

import (
	"net/http"
	"strconv"
	"time"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/service"
)

// AuditHandler handles HTTP requests for audit log endpoints.
type AuditHandler struct {
	svc *service.AuditService
}

// NewAuditHandler creates a new AuditHandler.
func NewAuditHandler(svc *service.AuditService) *AuditHandler {
	return &AuditHandler{svc: svc}
}

// List handles GET /api/v1/audit-logs
func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)

	var userID *int64
	if uid := q.Get("user_id"); uid != "" {
		if parsed, err := strconv.ParseInt(uid, 10, 64); err == nil {
			userID = &parsed
		}
	}

	var action *string
	if a := q.Get("action"); a != "" {
		action = &a
	}

	var resourceType *string
	if rt := q.Get("resource_type"); rt != "" {
		resourceType = &rt
	}

	var dateFrom *time.Time
	if df := q.Get("date_from"); df != "" {
		if parsed, err := time.Parse(time.RFC3339, df); err == nil {
			dateFrom = &parsed
		}
	}

	var dateTo *time.Time
	if dt := q.Get("date_to"); dt != "" {
		if parsed, err := time.Parse(time.RFC3339, dt); err == nil {
			dateTo = &parsed
		}
	}

	filter := domain.AuditLogFilter{
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		DateFrom:     dateFrom,
		DateTo:       dateTo,
		Limit:        int32(limit),
		Offset:       int32(offset),
	}

	resp, err := h.svc.List(r.Context(), filter)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list audit logs")
		return
	}

	Success(w, resp)
}
