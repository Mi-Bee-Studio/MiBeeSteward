package service

import (
	"context"
	"time"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// AuditService handles audit log query operations.
type AuditService struct {
	queries *db.Queries
}

// NewAuditService creates a new AuditService.
func NewAuditService(dbConn db.DBTX) *AuditService {
	return &AuditService{
		queries: db.New(dbConn),
	}
}

// List returns paginated audit logs matching the given filter.
func (s *AuditService) List(ctx context.Context, filter domain.AuditLogFilter) (*domain.AuditLogListResponse, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	// For each filter, we need to pass a sentinel + value pair to sqlc.
	// Sentinel = 0 for user_id, "" for strings/empty time — means "no filter".
	var userIDSentinel int64
	var userIDVal *int64
	if filter.UserID != nil {
		userIDSentinel = *filter.UserID
		userIDVal = filter.UserID
	}

	actionSentinel := ""
	actionVal := ""
	if filter.Action != nil {
		actionSentinel = *filter.Action
		actionVal = *filter.Action
	}

	resourceTypeSentinel := ""
	resourceTypeVal := ""
	if filter.ResourceType != nil {
		resourceTypeSentinel = *filter.ResourceType
		resourceTypeVal = *filter.ResourceType
	}

	var dateFromSentinel interface{} = ""
	var dateFromVal *time.Time
	if filter.DateFrom != nil {
		dateFromSentinel = *filter.DateFrom
		dateFromVal = filter.DateFrom
	}

	var dateToSentinel interface{} = ""
	var dateToVal *time.Time
	if filter.DateTo != nil {
		dateToSentinel = *filter.DateTo
		dateToVal = filter.DateTo
	}

	logs, err := s.queries.ListAuditLogs(ctx, db.ListAuditLogsParams{
		Column1:      userIDSentinel,
		UserID:       userIDVal,
		Column3:      actionSentinel,
		Action:       actionVal,
		Column5:      resourceTypeSentinel,
		ResourceType: resourceTypeVal,
		Column7:      dateFromSentinel,
		CreatedAt:    dateFromVal,
		Column9:      dateToSentinel,
		CreatedAt_2:  dateToVal,
		Limit:        int64(limit),
		Offset:       int64(offset),
	})
	if err != nil {
		return nil, err
	}

	total, err := s.queries.CountAuditLogs(ctx, db.CountAuditLogsParams{
		Column1:      userIDSentinel,
		UserID:       userIDVal,
		Column3:      actionSentinel,
		Action:       actionVal,
		Column5:      resourceTypeSentinel,
		ResourceType: resourceTypeVal,
		Column7:      dateFromSentinel,
		CreatedAt:    dateFromVal,
		Column9:      dateToSentinel,
		CreatedAt_2:  dateToVal,
	})
	if err != nil {
		return nil, err
	}

	responses := make([]domain.AuditLogResponse, len(logs))
	for i, log := range logs {
		responses[i] = toAuditLogResponse(log)
	}

	return &domain.AuditLogListResponse{
		AuditLogs: responses,
		Total:     int(total),
	}, nil
}

// toAuditLogResponse converts a db.AuditLog to a domain.AuditLogResponse.
func toAuditLogResponse(log db.AuditLog) domain.AuditLogResponse {
	createdAt := time.Time{}
	if log.CreatedAt != nil {
		createdAt = *log.CreatedAt
	}
	return domain.AuditLogResponse{
		ID:           log.ID,
		UserID:       log.UserID,
		Action:       log.Action,
		ResourceType: log.ResourceType,
		ResourceID:   log.ResourceID,
		IPAddress:    log.IpAddress,
		UserAgent:    log.UserAgent,
		Details:      log.Details,
		CreatedAt:    createdAt,
	}
}
