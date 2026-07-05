package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/repository"
)

var (
	ErrBatchEmptyIDs      = errors.New("no IDs provided")
	ErrBatchSelfDelete    = errors.New("cannot delete yourself")
	ErrBatchInvalidStatus = errors.New("invalid device status")
	ErrBatchPartialDelete = errors.New("some IDs were not found")
)

// BatchService handles batch operations for devices and users.
type BatchService struct {
	db    *sql.DB
	audit *repository.AuditRepository
}

// NewBatchService creates a new BatchService.
func NewBatchService(db *sql.DB, audit *repository.AuditRepository) *BatchService {
	return &BatchService{db: db, audit: audit}
}

// DeleteDevices deletes multiple devices by IDs in a single transaction.
// Returns the number of devices actually deleted.
func (s *BatchService) DeleteDevices(ctx context.Context, ids []int64, userID int64) (int64, error) {
	if len(ids) == 0 {
		return 0, ErrBatchEmptyIDs
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // rollback errors (sql.ErrTxDone after commit) are expected

	q := db.New(tx).WithTx(tx)
	var totalDeleted int64

	for _, id := range ids {
		affected, err := q.DeleteDevice(ctx, id)
		if err != nil {
			return 0, fmt.Errorf("failed to delete device %d: %w", id, err)
		}
		totalDeleted += affected
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Audit log
	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = fmt.Sprintf("%d", id)
	}
	s.audit.Log(ctx, repository.AuditLog{
		UserID:       &userID,
		Action:       "admin.device.batch_delete",
		ResourceType: "device",
		ResourceID:   strings.Join(idStrs, ","),
		Details:      fmt.Sprintf("deleted %d devices", totalDeleted),
	})

	return totalDeleted, nil
}

// UpdateDeviceStatuses updates the status for multiple devices in a single transaction.
// Returns the number of devices actually updated.
func (s *BatchService) UpdateDeviceStatuses(ctx context.Context, ids []int64, status string, userID int64) (int64, error) {
	if len(ids) == 0 {
		return 0, ErrBatchEmptyIDs
	}

	// Validate status
	if !isValidDeviceStatus(status) {
		return 0, ErrBatchInvalidStatus
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // rollback errors (sql.ErrTxDone after commit) are expected

	// Use raw SQL for batch status update — more efficient than looping UpdateDevice
	// since we only change one field
	placeholders := make([]string, len(ids))
	args := make([]interface{}, 0, len(ids)+1)
	args = append(args, status)
	for i, id := range ids {
		placeholders[i] = "?"
		args = append(args, id)
	}

	query := fmt.Sprintf(
		"UPDATE devices SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id IN (%s)",
		strings.Join(placeholders, ","),
	)

	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to update device statuses: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	affected, _ := result.RowsAffected()

	// Audit log
	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = fmt.Sprintf("%d", id)
	}
	s.audit.Log(ctx, repository.AuditLog{
		UserID:       &userID,
		Action:       "admin.device.batch_update_status",
		ResourceType: "device",
		ResourceID:   strings.Join(idStrs, ","),
		Details:      fmt.Sprintf("set status=%s for %d devices", status, affected),
	})

	return affected, nil
}

// DeleteUsers deletes multiple users by IDs in a single transaction.
// Prevents self-deletion. Returns the number of users actually deleted.
func (s *BatchService) DeleteUsers(ctx context.Context, ids []int64, currentUserID int64) (int64, error) {
	if len(ids) == 0 {
		return 0, ErrBatchEmptyIDs
	}

	// Check for self-delete
	for _, id := range ids {
		if id == currentUserID {
			return 0, ErrBatchSelfDelete
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // rollback errors (sql.ErrTxDone after commit) are expected

	q := db.New(tx).WithTx(tx)
	var totalDeleted int64

	for _, id := range ids {
		affected, err := q.DeleteUser(ctx, id)
		if err != nil {
			return 0, fmt.Errorf("failed to delete user %d: %w", id, err)
		}
		totalDeleted += affected
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Audit log
	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = fmt.Sprintf("%d", id)
	}
	s.audit.Log(ctx, repository.AuditLog{
		UserID:       &currentUserID,
		Action:       "admin.user.batch_delete",
		ResourceType: "user",
		ResourceID:   strings.Join(idStrs, ","),
		Details:      fmt.Sprintf("deleted %d users", totalDeleted),
	})

	return totalDeleted, nil
}

// isValidDeviceStatus checks if the given status is a valid device status.
func isValidDeviceStatus(status string) bool {
	switch domain.DeviceStatus(status) {
	case domain.StatusOnline, domain.StatusOffline, domain.StatusUnknown:
		return true
	}
	return false
}
