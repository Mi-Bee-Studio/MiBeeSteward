package repository

import (
	"context"
	"fmt"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// DeviceSystemRepository wraps sqlc queries for device system operations.
type DeviceSystemRepository struct {
	queries *db.Queries
}

// NewDeviceSystemRepository creates a new DeviceSystemRepository.
func NewDeviceSystemRepository(dbConn db.DBTX) *DeviceSystemRepository {
	return &DeviceSystemRepository{queries: db.New(dbConn)}
}

// Create inserts a new device system.
func (r *DeviceSystemRepository) Create(ctx context.Context, deviceID int64, req domain.CreateDeviceSystemRequest) (db.DeviceSystem, error) {
	category := req.Category
	if category == "" {
		category = "custom"
	}

	tags := req.Tags
	if tags == "" {
		tags = "{}"
	}

	var metricsEnabled int64 = 0
	if req.MetricsEnabled {
		metricsEnabled = 1
	}

	system, err := r.queries.CreateDeviceSystem(ctx, db.CreateDeviceSystemParams{
		DeviceID:       deviceID,
		Name:           req.Name,
		EntryUrl:       req.EntryURL,
		Description:    req.Description,
		Category:       category,
		MetricsUrl:     req.MetricsURL,
		MetricsEnabled: metricsEnabled,
		Tags:           tags,
	})
	if err != nil {
		return db.DeviceSystem{}, fmt.Errorf("failed to create device system: %w", err)
	}
	return system, nil
}

// GetByID retrieves a device system by its ID.
func (r *DeviceSystemRepository) GetByID(ctx context.Context, id int64) (db.DeviceSystem, error) {
	system, err := r.queries.GetDeviceSystem(ctx, id)
	if err != nil {
		return db.DeviceSystem{}, fmt.Errorf("failed to get device system: %w", err)
	}
	return system, nil
}

// ListByDevice returns device systems for a specific device matching the filter with pagination.
func (r *DeviceSystemRepository) ListByDevice(ctx context.Context, deviceID int64, filter domain.DeviceSystemFilter) ([]db.DeviceSystem, error) {
	categoryVal := ""
	if filter.Category != "" {
		categoryVal = filter.Category
	}

	systems, err := r.queries.ListDeviceSystemsByDevice(ctx, db.ListDeviceSystemsByDeviceParams{
		DeviceID: deviceID,
		Column2:  categoryVal,
		Category: categoryVal,
		Limit:    filter.Limit,
		Offset:   filter.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list device systems by device: %w", err)
	}
	return systems, nil
}

// ListAll returns all device systems matching the filter with pagination.
func (r *DeviceSystemRepository) ListAll(ctx context.Context, filter domain.DeviceSystemFilter) ([]db.DeviceSystem, error) {
	categoryVal := ""
	if filter.Category != "" {
		categoryVal = filter.Category
	}

	systems, err := r.queries.ListAllDeviceSystems(ctx, db.ListAllDeviceSystemsParams{
		Column1:  categoryVal,
		Category: categoryVal,
		Limit:    filter.Limit,
		Offset:   filter.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list all device systems: %w", err)
	}
	return systems, nil
}

// Update modifies an existing device system.
func (r *DeviceSystemRepository) Update(ctx context.Context, params db.UpdateDeviceSystemParams) (db.DeviceSystem, error) {
	system, err := r.queries.UpdateDeviceSystem(ctx, params)
	if err != nil {
		return db.DeviceSystem{}, fmt.Errorf("failed to update device system: %w", err)
	}
	return system, nil
}

// Delete removes a device system by ID.
func (r *DeviceSystemRepository) Delete(ctx context.Context, id int64) error {
	affected, err := r.queries.DeleteDeviceSystem(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to delete device system: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("device system not found")
	}
	return nil
}

// CountByDevice returns the count of device systems for a specific device.
func (r *DeviceSystemRepository) CountByDevice(ctx context.Context, deviceID int64) (int64, error) {
	count, err := r.queries.CountDeviceSystemsByDevice(ctx, deviceID)
	if err != nil {
		return 0, fmt.Errorf("failed to count device systems by device: %w", err)
	}
	return count, nil
}

// ListForSD returns device systems with metrics enabled for Prometheus service discovery.
func (r *DeviceSystemRepository) ListForSD(ctx context.Context) ([]db.ListDeviceSystemsForSDRow, error) {
	rows, err := r.queries.ListDeviceSystemsForSD(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list device systems for SD: %w", err)
	}
	return rows, nil
}
