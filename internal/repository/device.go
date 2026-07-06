package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// DeviceRepository wraps sqlc queries for device operations.
type DeviceRepository struct {
	queries *db.Queries
}

// NewDeviceRepository creates a new DeviceRepository.
func NewDeviceRepository(dbConn db.DBTX) *DeviceRepository {
	return &DeviceRepository{queries: db.New(dbConn)}
}

// Create inserts a new device.
func (r *DeviceRepository) Create(ctx context.Context, req domain.CreateDeviceRequest) (db.Device, error) {
	deviceType := req.Type
	if deviceType == "" {
		deviceType = string(domain.TypeOther)
	}

	tags := req.Tags
	if tags == "" {
		tags = "{}"
	}

	userAttrs, err := domain.MarshalUserAttributes(req.UserAttributes)
	if err != nil {
		return db.Device{}, fmt.Errorf("failed to marshal user_attributes: %w", err)
	}

	device, err := r.queries.CreateDevice(ctx, db.CreateDeviceParams{
		Name:           req.Name,
		Type:           deviceType,
		Brand:          req.Brand,
		Model:          req.Model,
		Location:       req.Location,
		Purpose:        req.Purpose,
		Description:    req.Description,
		Status:         string(domain.StatusUnknown),
		IpAddress:      req.IPAddress,
		MacAddress:     req.MACAddress,
		SerialNumber:   req.SerialNumber,
		PurchaseDate:   req.PurchaseDate,
		WarrantyExpiry: req.WarrantyExpiry,
		Tags:           tags,
		UserAttributes: userAttrs,
	})
	if err != nil {
		return db.Device{}, fmt.Errorf("failed to create device: %w", err)
	}
	return device, nil
}

// UpdateUserAttributes replaces the user_attributes JSON document for a device.
func (r *DeviceRepository) UpdateUserAttributes(ctx context.Context, id int64, attrs domain.UserAttributes) error {
	raw, err := domain.MarshalUserAttributes(attrs)
	if err != nil {
		return fmt.Errorf("failed to marshal user_attributes: %w", err)
	}
	return r.queries.UpdateUserAttributes(ctx, db.UpdateUserAttributesParams{
		UserAttributes: raw,
		ID:             id,
	})
}

// UpdateScanAttributes replaces the engine-owned scan_attributes JSON
// document for a device. Only the scanner engine should call this.
func (r *DeviceRepository) UpdateScanAttributes(ctx context.Context, id int64, attrs domain.ScanAttributes) error {
	raw, err := domain.MarshalScanAttributes(attrs)
	if err != nil {
		return fmt.Errorf("failed to marshal scan_attributes: %w", err)
	}
	return r.queries.UpdateScanAttributes(ctx, db.UpdateScanAttributesParams{
		ScanAttributes: raw,
		ID:             id,
	})
}

// GetByMAC looks up a device by its normalized scan MAC via the scan_attributes
// JSON field (covered by idx_devices_scan_mac_expr). Returns the device and
// whether a match existed.
func (r *DeviceRepository) GetByMAC(ctx context.Context, mac string) (db.Device, bool, error) {
	if mac == "" {
		return db.Device{}, false, nil
	}
	device, err := r.queries.GetDeviceByMAC(ctx, mac)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return db.Device{}, false, nil
		}
		return db.Device{}, false, fmt.Errorf("failed to get device by MAC: %w", err)
	}
	return device, true, nil
}

// GetByID retrieves a device by its ID.
func (r *DeviceRepository) GetByID(ctx context.Context, id int64) (db.Device, error) {
	device, err := r.queries.GetDevice(ctx, id)
	if err != nil {
		return db.Device{}, fmt.Errorf("failed to get device: %w", err)
	}
	return device, nil
}

// List returns devices matching the filter with pagination.
func (r *DeviceRepository) List(ctx context.Context, filter domain.DeviceFilter) ([]db.Device, error) {
	statusVal := ""
	if filter.Status != "" {
		statusVal = filter.Status
	}

	typeVal := ""
	if filter.Type != "" {
		typeVal = filter.Type
	}

	devices, err := r.queries.ListDevices(ctx, db.ListDevicesParams{
		Column1: statusVal,
		Status:  statusVal,
		Column3: typeVal,
		Type:    typeVal,
		Limit:   filter.Limit,
		Offset:  filter.Offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}
	return devices, nil
}

// Count returns total device count matching the filter.
func (r *DeviceRepository) Count(ctx context.Context, filter domain.DeviceFilter) (int64, error) {
	statusVal := ""
	if filter.Status != "" {
		statusVal = filter.Status
	}

	typeVal := ""
	if filter.Type != "" {
		typeVal = filter.Type
	}

	count, err := r.queries.CountDevices(ctx, db.CountDevicesParams{
		Column1: statusVal,
		Status:  statusVal,
		Column3: typeVal,
		Type:    typeVal,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to count devices: %w", err)
	}
	return count, nil
}

// Update modifies an existing device.
func (r *DeviceRepository) Update(ctx context.Context, params db.UpdateDeviceParams) (db.Device, error) {
	device, err := r.queries.UpdateDevice(ctx, params)
	if err != nil {
		return db.Device{}, fmt.Errorf("failed to update device: %w", err)
	}
	return device, nil
}

// Delete removes a device by ID.
func (r *DeviceRepository) Delete(ctx context.Context, id int64) error {
	affected, err := r.queries.DeleteDevice(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to delete device: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("device not found")
	}
	return nil
}

// CountByStatus returns device counts grouped by status.
func (r *DeviceRepository) CountByStatus(ctx context.Context) ([]db.CountByStatusRow, error) {
	rows, err := r.queries.CountByStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to count devices by status: %w", err)
	}
	return rows, nil
}

// CountByType returns device counts grouped by type.
func (r *DeviceRepository) CountByType(ctx context.Context) ([]db.CountDevicesByTypeRow, error) {
	rows, err := r.queries.CountDevicesByType(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to count devices by type: %w", err)
	}
	return rows, nil
}
