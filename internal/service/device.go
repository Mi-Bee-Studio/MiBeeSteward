package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/repository"
)

var (
	ErrDeviceNotFound = errors.New("device not found")
	ErrInvalidIP      = errors.New("invalid IP address")
)

// DeviceService handles device management business logic.
type DeviceService struct {
	repo         *repository.DeviceRepository
	heartbeatSvc *HeartbeatService
}

// NewDeviceService creates a new DeviceService.
func NewDeviceService(repo *repository.DeviceRepository, heartbeatSvc *HeartbeatService) *DeviceService {
	return &DeviceService{repo: repo, heartbeatSvc: heartbeatSvc}
}

// Create validates and creates a new device.
func (s *DeviceService) Create(ctx context.Context, req domain.CreateDeviceRequest) (*domain.DeviceResponse, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("device name is required")
	}

	if req.IPAddress != "" {
		if net.ParseIP(req.IPAddress) == nil {
			return nil, ErrInvalidIP
		}
	}

	device, err := s.repo.Create(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create device: %w", err)
	}

	// Auto-create default heartbeat config if device has an IP
	if req.IPAddress != "" && s.heartbeatSvc != nil {
		if hbErr := s.heartbeatSvc.CreateDefaultConfig(ctx, device.ID, device.IpAddress); hbErr != nil {
			slog.Warn("failed to auto-create heartbeat config", "device_id", device.ID, "error", hbErr)
		}
	}

	resp := toDeviceResponse(device)
	return &resp, nil
}

// Get retrieves a device by ID.
func (s *DeviceService) Get(ctx context.Context, id int64) (*domain.DeviceResponse, error) {
	device, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDeviceNotFound
		}
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	resp := toDeviceResponse(device)
	return &resp, nil
}

// List returns devices matching the filter with pagination.
func (s *DeviceService) List(ctx context.Context, filter domain.DeviceFilter) (*domain.DeviceListResponse, error) {
	if filter.Limit <= 0 {
		filter.Limit = 20
	}
	if filter.Limit > 100 {
		filter.Limit = 100
	}

	devices, err := s.repo.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %w", err)
	}

	resp := make([]domain.DeviceResponse, 0, len(devices))
	for _, d := range devices {
		resp = append(resp, toDeviceResponse(d))
	}
	total, err := s.repo.Count(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to count devices: %w", err)
	}

	return &domain.DeviceListResponse{
		Devices: resp,
		Total:   int(total),
	}, nil
}

// Update modifies an existing device by merging provided fields.
func (s *DeviceService) Update(ctx context.Context, id int64, req domain.UpdateDeviceRequest) (*domain.DeviceResponse, error) {
	existing, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDeviceNotFound
		}
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	params := db.UpdateDeviceParams{
		ID:             existing.ID,
		Name:           existing.Name,
		Type:           existing.Type,
		Brand:          existing.Brand,
		Model:          existing.Model,
		Location:       existing.Location,
		Purpose:        existing.Purpose,
		Description:    existing.Description,
		Status:         existing.Status,
		IpAddress:      existing.IpAddress,
		MacAddress:     existing.MacAddress,
		SerialNumber:   existing.SerialNumber,
		PurchaseDate:   existing.PurchaseDate,
		WarrantyExpiry: existing.WarrantyExpiry,
		Tags:           existing.Tags,
	}

	if req.Name != nil {
		params.Name = *req.Name
	}
	if req.Type != nil {
		params.Type = *req.Type
	}
	if req.Brand != nil {
		params.Brand = *req.Brand
	}
	if req.Model != nil {
		params.Model = *req.Model
	}
	if req.Location != nil {
		params.Location = *req.Location
	}
	if req.Purpose != nil {
		params.Purpose = *req.Purpose
	}
	if req.Description != nil {
		params.Description = *req.Description
	}
	if req.IPAddress != nil {
		if *req.IPAddress != "" && net.ParseIP(*req.IPAddress) == nil {
			return nil, ErrInvalidIP
		}
		params.IpAddress = *req.IPAddress
	}
	if req.MACAddress != nil {
		params.MacAddress = *req.MACAddress
	}
	if req.SerialNumber != nil {
		params.SerialNumber = *req.SerialNumber
	}
	if req.PurchaseDate != nil {
		params.PurchaseDate = *req.PurchaseDate
	}
	if req.WarrantyExpiry != nil {
		params.WarrantyExpiry = *req.WarrantyExpiry
	}
	if req.Tags != nil {
		params.Tags = *req.Tags
	}

	device, err := s.repo.Update(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to update device: %w", err)
	}

	// Apply user_attributes patch (merged with existing; empty values delete).
	// scan_attributes is engine-owned and never touched here. We re-read the
	// freshly updated row so the merge base reflects concurrent engine writes.
	if len(req.UserAttributesPatch) > 0 {
		base, err := domain.UnmarshalUserAttributes(device.UserAttributes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse existing user_attributes: %w", err)
		}
		merged := domain.MergeUserAttributes(base, req.UserAttributesPatch)
		if err := s.repo.UpdateUserAttributes(ctx, id, merged); err != nil {
			return nil, fmt.Errorf("failed to update user_attributes: %w", err)
		}
		// Re-fetch so the response reflects the merged map.
		device, err = s.repo.GetByID(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("failed to re-read device after user_attributes update: %w", err)
		}
	}

	resp := toDeviceResponse(device)
	return &resp, nil
}

// Delete removes a device by ID.
func (s *DeviceService) Delete(ctx context.Context, id int64) error {
	err := s.repo.Delete(ctx, id)
	if err != nil {
		if err.Error() == "device not found" {
			return ErrDeviceNotFound
		}
		return fmt.Errorf("failed to delete device: %w", err)
	}
	return nil
}

// GetStats returns device statistics grouped by status and type.
func (s *DeviceService) GetStats(ctx context.Context) (*domain.DeviceStatsResponse, error) {
	statusRows, err := s.repo.CountByStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get device stats: %w", err)
	}

	byStatus := make(map[string]int64)
	for _, row := range statusRows {
		byStatus[row.Status] = row.Count
	}

	typeRows, err := s.repo.CountByType(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get device stats by type: %w", err)
	}

	byType := make(map[string]int64)
	for _, row := range typeRows {
		byType[row.Type] = row.Count
	}

	return &domain.DeviceStatsResponse{
		ByStatus: byStatus,
		ByType:   byType,
	}, nil
}

// toDeviceResponse converts a db.Device to domain.DeviceResponse.
func toDeviceResponse(d db.Device) domain.DeviceResponse {
	scanAttrs, err := domain.UnmarshalScanAttributes(d.ScanAttributes)
	if err != nil {
		slog.Warn("invalid scan_attributes JSON on device; defaulting to empty",
			"device_id", d.ID, "ip", d.IpAddress, "error", err)
	}
	userAttrs, err := domain.UnmarshalUserAttributes(d.UserAttributes)
	if err != nil {
		slog.Warn("invalid user_attributes JSON on device; defaulting to empty",
			"device_id", d.ID, "ip", d.IpAddress, "error", err)
	}
	return domain.DeviceResponse{
		ID:               d.ID,
		Name:             d.Name,
		Type:             d.Type,
		Brand:            d.Brand,
		Model:            d.Model,
		Location:         d.Location,
		Purpose:          d.Purpose,
		Description:      d.Description,
		Status:           d.Status,
		IPAddress:        d.IpAddress,
		MACAddress:       d.MacAddress,
		SerialNumber:     d.SerialNumber,
		PurchaseDate:     d.PurchaseDate,
		WarrantyExpiry:   d.WarrantyExpiry,
		Tags:             d.Tags,
		CreatedAt:        d.CreatedAt,
		ScanSource:       d.ScanSource,
		PrometheusLabels: d.PrometheusLabels,
		LastScannedAt:    d.LastScannedAt,
		LastScanTaskID:   d.LastScanTaskID,
		OpenPorts:        d.OpenPorts,
		DetectedServices: d.DetectedServices,
		PrometheusURL:    d.PrometheusUrl,
		NodeExporterURL:  d.NodeExporterUrl,
		LastScanRttMs:    d.LastScanRttMs,
		ScanAttributes:   scanAttrs,
		UserAttributes:   userAttrs,
	}
}
