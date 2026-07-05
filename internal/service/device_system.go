package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/repository"
)

var (
	ErrDeviceSystemNotFound = errors.New("device system not found")
	ErrInvalidEntryURL      = errors.New("invalid entry URL")
	ErrInvalidMetricsURL    = errors.New("invalid metrics URL")
	ErrSystemNameRequired   = errors.New("system name is required")
)

// DeviceSystemService handles device system management business logic.
type DeviceSystemService struct {
	repo *repository.DeviceSystemRepository
}

// NewDeviceSystemService creates a new DeviceSystemService.
func NewDeviceSystemService(repo *repository.DeviceSystemRepository) *DeviceSystemService {
	return &DeviceSystemService{repo: repo}
}

// Create validates and creates a new device system.
func (s *DeviceSystemService) Create(ctx context.Context, deviceID int64, req domain.CreateDeviceSystemRequest) (*domain.DeviceSystemResponse, error) {
	if req.Name == "" {
		return nil, ErrSystemNameRequired
	}

	if err := validateURL(req.EntryURL); err != nil {
		return nil, ErrInvalidEntryURL
	}

	if err := validateURL(req.MetricsURL); err != nil {
		return nil, ErrInvalidMetricsURL
	}

	system, err := s.repo.Create(ctx, deviceID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create device system: %w", err)
	}

	resp := toDeviceSystemResponse(system)
	return &resp, nil
}

// Get retrieves a device system by ID.
func (s *DeviceSystemService) Get(ctx context.Context, id int64) (*domain.DeviceSystemResponse, error) {
	system, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDeviceSystemNotFound
		}
		return nil, fmt.Errorf("failed to get device system: %w", err)
	}

	resp := toDeviceSystemResponse(system)
	return &resp, nil
}

// ListByDevice returns device systems for a specific device matching the filter with pagination.
func (s *DeviceSystemService) ListByDevice(ctx context.Context, deviceID int64, filter domain.DeviceSystemFilter) (*domain.DeviceSystemListResponse, error) {
	if filter.Limit <= 0 {
		filter.Limit = 20
	}
	if filter.Limit > 100 {
		filter.Limit = 100
	}

	systems, err := s.repo.ListByDevice(ctx, deviceID, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list device systems: %w", err)
	}

	total, err := s.repo.CountByDevice(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to count device systems: %w", err)
	}

	resp := make([]domain.DeviceSystemResponse, 0, len(systems))
	for _, sys := range systems {
		resp = append(resp, toDeviceSystemResponse(sys))
	}

	return &domain.DeviceSystemListResponse{
		Systems: resp,
		Total:   int(total),
	}, nil
}

// Update modifies an existing device system by merging provided fields.
func (s *DeviceSystemService) Update(ctx context.Context, id int64, req domain.UpdateDeviceSystemRequest) (*domain.DeviceSystemResponse, error) {
	existing, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDeviceSystemNotFound
		}
		return nil, fmt.Errorf("failed to get device system: %w", err)
	}

	params := db.UpdateDeviceSystemParams{
		ID:             existing.ID,
		DeviceID:       existing.DeviceID,
		Name:           existing.Name,
		EntryUrl:       existing.EntryUrl,
		Description:    existing.Description,
		Category:       existing.Category,
		MetricsUrl:     existing.MetricsUrl,
		MetricsEnabled: existing.MetricsEnabled,
		Tags:           existing.Tags,
	}

	if req.Name != nil {
		params.Name = *req.Name
	}
	if req.EntryURL != nil {
		if err := validateURL(*req.EntryURL); err != nil {
			return nil, ErrInvalidEntryURL
		}
		params.EntryUrl = *req.EntryURL
	}
	if req.Description != nil {
		params.Description = *req.Description
	}
	if req.Category != nil {
		params.Category = *req.Category
	}
	if req.MetricsURL != nil {
		if err := validateURL(*req.MetricsURL); err != nil {
			return nil, ErrInvalidMetricsURL
		}
		params.MetricsUrl = *req.MetricsURL
	}
	if req.MetricsEnabled != nil {
		var val int64 = 0
		if *req.MetricsEnabled {
			val = 1
		}
		params.MetricsEnabled = val
	}
	if req.Tags != nil {
		params.Tags = *req.Tags
	}

	system, err := s.repo.Update(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to update device system: %w", err)
	}

	resp := toDeviceSystemResponse(system)
	return &resp, nil
}

// Delete removes a device system by ID.
func (s *DeviceSystemService) Delete(ctx context.Context, id int64) error {
	err := s.repo.Delete(ctx, id)
	if err != nil {
		if err.Error() == "device system not found" {
			return ErrDeviceSystemNotFound
		}
		return fmt.Errorf("failed to delete device system: %w", err)
	}
	return nil
}

// toDeviceSystemResponse converts a db.DeviceSystem to domain.DeviceSystemResponse.
func toDeviceSystemResponse(s db.DeviceSystem) domain.DeviceSystemResponse {
	return domain.DeviceSystemResponse{
		ID:             s.ID,
		DeviceID:       s.DeviceID,
		Name:           s.Name,
		EntryURL:       s.EntryUrl,
		Description:    s.Description,
		Category:       s.Category,
		MetricsURL:     s.MetricsUrl,
		MetricsEnabled: s.MetricsEnabled == 1,
		Tags:           s.Tags,
		CreatedAt:      s.CreatedAt,
		UpdatedAt:      s.UpdatedAt,
	}
}

// validateURL checks that a URL is valid with http or https scheme.
func validateURL(rawURL string) error {
	if rawURL == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL must use http or https scheme")
	}
	if u.Host == "" {
		return fmt.Errorf("URL must have a host")
	}
	return nil
}
