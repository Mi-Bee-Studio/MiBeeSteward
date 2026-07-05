package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
)

// DashboardService handles dashboard config CRUD and Prometheus/VM query proxying.
type DashboardService struct {
	queries        *db.Queries
	prometheusURL  string
	dataSourceType string
	client         *http.Client
}

// NewDashboardService creates a new DashboardService.
func NewDashboardService(dbConn db.DBTX, cfg *config.Config) *DashboardService {
	return &DashboardService{
		queries:        db.New(dbConn),
		prometheusURL:  cfg.Dashboard.PrometheusURL,
		dataSourceType: cfg.Dashboard.DataSourceType,
		client:         &http.Client{Timeout: 30 * time.Second},
	}
}

// dataSourceEndpoint returns the appropriate URL based on the configured data source type.
func (s *DashboardService) dataSourceEndpoint() (string, error) {
	switch s.dataSourceType {
	case "prometheus":
		if s.prometheusURL == "" {
			return "", fmt.Errorf("prometheus URL not configured")
		}
		return s.prometheusURL, nil
	default:
		if s.prometheusURL == "" {
			return "", fmt.Errorf("prometheus URL not configured")
		}
		return s.prometheusURL, nil
	}
}

// ListConfigs returns all dashboard configurations.
func (s *DashboardService) ListConfigs(ctx context.Context) ([]db.DashboardConfig, error) {
	return s.queries.ListConfigs(ctx)
}

// CreateConfig creates a new dashboard configuration.
func (s *DashboardService) CreateConfig(ctx context.Context, params db.CreateDashboardConfigParams) (db.DashboardConfig, error) {
	return s.queries.CreateDashboardConfig(ctx, params)
}

// UpdateConfig updates an existing dashboard configuration.
func (s *DashboardService) UpdateConfig(ctx context.Context, params db.UpdateDashboardConfigParams) (db.DashboardConfig, error) {
	return s.queries.UpdateDashboardConfig(ctx, params)
}

// DeleteConfig deletes a dashboard configuration by ID.
func (s *DashboardService) DeleteConfig(ctx context.Context, id int64) error {
	affected, err := s.queries.DeleteDashboardConfig(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to delete config: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("dashboard config not found")
	}
	return nil
}

// Query performs an instant query against the configured Prometheus/VM data source.
func (s *DashboardService) Query(ctx context.Context, query string, ts string) ([]byte, error) {
	baseURL, err := s.dataSourceEndpoint()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/api/v1/query?query=%s", baseURL, query)
	if ts != "" {
		url += "&time=" + ts
	}

	return s.proxyRequest(ctx, url)
}

// QueryRange performs a range query against the configured Prometheus/VM data source.
func (s *DashboardService) QueryRange(ctx context.Context, query, start, end, step string) ([]byte, error) {
	baseURL, err := s.dataSourceEndpoint()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/api/v1/query_range?query=%s&start=%s&end=%s&step=%s",
		baseURL, query, start, end, step)

	return s.proxyRequest(ctx, url)
}

// proxyRequest executes an HTTP GET against the data source and returns the raw response body.
func (s *DashboardService) proxyRequest(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, &UpstreamError{Err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream returned status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// UpstreamError indicates the Prometheus/VM data source is unreachable.
type UpstreamError struct {
	Err error
}

func (e *UpstreamError) Error() string {
	return fmt.Sprintf("data source unreachable: %v", e.Err)
}
