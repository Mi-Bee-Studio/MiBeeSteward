package domain

import "time"

// HeartbeatConfigListResponse wraps a list of heartbeat configs with a total count.
type HeartbeatConfigListResponse struct {
	Configs interface{} `json:"configs"`
	Total   int         `json:"total"`
}

// HeartbeatResultListResponse wraps a list of heartbeat results with a total count.
type HeartbeatResultListResponse struct {
	Results interface{} `json:"results"`
	Total   int         `json:"total"`
}

// HeartbeatHistoryListResponse wraps a time-filtered list of heartbeat results with a total count.
type HeartbeatHistoryListResponse struct {
	Results []HeartbeatResultResponse `json:"results"`
	Total   int                       `json:"total"`
}

// HeartbeatResultResponse represents a single heartbeat result in API responses.
type HeartbeatResultResponse struct {
	ID           int64     `json:"id"`
	DeviceID     int64     `json:"device_id"`
	ConfigID     int64     `json:"config_id"`
	Status       string    `json:"status"`
	LatencyMs    float64   `json:"latency_ms"`
	ErrorMessage string    `json:"error_message"`
	CheckedAt    time.Time `json:"checked_at"`
}

// HeartbeatStatsResponse represents aggregated heartbeat statistics.
type HeartbeatStatsResponse struct {
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	SuccessCount int64   `json:"success_count"`
	FailCount    int64   `json:"fail_count"`
	TimeoutCount int64   `json:"timeout_count"`
}
