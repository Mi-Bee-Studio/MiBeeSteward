package domain

import "time"

// DeviceStatus represents the operational status of a device.
type DeviceStatus string

const (
	StatusOnline  DeviceStatus = "online"
	StatusOffline DeviceStatus = "offline"
	StatusUnknown DeviceStatus = "unknown"
)

// DeviceType represents the category of a device.
type DeviceType string

const (
	TypePC       DeviceType = "pc"
	TypeEmbedded DeviceType = "embedded"
	TypeIoT      DeviceType = "iot"
	TypeOther    DeviceType = "other"
	TypeServer   DeviceType = "server"
	TypeSwitch   DeviceType = "switch"
	TypeRouter   DeviceType = "router"
	TypeFirewall DeviceType = "firewall"
	TypeNAS      DeviceType = "nas"
	TypeCamera   DeviceType = "camera" // present in schema CHECK + validDeviceTypes; keep aligned
)

// Request types

type CreateDeviceRequest struct {
	Name           string         `json:"name"`
	Type           string         `json:"type"`
	Brand          string         `json:"brand"`
	Model          string         `json:"model"`
	Location       string         `json:"location"`
	Purpose        string         `json:"purpose"`
	Description    string         `json:"description"`
	IPAddress      string         `json:"ip_address"`
	MACAddress     string         `json:"mac_address"`
	SerialNumber   string         `json:"serial_number"`
	PurchaseDate   string         `json:"purchase_date"`
	WarrantyExpiry string         `json:"warranty_expiry"`
	Tags           string         `json:"tags"`
	UserAttributes UserAttributes `json:"user_attributes,omitempty"`
}

type UpdateDeviceRequest struct {
	Name           *string `json:"name,omitempty"`
	Type           *string `json:"type,omitempty"`
	Brand          *string `json:"brand,omitempty"`
	Model          *string `json:"model,omitempty"`
	Location       *string `json:"location,omitempty"`
	Purpose        *string `json:"purpose,omitempty"`
	Description    *string `json:"description,omitempty"`
	IPAddress      *string `json:"ip_address,omitempty"`
	MACAddress     *string `json:"mac_address,omitempty"`
	SerialNumber   *string `json:"serial_number,omitempty"`
	PurchaseDate   *string `json:"purchase_date,omitempty"`
	WarrantyExpiry *string `json:"warranty_expiry,omitempty"`
	Tags           *string `json:"tags,omitempty"`
	// UserAttributesPatch is merged into the existing user_attributes map.
	// Empty-string values delete keys. scan_attributes is engine-owned and
	// cannot be set through this request.
	UserAttributesPatch UserAttributes `json:"user_attributes,omitempty"`
}

type DeviceFilter struct {
	Status string `json:"status,omitempty"`
	Type   string `json:"type,omitempty"`
	Limit  int64  `json:"limit,omitempty"`
	Offset int64  `json:"offset,omitempty"`
	// Search performs a substring match across name / ip_address / mac_address /
	// serial_number. Empty string disables search. Pushed to the backend so it
	// works across all pages (the previous client-side filter only searched the
	// current 20-row page, so anything beyond was unfindable).
	Search string `json:"search,omitempty"`
	// CreatedAtFrom/To filter by created_at (inclusive). The frontend already
	// sent created_from/created_to but the handler ignored them.
	CreatedAtFrom *time.Time `json:"created_from,omitempty"`
	CreatedAtTo   *time.Time `json:"created_to,omitempty"`
	// NetworkID filters by devices.network_id (the logical network an agent
	// discovered the device on). nil = all networks (no filter); non-nil =
	// devices on that network only. NULL-network (legacy/unresolved) devices
	// are excluded when this is set — they have no network to match.
	NetworkID *int64 `json:"network_id,omitempty"`
	// SortBy is validated against a whitelist in the repository layer (never
	// interpolated raw into SQL). Order is "asc" or "desc" (default "asc").
	SortBy string `json:"sort_by,omitempty"`
	Order  string `json:"order,omitempty"`
}

// Response types

type DeviceResponse struct {
	ID             int64     `json:"id"`
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	Brand          string    `json:"brand"`
	Model          string    `json:"model"`
	Location       string    `json:"location"`
	Purpose        string    `json:"purpose"`
	Description    string    `json:"description"`
	Status         string    `json:"status"`
	IPAddress      string    `json:"ip_address"`
	MACAddress     string    `json:"mac_address"`
	SerialNumber   string    `json:"serial_number"`
	PurchaseDate   string    `json:"purchase_date"`
	WarrantyExpiry string    `json:"warranty_expiry"`
	Tags           string    `json:"tags"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	ScanSource     string    `json:"scan_source"`
	// NetworkID/NetworkName identify the logical network this device was
	// discovered on (distributed/multi-LAN). NetworkID is nil for legacy
	// unresolved devices; NetworkName is the human label from the networks table
	// (resolved by the repository via JOIN, empty when NetworkID is nil).
	NetworkID        *int64     `json:"network_id,omitempty"`
	NetworkName      string     `json:"network_name,omitempty"`
	PrometheusLabels string     `json:"prometheus_labels"`
	LastScannedAt    *time.Time `json:"last_scanned_at,omitempty"`
	LastScanTaskID   *int64     `json:"last_scan_task_id,omitempty"`
	OpenPorts        string     `json:"open_ports"`
	DetectedServices string     `json:"detected_services"`
	PrometheusURL    string     `json:"prometheus_url"`
	NodeExporterURL  string     `json:"node_exporter_url"`
	LastScanRttMs    int64      `json:"last_scan_rtt_ms"`
	// Dual JSON layer. ScanAttributes is the typed view of the engine-written
	// discovery document; UserAttributes is the free-form user map. The legacy
	// JSON-string fields above (open_ports, detected_services, prometheus_labels)
	// remain populated for backwards compatibility — frontend may read either.
	ScanAttributes ScanAttributes `json:"scan_attributes"`
	UserAttributes UserAttributes `json:"user_attributes"`
}

type DeviceListResponse struct {
	Devices []DeviceResponse `json:"devices"`
	Total   int              `json:"total"`
}

type DeviceStatsResponse struct {
	ByStatus map[string]int64 `json:"by_status"`
	ByType   map[string]int64 `json:"by_type"`
}

// DashboardOverviewResponse is the single aggregated payload behind the default
// dashboard. It replaces the old approach where the frontend pulled
// /devices?limit=200 and computed pie charts client-side (which both capped at
// 200 devices and skewed the distribution). Everything here is computed
// server-side over the full dataset.
type DashboardOverviewResponse struct {
	Devices   OverviewDevices  `json:"devices"`
	Scanning  OverviewScanning `json:"scanning"`
	Abnormal  []OverviewDevice `json:"abnormal"` // offline devices (top N), clickable targets for the UI
	Generated time.Time        `json:"generated"`
}

// OverviewDevices holds the device-population totals and distributions.
type OverviewDevices struct {
	Total      int64            `json:"total"`
	Online     int64            `json:"online"`
	Offline    int64            `json:"offline"`
	Unknown    int64            `json:"unknown"`
	OnlineRate float64          `json:"online_rate"` // 0..1, online/total (0 when total==0)
	ByType     map[string]int64 `json:"by_type"`     // full-population GROUP BY (not a 200-row sample)
	ByLocation map[string]int64 `json:"by_location"` // GROUP BY location (empty location bucketed as "unknown")
}

// OverviewScanning summarises recent scan activity so the dashboard reflects
// "discovery" — the system's core job — rather than only device counts.
type OverviewScanning struct {
	TasksTotal    int64              `json:"tasks_total"`
	RunsTotal     int64              `json:"runs_total"`
	RecentTasks   []OverviewScanTask `json:"recent_tasks"` // last N tasks
	RecentRuns    []OverviewScanRun  `json:"recent_runs"`  // last N runs across all tasks
	RunsByStatus  map[string]int64   `json:"runs_by_status"`
	LastDiscovery *OverviewScanRun   `json:"last_discovery,omitempty"` // most recent completed run
}

// OverviewScanTask is a lightweight task projection for the dashboard (no
// pipeline config / cron details — those live on the scan-tasks page).
type OverviewScanTask struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	Targets       string     `json:"targets"`
	Enabled       bool       `json:"enabled"`
	LastRunAt     *time.Time `json:"last_run_at,omitempty"`
	LastRunStatus string     `json:"last_run_status,omitempty"`
}

// OverviewScanRun is a lightweight run projection: status + discovered-host
// counts, enough for an activity feed / "last discovery" card.
type OverviewScanRun struct {
	ID           int64      `json:"id"`
	TaskID       int64      `json:"task_id"`
	Status       string     `json:"status"`
	TotalHosts   int64      `json:"total_hosts"`
	AliveHosts   int64      `json:"alive_hosts"`
	NewHosts     int64      `json:"new_hosts"`
	DurationMs   int64      `json:"duration_ms"`
	ErrorMessage string     `json:"error_message,omitempty"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
}

// OverviewDevice is a compact device projection for the abnormal-device list:
// enough to identify and link to it, without the full scan document.
type OverviewDevice struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	IPAddress     string     `json:"ip_address"`
	Type          string     `json:"type"`
	Status        string     `json:"status"`
	LastScannedAt *time.Time `json:"last_scanned_at,omitempty"`
}
