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
)

// Request types

type CreateDeviceRequest struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	Brand          string `json:"brand"`
	Model          string `json:"model"`
	Location       string `json:"location"`
	Purpose        string `json:"purpose"`
	Description    string `json:"description"`
	IPAddress      string `json:"ip_address"`
	MACAddress     string `json:"mac_address"`
	SerialNumber   string `json:"serial_number"`
	PurchaseDate   string `json:"purchase_date"`
	WarrantyExpiry string `json:"warranty_expiry"`
	Tags           string `json:"tags"`
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
}

type DeviceFilter struct {
	Status string `json:"status,omitempty"`
	Type   string `json:"type,omitempty"`
	Limit  int64  `json:"limit,omitempty"`
	Offset int64  `json:"offset,omitempty"`
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
	ScanSource       string     `json:"scan_source"`
	PrometheusLabels string     `json:"prometheus_labels"`
	LastScannedAt    *time.Time `json:"last_scanned_at,omitempty"`
	LastScanTaskID   *int64     `json:"last_scan_task_id,omitempty"`
	OpenPorts        string     `json:"open_ports"`
	DetectedServices string     `json:"detected_services"`
	PrometheusUrl    string     `json:"prometheus_url"`
	NodeExporterUrl  string     `json:"node_exporter_url"`
	LastScanRttMs    int64      `json:"last_scan_rtt_ms"`
}

type DeviceListResponse struct {
	Devices []DeviceResponse `json:"devices"`
	Total   int              `json:"total"`
}

type DeviceStatsResponse struct {
	ByStatus map[string]int64  `json:"by_status"`
	ByType   map[string]int64  `json:"by_type"`
}
