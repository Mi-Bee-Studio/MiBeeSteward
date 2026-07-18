// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package domain

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-co-op/gocron/v2"
)

// Validation limits for scan tasks.
const (
	maxTargetIPs       = 4096
	minTimeout         = 1
	maxTimeout         = 600
	minConcurrentHosts = 1
	maxConcurrentHosts = 200
)

// ScanRequest is the input for a network scan operation.
type ScanRequest struct {
	Targets   string `json:"targets"`
	Community string `json:"community"`
	Timeout   int    `json:"timeout"`
}

// ScanHost represents a single host result from a network scan.
type ScanHost struct {
	IP           string `json:"ip"`
	Alive        bool   `json:"alive"`
	RTTMs        int64  `json:"rtt_ms"`
	SNMPName     string `json:"snmp_name,omitempty"`
	SNMPDescr    string `json:"snmp_descr,omitempty"`
	SNMPSuccess  bool   `json:"snmp_success"`
	SNMPObjID    string `json:"snmp_obj_id,omitempty"`
	SNMPLocation string `json:"snmp_location,omitempty"`
	SNMPContact  string `json:"snmp_contact,omitempty"`
	SNMPUptime   int64  `json:"snmp_uptime,omitempty"`
	SNMPServices int    `json:"snmp_services,omitempty"`
	SNMPIfCount  int    `json:"snmp_if_count,omitempty"`
	// Enriched fields (inferred from scan data)
	InferredBrand       string `json:"inferred_brand,omitempty"`
	InferredType        string `json:"inferred_type,omitempty"`
	InferredDescription string `json:"inferred_description,omitempty"`
	InferredLocation    string `json:"inferred_location,omitempty"`
}

// ScanResponse is the result of a network scan.
type ScanResponse struct {
	Hosts      []ScanHost `json:"hosts"`
	Total      int        `json:"total"`
	Alive      int        `json:"alive"`
	DurationMs int64      `json:"duration_ms"`
}

// PortInfo describes a network port found on a scanned device.
type PortInfo struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// ServiceInfo describes a detected service running on a device.
type ServiceInfo struct {
	Port    int    `json:"port"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// AddDeviceItem represents a single device to add from scan results.
type AddDeviceItem struct {
	IP          string                 `json:"ip"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Description string                 `json:"description,omitempty"`
	Brand       string                 `json:"brand,omitempty"`
	Model       string                 `json:"model,omitempty"`
	Location    string                 `json:"location,omitempty"`
	SNMPData    map[string]interface{} `json:"snmp_data,omitempty"`
	Ports       []PortInfo             `json:"ports,omitempty"`
	Services    []ServiceInfo          `json:"services,omitempty"`
	PromURL     string                 `json:"prometheus_url,omitempty"`
	NEURL       string                 `json:"node_exporter_url,omitempty"`
	RTTMs       int64                  `json:"rtt_ms,omitempty"`
}

// AddDevicesRequest is the input for adding discovered devices.
type AddDevicesRequest struct {
	Devices []AddDeviceItem `json:"devices"`
}

// AddDevicesResponse is the result of adding discovered devices.
type AddDevicesResponse struct {
	Added  int      `json:"added"`
	Errors []string `json:"errors,omitempty"`
}

// validDeviceTypes maps allowed device type strings.
var validDeviceTypes = map[string]bool{
	"pc":       true,
	"embedded": true,
	"iot":      true,
	"other":    true,
	"server":   true,
	"switch":   true,
	"router":   true,
	"firewall": true,
	"nas":      true,
	"camera":   true,
}

// ValidateDeviceType returns a valid device type, defaulting to "other".
func ValidateDeviceType(t string) string {
	if validDeviceTypes[t] {
		return t
	}
	return "other"
}

// Pipeline configuration types
type PipelineConfig struct {
	ICMP          ICMPConfig            `json:"icmp"`
	SNMP          SNMPConfig            `json:"snmp"`
	PortScan      PortScanConfig        `json:"port_scan"`
	ServiceDetect ServiceDetectConfig   `json:"service_detect"`
	Prometheus    PrometheusStageConfig `json:"prometheus"`
	NodeExporter  NodeExporterConfig    `json:"node_exporter"`
}

type ICMPConfig struct {
	Enabled bool `json:"enabled"`
	Timeout int  `json:"timeout"`
}

type SNMPConfig struct {
	Enabled   bool   `json:"enabled"`
	Community string `json:"community"`
}

type PortScanConfig struct {
	Enabled  bool   `json:"enabled"`
	Ports    string `json:"ports"`
	ScanType string `json:"scan_type"`
}

type ServiceDetectConfig struct {
	Enabled bool `json:"enabled"`
}

type PrometheusStageConfig struct {
	Enabled bool   `json:"enabled"`
	Ports   string `json:"ports"`
}

type NodeExporterConfig struct {
	Enabled bool `json:"enabled"`
}

// DefaultPipelineConfig returns a pipeline config with all stages enabled.
func DefaultPipelineConfig() PipelineConfig {
	return PipelineConfig{
		ICMP:          ICMPConfig{Enabled: true, Timeout: 2},
		SNMP:          SNMPConfig{Enabled: true, Community: "public"},
		PortScan:      PortScanConfig{Enabled: true, Ports: "22,80,443,9100", ScanType: "connect"},
		ServiceDetect: ServiceDetectConfig{Enabled: true},
		Prometheus:    PrometheusStageConfig{Enabled: true, Ports: "9090,9100"},
		NodeExporter:  NodeExporterConfig{Enabled: true},
	}
}

// Scan task request/response types
type ScanTaskRequest struct {
	Name            string         `json:"name"`
	Targets         string         `json:"targets"`
	CronExpr        string         `json:"cron_expr"`
	PipelineConfig  PipelineConfig `json:"pipeline_config"`
	GlobalLabels    string         `json:"global_labels"`
	Timeout         int            `json:"timeout"`
	ConcurrentHosts int            `json:"concurrent_hosts"`
}

type ScanTaskResponse struct {
	ID              int64      `json:"id"`
	Name            string     `json:"name"`
	Targets         string     `json:"targets"`
	CronExpr        string     `json:"cron_expr"`
	PipelineConfig  string     `json:"pipeline_config"`
	GlobalLabels    string     `json:"global_labels"`
	Timeout         int        `json:"timeout"`
	ConcurrentHosts int        `json:"concurrent_hosts"`
	Enabled         bool       `json:"enabled"`
	LastRunAt       *time.Time `json:"last_run_at,omitempty"`
	NextRunAt       *time.Time `json:"next_run_at,omitempty"`
	LastRunStatus   string     `json:"last_run_status,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type UpdateScanTaskRequest struct {
	Name            *string         `json:"name,omitempty"`
	Targets         *string         `json:"targets,omitempty"`
	CronExpr        *string         `json:"cron_expr,omitempty"`
	PipelineConfig  *PipelineConfig `json:"pipeline_config,omitempty"`
	GlobalLabels    *string         `json:"global_labels,omitempty"`
	Timeout         *int            `json:"timeout,omitempty"`
	ConcurrentHosts *int            `json:"concurrent_hosts,omitempty"`
	Enabled         *bool           `json:"enabled,omitempty"`
}

type ScanTaskListResponse struct {
	Tasks []ScanTaskResponse `json:"tasks"`
	Total int                `json:"total"`
}

// Scan result types
type ScanResultResponse struct {
	ID                   int64     `json:"id"`
	TaskID               int64     `json:"task_id"`
	RunID                int64     `json:"run_id,omitempty"`
	IP                   string    `json:"ip"`
	Alive                bool      `json:"alive"`
	RTTMs                int64     `json:"rtt_ms"`
	Ports                string    `json:"ports"`
	Services             string    `json:"services"`
	SNMPData             string    `json:"snmp_data"`
	PrometheusDetected   bool      `json:"prometheus_detected"`
	PrometheusURL        string    `json:"prometheus_url,omitempty"`
	NodeExporterDetected bool      `json:"node_exporter_detected"`
	NodeExporterURL      string    `json:"node_exporter_url,omitempty"`
	NodeExporterData     string    `json:"node_exporter_data"`
	ScannedAt            time.Time `json:"scanned_at"`
}

type ScanResultListResponse struct {
	Results []ScanResultResponse `json:"results"`
	Total   int                  `json:"total"`
}

// Scan run types
type ScanRunResponse struct {
	ID           int64      `json:"id"`
	TaskID       int64      `json:"task_id"`
	Status       string     `json:"status"`
	TotalHosts   int        `json:"total_hosts"`
	AliveHosts   int        `json:"alive_hosts"`
	NewHosts     int        `json:"new_hosts"`
	UpdatedHosts int        `json:"updated_hosts"`
	DurationMs   int        `json:"duration_ms"`
	ErrorMessage string     `json:"error_message,omitempty"`
	StartedAt    *time.Time `json:"started_at,omitempty"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

type ScanRunListResponse struct {
	Runs  []ScanRunResponse `json:"runs"`
	Total int               `json:"total"`
}

// ValidateScanTaskRequest validates a scan task request.
func ValidateScanTaskRequest(req ScanTaskRequest) error {
	if strings.TrimSpace(req.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(req.Targets) == "" {
		return fmt.Errorf("targets is required")
	}
	// Validate targets are valid IPs, CIDRs, or IP ranges
	// and total IPs do not exceed the limit.
	totalIPs, err := countTargetIPs(req.Targets)
	if err != nil {
		return fmt.Errorf("targets: %w", err)
	}
	if totalIPs > maxTargetIPs {
		return fmt.Errorf("targets: too many IPs (%d), maximum is %d", totalIPs, maxTargetIPs)
	}
	if req.CronExpr == "" {
		return fmt.Errorf("cron_expr is required")
	}
	if err := validateCronExpr(req.CronExpr); err != nil {
		return fmt.Errorf("cron_expr: %w", err)
	}
	if req.Timeout < minTimeout || req.Timeout > maxTimeout {
		return fmt.Errorf("timeout must be between %d and %d seconds", minTimeout, maxTimeout)
	}
	if req.ConcurrentHosts < minConcurrentHosts || req.ConcurrentHosts > maxConcurrentHosts {
		return fmt.Errorf("concurrent_hosts must be between %d and %d", minConcurrentHosts, maxConcurrentHosts)
	}
	if err := ValidatePipelineConfig(req.PipelineConfig); err != nil {
		return fmt.Errorf("pipeline_config: %w", err)
	}
	return nil
}

// ValidatePipelineConfig validates port ranges in pipeline config.
func ValidatePipelineConfig(config PipelineConfig) error {
	if config.PortScan.Enabled && config.PortScan.Ports != "" {
		if err := validatePortList(config.PortScan.Ports); err != nil {
			return fmt.Errorf("port_scan: %w", err)
		}
	}
	if config.Prometheus.Enabled && config.Prometheus.Ports != "" {
		if err := validatePortList(config.Prometheus.Ports); err != nil {
			return fmt.Errorf("prometheus: %w", err)
		}
	}
	// A pipeline with every stage disabled produces no useful evidence — the
	// scan would find nothing. Reject this so a malformed edit (e.g. a client
	// sending an empty/zero-valued config) can't silently brick a task.
	if !config.ICMP.Enabled && !config.SNMP.Enabled && !config.PortScan.Enabled &&
		!config.ServiceDetect.Enabled && !config.Prometheus.Enabled && !config.NodeExporter.Enabled {
		return fmt.Errorf("at least one pipeline stage must be enabled")
	}
	return nil
}

// validatePortList validates a port specification string.
func validatePortList(ports string) error {
	parts := strings.Split(ports, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Check for range format (e.g., "1-1000")
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return fmt.Errorf("invalid port range: %s", part)
			}
			start, err := strconv.Atoi(rangeParts[0])
			if err != nil || start < 1 || start > 65535 {
				return fmt.Errorf("invalid port: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(rangeParts[1])
			if err != nil || end < 1 || end > 65535 || end < start {
				return fmt.Errorf("invalid port range: %s", part)
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("invalid port: %s", part)
			}
		}
	}
	return nil
}

// countTargetIPs parses comma-separated targets (IPs, CIDRs, ranges)
// and returns the total number of IP addresses.
func countTargetIPs(targets string) (int, error) {
	parts := strings.Split(targets, ",")
	total := 0
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// CIDR: "192.168.1.0/24"
		if strings.Contains(part, "/") {
			_, ipnet, err := net.ParseCIDR(part)
			if err != nil {
				return 0, fmt.Errorf("invalid CIDR: %s", part)
			}
			ones, bits := ipnet.Mask.Size()
			if bits > 32 {
				return 0, fmt.Errorf("IPv6 not supported: %s", part)
			}
			count := 1 << (bits - ones)
			total += count
			if total > maxTargetIPs {
				return total, nil
			}
			continue
		}

		// IP range: "192.168.1.1-10" or "192.168.1.1-192.168.1.10"
		if strings.Contains(part, "-") {
			count, err := countIPRange(part)
			if err != nil {
				return 0, err
			}
			total += count
			if total > maxTargetIPs {
				return total, nil
			}
			continue
		}

		// Single IP
		if net.ParseIP(part) == nil {
			return 0, fmt.Errorf("invalid IP: %s", part)
		}
		total++
		if total > maxTargetIPs {
			return total, nil
		}
	}
	return total, nil
}

// countIPRange counts the number of IPs in a range like "192.168.1.1-10"
// or "192.168.1.1-192.168.1.10".
func countIPRange(rangeStr string) (int, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid IP range: %s", rangeStr)
	}

	start := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])

	startIP := net.ParseIP(start)
	if startIP == nil {
		return 0, fmt.Errorf("invalid IP in range: %s", start)
	}
	startIP = startIP.To4()
	if startIP == nil {
		return 0, fmt.Errorf("invalid IPv4 address in range: %s", start)
	}

	var endIP net.IP
	if parsed := net.ParseIP(endStr); parsed != nil {
		endIP = parsed.To4()
		if endIP == nil {
			return 0, fmt.Errorf("invalid IPv4 address in range end: %s", endStr)
		}
	} else {
		// Last octet only, e.g., "192.168.1.1-10"
		endOctet, err := strconv.Atoi(endStr)
		if err != nil || endOctet < 0 || endOctet > 255 {
			return 0, fmt.Errorf("invalid IP range end: %s", endStr)
		}
		endIP = make(net.IP, 4)
		copy(endIP, startIP)
		endIP[3] = byte(endOctet)
	}

	startUint := ipToUint32(startIP)
	endUint := ipToUint32(endIP)
	if endUint < startUint {
		return 0, fmt.Errorf("invalid IP range: end IP is before start IP in %s", rangeStr)
	}
	return int(endUint - startUint + 1), nil
}

// ipToUint32 converts an IPv4 address to a uint32 for range comparison.
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// validateCronExpr validates a cron expression using the gocron library.
func validateCronExpr(expr string) error {
	s, err := gocron.NewScheduler()
	if err != nil {
		return fmt.Errorf("failed to create scheduler: %w", err)
	}
	defer func() { _ = s.Shutdown() }()

	_, err = s.NewJob(
		gocron.CronJob(expr, false),
		gocron.NewTask(func() {}),
	)
	if err != nil {
		return fmt.Errorf("invalid cron expression: %s", expr)
	}
	return nil
}
